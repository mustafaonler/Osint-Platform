"""Gerçek PostgreSQL ve HTTP görünümü; sadece test transaction'ı geri alınır.

docker compose exec api python -m pytest tests/test_triage_db.py -q
"""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db import SessionLocal
from app.main import app, oturum
from app.models import Entity, Investigation, Job, Observation, Relationship
from app.triage_query import listele


@pytest.fixture
def veri():
    with SessionLocal() as s:
        inv = Investigation(ad="triage-test", kok_hedef="example.com", olusturan="pytest")
        diger = Investigation(ad="triage-other", kok_hedef="example.org", olusturan="pytest")
        s.add_all([inv, diger])
        s.flush()

        def entity(tip, deger, arastirma=None):
            e = Entity(investigation_id=(arastirma or inv).id, tip=tip,
                       deger_norm=deger, deger_ham=deger)
            s.add(e)
            s.flush()
            return e

        kok = entity("domain", "example.com")
        tek = entity("subdomain", "one.example.com")
        cok = entity("subdomain", "two.example.com")
        ip = entity("ip", "192.0.2.1")
        cert = entity("cert", "abcdef0123456789")
        saglayici = entity("asn", "64500")
        yetim = entity("ip", "192.0.2.2")
        yabanci = entity("subdomain", "foreign.example.org", diger)
        job = Job(investigation_id=inv.id, tool="test", tool_version="1",
                  hedef_deger="example.com")
        s.add(job)
        s.flush()

        def obs(e, tool, veri=None):
            s.add(Observation(entity_id=e.id, job_id=job.id, tool=tool,
                              tool_version="1", ham_cikti_ref="test.json", veri=veri or {}))

        for _ in range(20):
            obs(tek, "crtsh")
            obs(cert, "crtsh")
        tek.gozlem_sayisi = 20
        for tool in ("crtsh", "subfinder"):
            obs(cok, tool)
        obs(ip, "dns-resolver", {"saglayici_olabilir": "false"})
        obs(saglayici, "asn-bgp", {"saglayici_olabilir": True})
        obs(saglayici, "whois-rdap", {"saglayici_olabilir": False})
        obs(yetim, "dns-resolver")
        for e in (tek, cok, ip, cert, saglayici):
            s.add(Relationship(investigation_id=inv.id, kaynak_entity_id=e.id,
                               hedef_entity_id=kok.id, tip="owned_by"))
        # Araştırma dışındaki bir ilişki yetimlik kararını değiştirmemeli.
        s.add(Relationship(investigation_id=diger.id, kaynak_entity_id=yabanci.id,
                           hedef_entity_id=yetim.id, tip="resolves_to"))
        for i in range(105):
            entity("subdomain", f"page-{i:03}.example.com")
        s.flush()
        try:
            yield s, inv, dict(kok=kok, tek=tek, cok=cok, ip=ip, cert=cert,
                              saglayici=saglayici, yetim=yetim, yabanci=yabanci)
        finally:
            s.rollback()


def test_sorgu_kaynaklar_isaretler_izolasyon_ve_degisiklik_yok(veri):
    s, inv, e = veri
    before = s.scalar(select(func.count()).select_from(Entity).where(Entity.investigation_id == inv.id))
    sonuc = listele(s, inv.id, inv.kok_hedef)
    by_id = {r.entity.id: r for r in sonuc}
    assert len(sonuc) == before == 112
    assert e["yabanci"].id not in by_id
    assert by_id[e["tek"].id].tools == ("crtsh",)
    for ad, grup in dict(kok="oncelikli", tek="incele", cok="oncelikli", ip="oncelikli",
                         cert="sertifika", saglayici="baglam", yetim="incele").items():
        assert by_id[e[ad].id].on_eleme.grup == grup
    assert sonuc[-1].entity.id == e["cert"].id
    assert [r.entity.id for r in sonuc] == [r.entity.id for r in listele(s, inv.id, inv.kok_hedef)]
    assert not s.dirty and not s.deleted and not s.new


def test_http_sayfalar_gruplar_polling_ve_escape(veri):
    s, inv, e = veri
    e["tek"].deger_ham = "<script>alert(1)</script>"
    s.flush()
    app.dependency_overrides[oturum] = lambda: s
    try:
        with TestClient(app) as client:
            url = f"/investigations/{inv.id}"
            ilk = client.get(url + "/entities")
            ikinci = client.get(url + "/entities?sayfa=2")
            assert ilk.status_code == ikinci.status_code == 200
            assert ilk.text.count("kaynağı gör") == 100
            assert ikinci.text.count("kaynağı gör") == 12
            assert f"/entities/{e['cert'].id}" in ikinci.text
            cert = client.get(url + "/entities?grup=sertifika")
            assert cert.text.count("kaynağı gör") == 1
            assert "grup=sertifika&amp;sayfa=1" in cert.text
            assert "Tüm varlıklar (112)" in cert.text
            incele = client.get(url + "/entities?grup=incele")
            assert "<script>alert" not in incele.text
            assert "&lt;script&gt;" in incele.text
            full = client.get(url + "?grup=incele&sayfa=2")
            assert "grup=incele&amp;sayfa=2" in full.text
            assert client.get(url + "/entities?sayfa=0").status_code == 422
            assert client.get(url + "/entities?grup=invalid").status_code == 422
            assert client.get(f"/investigations/{uuid.uuid4()}/entities").status_code == 404
    finally:
        app.dependency_overrides.pop(oturum, None)
