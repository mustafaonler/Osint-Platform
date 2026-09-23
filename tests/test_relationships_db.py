"""PostgreSQL + HTTP ilişkiler görünümü; veri transaction rollback ile temizlenir."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app, oturum
from app.models import Entity, Investigation, Relationship
from app.relationships import komsular


@pytest.fixture
def iliski_verisi():
    with SessionLocal() as s:
        inv = Investigation(ad="relations-test", kok_hedef="example.com", olusturan="pytest")
        other = Investigation(ad="other-test", kok_hedef="example.org", olusturan="pytest")
        s.add_all([inv, other])
        s.flush()

        def varlik(ad, arastirma=inv):
            e = Entity(investigation_id=arastirma.id, tip="subdomain", deger_norm=ad, deger_ham=ad)
            s.add(e)
            s.flush()
            return e

        root, neighbor, empty = (varlik(ad) for ad in (
            "root.example.com", "neighbor.example.com", "empty.example.com"))
        foreign = varlik("foreign.example.org", other)

        def iliski(kaynak, hedef, tip, arastirma=inv):
            s.add(Relationship(investigation_id=arastirma.id,
                               kaynak_entity_id=kaynak.id, hedef_entity_id=hedef.id, tip=tip))

        iliski(root, neighbor, "resolves_to")
        iliski(neighbor, root, "cname_for")
        iliski(root, neighbor, "custom_relation")
        for i in range(51):
            iliski(varlik(f"page-{i:02}.example.com"), root, "subdomain_of")
        # Hem ilişki araştırması hem de uç varlık izolasyonu sınanır.
        iliski(root, foreign, "owned_by")
        iliski(foreign, root, "owned_by")
        iliski(root, neighbor, "ns_for", other)
        s.flush()
        try:
            yield s, root, neighbor, empty, foreign
        finally:
            s.rollback()


def test_yonler_turler_izolasyon_ve_sayfalama(iliski_verisi):
    s, root, neighbor, empty, foreign = iliski_verisi
    ilk = komsular(s, root)
    son = komsular(s, root, 2)
    assert ilk["toplam"] == 54
    assert len(ilk["satirlar"]) == 50 and len(son["satirlar"]) == 4
    rows = ilk["satirlar"] + son["satirlar"]
    assert len({r[0].id for r in rows}) == 54
    assert all(foreign.id not in (a.id, b.id) for _, a, b in rows)
    assert {(r.tip, a.id, b.id) for r, a, b in rows if r.tip != "subdomain_of"} == {
        ("resolves_to", root.id, neighbor.id),
        ("cname_for", neighbor.id, root.id),
        ("custom_relation", root.id, neighbor.id),
    }
    assert [r[0].id for r in ilk["satirlar"]] == [r[0].id for r in komsular(s, root)["satirlar"]]
    assert komsular(s, root, 999)["sayfa"] == 2
    assert komsular(s, empty)["toplam"] == 0
    assert not s.dirty and not s.new and not s.deleted


def test_http_komsu_gezintisi_escape_ve_bos_gorunum(iliski_verisi):
    s, root, neighbor, empty, foreign = iliski_verisi
    neighbor.deger_ham = "<script>alert(1)</script>"
    s.flush()
    app.dependency_overrides[oturum] = lambda: s
    try:
        with TestClient(app) as client:
            url = f"/entities/{root.id}"
            response = client.get(url)
            assert response.status_code == 200
            html = response.text
            assert "54 ilişki" in html
            assert "Giden →" in html and "Gelen ←" in html
            assert "custom_relation" in html
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
            assert "<script>alert(1)</script>" not in html
            assert f'/entities/{neighbor.id}' in html
            assert str(foreign.id) not in html
            assert "?iliski_sayfa=2#iliskiler" in html
            assert "Kanıt zinciri" in html and "AI skorları" in html
            assert "Sayfa 2 / 2" in client.get(url + "?iliski_sayfa=2").text
            assert "54 ilişki" in client.get(url + "?iliski_sayfa=999").text
            assert "3 ilişki" in client.get(f"/entities/{neighbor.id}").text
            assert "henüz ilişki kaydı yok" in client.get(f"/entities/{empty.id}").text
            assert client.get(url + "?iliski_sayfa=0").status_code == 422
            assert client.get(f"/entities/{uuid.uuid4()}").status_code == 404
    finally:
        app.dependency_overrides.pop(oturum, None)
