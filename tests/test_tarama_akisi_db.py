"""Araştırma kurulumu ve tarama akışı: tool seçimi, IP/domain kök, otomatik AI.

docker compose exec -T api python -m pytest tests/test_tarama_akisi_db.py -q

Akış: analist araştırmayı kurarken tool'ları seçer -> tek düğmeyle tarama
başlar -> zincirleme yalnızca seçili tool'ları çağırır -> bekleyen iş
kalmadığında AI skorlaması kendiliğinden tetiklenir.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import SessionLocal
from app.main import ONEM_DUZEYLERI, _onem_kodu, app, oturum
from app.models import Investigation, Job, JobStatus


@pytest.fixture
def s():
    with SessionLocal() as oturum_:
        try:
            yield oturum_
        finally:
            oturum_.rollback()


@pytest.fixture
def client(s):
    app.dependency_overrides[oturum] = lambda: s
    try:
        with TestClient(app) as c:
            yield c
    finally:
        app.dependency_overrides.pop(oturum, None)


def _olustur(client, **ek):
    veri = {"ad": "akis-test", "kok_hedef": "example.com", "olusturan": "pytest"}
    veri.update(ek)
    y = client.post("/investigations", data=veri, follow_redirects=False)
    assert y.status_code == 303, y.text
    return uuid.UUID(y.headers["location"].rsplit("/", 1)[1])


def _inv(s, iid) -> Investigation:
    s.expire_all()
    return s.get(Investigation, iid)


def _isler(s, iid):
    return list(s.execute(select(Job).where(Job.investigation_id == iid)).scalars())


# --------------------------------------------------------------------------- #
# Kök hedef: domain ya da IP
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "girdi,beklenen,tip",
    [
        ("example.com", "example.com", "domain"),
        ("WWW.Example.COM", "example.com", "domain"),   # subdomain koke iner
        ("https://api.example.com/v1", "example.com", "domain"),
        ("192.0.2.10", "192.0.2.10", "ip"),
        ("2001:0db8::1", "2001:db8::1", "ip"),          # IPv6 sikistirilir
    ],
)
def test_kok_hedef_tipi_belirlenir(client, s, girdi, beklenen, tip):
    inv = _inv(s, _olustur(client, kok_hedef=girdi))
    assert inv.kok_hedef == beklenen
    assert inv.kok_tip == tip


def test_gecersiz_kok_hedef_reddedilir(client):
    y = client.post("/investigations", data={"ad": "x", "kok_hedef": "  "},
                    follow_redirects=False)
    assert y.status_code == 400


# --------------------------------------------------------------------------- #
# Tool secimi
# --------------------------------------------------------------------------- #


def test_secili_toollar_saklanir(client, s):
    inv = _inv(s, _olustur(client, toollar=["crtsh", "subfinder"]))
    assert set(inv.secili_toollar) == {"crtsh", "subfinder"}


def test_bos_secim_kisit_yok_demektir(client, s):
    """Eski arastirmalar da boyle: bos liste = etkin her tool kullanilir."""
    inv = _inv(s, _olustur(client, toollar=[]))
    assert inv.secili_toollar == []


def test_bilinmeyen_tool_reddedilir(client):
    y = client.post(
        "/investigations",
        data={"ad": "x", "kok_hedef": "example.com", "toollar": ["yok-boyle-tool"]},
        follow_redirects=False,
    )
    assert y.status_code == 400


def test_tekrarlanan_secim_tekillesir(client, s):
    inv = _inv(s, _olustur(client, toollar=["crtsh", "crtsh", "subfinder"]))
    assert inv.secili_toollar.count("crtsh") == 1


# --------------------------------------------------------------------------- #
# Tarama baslatma
# --------------------------------------------------------------------------- #


def test_secili_toollarin_hepsi_tek_hamlede_kuyruga_girer(client, s, monkeypatch):
    import app.main as m

    gonderilen = []
    monkeypatch.setattr(m, "_kuyruga_gonder", gonderilen.append)

    iid = _olustur(client, toollar=["crtsh", "subfinder", "dns-resolver"])
    y = client.post(f"/investigations/{iid}/run", follow_redirects=False)
    assert y.status_code == 303

    isler = _isler(s, iid)
    assert {j.tool for j in isler} == {"crtsh", "subfinder", "dns-resolver"}
    assert all(j.derinlik == 0 for j in isler)
    assert len(gonderilen) == 3, "job satiri yazildi ama gorev gonderilmedi"


def test_kok_tipini_kabul_etmeyen_tool_bu_turda_baslamaz(client, s, monkeypatch):
    """`shodan-lookup` IP bekler; domain kokunde ilk turda kuyruga girmez.

    Atlanmasi veri kaybi DEGILDIR: zincir IP olustugunda onu cagirir.
    """
    import app.main as m

    monkeypatch.setattr(m, "_kuyruga_gonder", lambda *_: None)
    iid = _olustur(client, toollar=["crtsh", "shodan-lookup"])
    client.post(f"/investigations/{iid}/run", follow_redirects=False)

    assert {j.tool for j in _isler(s, iid)} == {"crtsh"}


def test_ip_kokunde_ip_kabul_eden_toollar_baslar(client, s, monkeypatch):
    import app.main as m

    monkeypatch.setattr(m, "_kuyruga_gonder", lambda *_: None)
    iid = _olustur(client, kok_hedef="192.0.2.10",
                   toollar=["shodan-lookup", "asn-bgp", "crtsh"])
    client.post(f"/investigations/{iid}/run", follow_redirects=False)

    baslayan = {j.tool for j in _isler(s, iid)}
    assert "asn-bgp" in baslayan and "shodan-lookup" in baslayan
    assert "crtsh" not in baslayan, "crtsh IP kabul etmiyor"


def test_hicbiri_kok_tipini_kabul_etmiyorsa_hata(client, monkeypatch):
    import app.main as m

    monkeypatch.setattr(m, "_kuyruga_gonder", lambda *_: None)
    iid = _olustur(client, kok_hedef="192.0.2.10", toollar=["crtsh"])
    y = client.post(f"/investigations/{iid}/run", follow_redirects=False)
    assert y.status_code == 400


def test_ikinci_calistirma_tekrar_is_yaratmaz(client, s, monkeypatch):
    """`uq_job_tekrar`: ayni tool + ayni hedef ikinci kez kuyruga girmez."""
    import app.main as m

    monkeypatch.setattr(m, "_kuyruga_gonder", lambda *_: None)
    iid = _olustur(client, toollar=["crtsh"])
    client.post(f"/investigations/{iid}/run", follow_redirects=False)
    client.post(f"/investigations/{iid}/run", follow_redirects=False)
    assert len(_isler(s, iid)) == 1


# --------------------------------------------------------------------------- #
# Zincirleme seciliyle sinirli
# --------------------------------------------------------------------------- #


def test_zincirleme_secili_olmayan_toolu_cagirmaz(s):
    """Analist "shodan kullanma" dediyse ucuncu derinlikte de kullanilmamali."""
    from app.ingest import ingest
    from app.main import registry
    from app.normalize import EntityType
    from app.tools._base import Observation as Gozlem

    inv = Investigation(ad="zincir", kok_hedef="example.com", kok_tip="domain",
                        olusturan="pytest", secili_toollar=["crtsh", "dns-resolver"])
    s.add(inv)
    s.flush()
    job = Job(investigation_id=inv.id, tool="crtsh", tool_version="1",
              hedef_deger="example.com", derinlik=0)
    s.add(job)
    s.flush()

    adapter = registry().get("crtsh")
    ozet = ingest(
        s, job,
        [Gozlem(tip=EntityType.SUBDOMAIN, deger_ham="a.example.com")],
        spec=adapter.spec, ham_cikti_ref="t.json", registry=registry(),
        secili_toollar=list(inv.secili_toollar),
    )
    s.flush()

    zincir = {j.tool for j in _isler(s, inv.id) if j.derinlik == 1}
    assert zincir == {"dns-resolver"}, f"secili olmayan tool cagrildi: {zincir}"
    assert ozet.kuyruga_alinan == 1


# --------------------------------------------------------------------------- #
# Tur bitince AI otomatik tetiklenir
# --------------------------------------------------------------------------- #


def test_bekleyen_is_varken_skorlama_tetiklenmez(s, monkeypatch):
    import app.worker as w

    cagrilar = []
    monkeypatch.setattr(w, "skorlamayi_gonder", lambda i: cagrilar.append(i) or True)

    inv = Investigation(ad="tur", kok_hedef="example.com", olusturan="pytest")
    s.add(inv)
    s.flush()
    s.add(Job(investigation_id=inv.id, tool="crtsh", tool_version="1",
              hedef_deger="example.com",
              durum=JobStatus.QUEUED.value))
    s.flush()

    assert w._tur_bittiyse_skorla(s, inv.id) is False
    assert cagrilar == []


def test_son_is_bitince_skorlama_tetiklenir(s, monkeypatch):
    import app.worker as w

    cagrilar = []
    monkeypatch.setattr(w, "skorlamayi_gonder", lambda i: cagrilar.append(i) or True)

    inv = Investigation(ad="tur", kok_hedef="example.com", olusturan="pytest")
    s.add(inv)
    s.flush()
    s.add(Job(investigation_id=inv.id, tool="crtsh", tool_version="1",
              hedef_deger="example.com",
              durum=JobStatus.SUCCESS.value))
    s.flush()

    assert w._tur_bittiyse_skorla(s, inv.id) is True
    assert cagrilar == [inv.id]


def test_baska_arastirmanin_isi_turu_acik_tutmaz(s, monkeypatch):
    import app.worker as w

    monkeypatch.setattr(w, "skorlamayi_gonder", lambda i: True)
    a = Investigation(ad="a", kok_hedef="a.com", olusturan="pytest")
    b = Investigation(ad="b", kok_hedef="b.com", olusturan="pytest")
    s.add_all([a, b])
    s.flush()
    s.add(Job(investigation_id=a.id, tool="crtsh", tool_version="1",
              hedef_deger="a.com", durum=JobStatus.SUCCESS.value))
    s.add(Job(investigation_id=b.id, tool="crtsh", tool_version="1",
              hedef_deger="b.com", durum=JobStatus.RUNNING.value))
    s.flush()

    assert w._tur_bittiyse_skorla(s, a.id) is True


# --------------------------------------------------------------------------- #
# AI onem duzeyleri
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "skor,beklenen",
    [(100, "kritik"), (90, "kritik"), (89, "yuksek"), (70, "yuksek"),
     (69, "orta"), (50, "orta"), (49, "dusuk"), (0, "dusuk"), (None, "skorsuz")],
)
def test_onem_bantlari_promptaki_rubrikle_ayni(skor, beklenen):
    assert _onem_kodu(skor) == beklenen


def test_onem_bantlari_bosluksuz_ve_ortusmez():
    araliklar = sorted(
        (alt, ust) for _, alt, ust in ONEM_DUZEYLERI.values() if alt is not None
    )
    assert araliklar[0][0] == 0 and araliklar[-1][1] == 101
    for (_, ust), (alt, _) in zip(araliklar, araliklar[1:]):
        assert ust == alt, "bantlarda boşluk ya da örtüşme var"


def test_onem_suzgeci_sayimlari_daraltmaz(client, s, monkeypatch):
    """Suzgec secilse de sayimlar TUM varliklar uzerinden gosterilir (Ilke 1)."""
    import app.main as m

    monkeypatch.setattr(m, "_kuyruga_gonder", lambda *_: None)
    iid = _olustur(client, toollar=["crtsh"])
    y = client.get(f"/investigations/{iid}/entities?onem=kritik")
    assert y.status_code == 200


def test_gecersiz_onem_reddedilir(client):
    iid = _olustur(client)
    assert client.get(f"/investigations/{iid}/entities?onem=cokonemli").status_code == 422
