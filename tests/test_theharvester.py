"""theHarvester adapter'ı — `parse()` saf, testler ağsız.

Fixture GERÇEK çıktıdır (`-d python.org`, 7 pasif kaynak, tam güvenlik
kısıtları altında koşturuldu): 155 host, 1 e-posta.

Fixture'ın kapsadığı gerçek kenar durumlar:
  `blog.python.org:142.251.45.211`  → ad:IP biçimi (129 kayıt)
  `2Fblog.python.org`               → URL-kodlu çöp, %2F sızıntısı (10 kayıt)
  `Docs.python.org`                 → karışık büyük harf
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalize import EntityType, normalize
from app.tools._base import Passivity, RawResult, RelationType, ToolRegistry
from app.tools.theharvester.adapter import (
    PASIF_KAYNAKLAR,
    YASAK_BAYRAKLAR,
    TheHarvesterAdapter,
)

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE = TOOL_KOK / "theharvester" / "fixtures" / "sample_output.json"
IMAJ = "osint-theharvester:1.0"


@pytest.fixture
def adapter() -> TheHarvesterAdapter:
    return TheHarvesterAdapter()


def _ham(veri) -> RawResult:
    if isinstance(veri, (dict, list)):
        veri = json.dumps(veri)
    if isinstance(veri, str):
        veri = veri.encode("utf-8")
    return RawResult(icerik=veri, format="json", cikis_kodu=0)


@pytest.fixture
def fixture_ham() -> RawResult:
    return _ham(FIXTURE.read_bytes())


def _tip(gozlemler, tip):
    return [g for g in gozlemler if g.tip is tip]


def _adlar(gozlemler, tip=EntityType.SUBDOMAIN):
    return {g.deger_ham for g in _tip(gozlemler, tip)}


# --------------------------------------------------------------------------- #
# Fixture
# --------------------------------------------------------------------------- #


def test_fixture_gercek_cikti():
    assert FIXTURE.is_file() and FIXTURE.stat().st_size > 0
    d = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert {"emails", "hosts"} <= set(d)
    # Kenar durumlar fixture'da GERÇEKTEN olmalı
    h = d["hosts"]
    assert any(":" in x for x in h), "ad:IP biçimi fixture'da yok"
    assert any(x.startswith("2F") for x in h), "URL-kodlu çöp fixture'da yok"


def test_parse_email_ve_subdomain_uretir(adapter, fixture_ham):
    tipler = {g.tip for g in adapter.parse(fixture_ham)}
    assert tipler == {EntityType.EMAIL, EntityType.SUBDOMAIN}


def test_uretilen_her_deger_normalize_edilebilir(adapter, fixture_ham):
    """Hiçbir gözlem ingest'te WARNING'e düşmemeli."""
    for g in adapter.parse(fixture_ham):
        normalize(g.tip, g.deger_ham)


def test_parse_saf_fonksiyon(adapter, fixture_ham, monkeypatch):
    import socket

    def _yasak(*a, **k):  # pragma: no cover
        raise AssertionError("parse() ağa çıktı!")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "getaddrinfo", _yasak)

    assert [(g.tip, g.deger_ham) for g in adapter.parse(fixture_ham)] == [
        (g.tip, g.deger_ham) for g in adapter.parse(fixture_ham)
    ]


# --------------------------------------------------------------------------- #
# PASİFLİK — aktif modüller komutta OLMAMALI
# --------------------------------------------------------------------------- #


def test_komutta_aktif_bayrak_yok(adapter):
    """DNS brute-force Seviye A'dır; komuta sızarsa v1 kapsamı delinir."""
    komut = adapter.komut("firma.com")
    for bayrak in YASAK_BAYRAKLAR:
        assert bayrak not in komut, f"AKTİF BAYRAK KOMUTTA: {bayrak}"


def test_komut_beklenen_bicimde(adapter):
    assert adapter.komut("firma.com") == [
        "-d",
        "firma.com",
        "-b",
        ",".join(PASIF_KAYNAKLAR),
    ]


def test_kaynaklar_pasif_ve_anahtarsiz():
    """Anahtar isteyen ya da aktif davranan kaynak listede olmamalı."""
    yasak = {
        "shodan",  # ayrı bir tool olacak
        "censys",
        "hunter",
        "intelx",
        "netlas",
        "binaryedge",
        "fullhunt",
        "securityTrails",
        "virustotal",
        "zoomeye",
        "github-code",
    }
    assert not (set(PASIF_KAYNAKLAR) & yasak), "anahtarlı/ayrı tool kaynağı listede"


def test_crtsh_kaynagi_kullanilmiyor():
    """Kendi crtsh tool'umuz var; aynı veriyi iki kez toplamayız."""
    assert "crtsh" not in PASIF_KAYNAKLAR


def test_calistir_dogrudan_cagrilmaz(adapter):
    from app.tools._base import ToolConfig

    with pytest.raises(NotImplementedError):
        adapter.calistir("firma.com", ToolConfig())


# --------------------------------------------------------------------------- #
# Host ayrıştırma — gerçek kenar durumlar
# --------------------------------------------------------------------------- #


def test_ad_ip_bicimi_ayrilir(adapter):
    """'blog.firma.com:1.2.3.4' → ad SUBDOMAIN, IP niteliklerde."""
    g = adapter.parse(_ham({"hosts": ["blog.firma.com:1.2.3.4"], "emails": []}))
    (s,) = _tip(g, EntityType.SUBDOMAIN)

    assert s.deger_ham == "blog.firma.com"
    assert s.nitelikler["cozumlenen_ip"] == "1.2.3.4"


def test_ip_entitysi_uretilmez(adapter, fixture_ham):
    """Manifest `uretir: [EMAIL, SUBDOMAIN]`; beyan edilmemiş tip üretilmez."""
    assert _tip(adapter.parse(fixture_ham), EntityType.IP) == []


def test_url_kodlu_cop_eleniyor(adapter):
    """'%2F' sızıntısı: gerçek çıktıda 10 tane vardı."""
    g = adapter.parse(
        _ham(
            {
                "hosts": [
                    "2Fblog.firma.com",
                    "gercek.firma.com",
                    "a%2Fb.firma.com",
                ],
                "emails": [],
            }
        )
    )
    assert _adlar(g) == {"gercek.firma.com"}


@pytest.mark.parametrize(
    "cop",
    ["", "   ", "noktasizad", "bosluk li.firma.com", "posta@firma.com", "2Fx.firma.com"],
)
def test_bariz_cop_eleniyor(adapter, cop):
    g = adapter.parse(_ham({"hosts": [cop, "iyi.firma.com"], "emails": []}))
    assert _adlar(g) == {"iyi.firma.com"}


def test_fixture_copu_gercekten_eliyor(adapter, fixture_ham):
    """Gerçek çıktıdaki 10 çöp kaydı elenmiş olmalı."""
    ham_sayi = len(json.loads(FIXTURE.read_text(encoding="utf-8"))["hosts"])
    cikan = len(_tip(adapter.parse(fixture_ham), EntityType.SUBDOMAIN))

    assert cikan < ham_sayi, "hiç çöp elenmedi"
    assert not any(a.startswith("2F") for a in _adlar(adapter.parse(fixture_ham)))


def test_sondaki_nokta_atilir(adapter):
    g = adapter.parse(_ham({"hosts": ["a.firma.com."], "emails": []}))
    assert _adlar(g) == {"a.firma.com"}


# --------------------------------------------------------------------------- #
# E-posta
# --------------------------------------------------------------------------- #


def test_email_at_iliskisi_yonu(adapter, fixture_ham):
    """`email_at` = email → domain. Gözlem e-posta: yön 'giden'."""
    (e,) = _tip(adapter.parse(fixture_ham), EntityType.EMAIL)

    assert e.deger_ham == "python-committers@python.org"
    il = e.iliskiler[0]
    assert il.tip is RelationType.EMAIL_AT
    assert il.hedef_tip is EntityType.DOMAIN
    assert il.hedef_deger == "python.org"
    assert il.yon == "giden"


def test_deger_ham_korunur_normalize_etmez(adapter):
    """§3.4: plus-tag ayıklaması `normalize()`'ın işi; `deger_ham` ilk hâl."""
    g = adapter.parse(_ham({"hosts": [], "emails": ["Ahmet+etiket@Firma.COM"]}))
    (e,) = _tip(g, EntityType.EMAIL)

    assert e.deger_ham == "Ahmet+etiket@Firma.COM"  # dokunulmadı
    assert normalize(EntityType.EMAIL, e.deger_ham) == "ahmet@firma.com"


@pytest.mark.parametrize(
    "bozuk",
    [
        "@firma.com",
        "ahmet@",
        "ahmet",
        "ahmet@@firma.com",
        "ahmet@noktasiz",
        "ah met@firma.com",
        "ahmet@%2Ffirma.com",
        "ahmet@.firma.com",
    ],
)
def test_gecersiz_eposta_eleniyor(adapter, bozuk):
    g = adapter.parse(_ham({"hosts": [], "emails": [bozuk, "iyi@firma.com"]}))
    assert _adlar(g, EntityType.EMAIL) == {"iyi@firma.com"}


def test_farkli_alanlardan_epostalar(adapter):
    """Her e-posta KENDİ alanına bağlanır, ortak varsayım yapılmaz."""
    g = adapter.parse(
        _ham({"hosts": [], "emails": ["a@firma.com", "b@baska.com"]})
    )
    hedefler = {e.iliskiler[0].hedef_deger for e in _tip(g, EntityType.EMAIL)}
    assert hedefler == {"firma.com", "baska.com"}


# --------------------------------------------------------------------------- #
# Boş ve bozuk çıktı
# --------------------------------------------------------------------------- #


def test_sonuc_bulunamamasi_normaldir(adapter):
    """Boş sonuç FAILED değildir."""
    assert adapter.parse(_ham({"emails": [], "hosts": []})) == []
    assert adapter.parse(_ham({})) == []


@pytest.mark.parametrize(
    "govde", [b"", b"bozuk", b"[1,2]", b'"metin"', b"\xff\xfe", b'{"hosts":null}']
)
def test_bozuk_govde_istisna_firlatmaz(adapter, govde):
    assert adapter.parse(_ham(govde)) == []


def test_liste_icinde_yanlis_tip_cokmez(adapter):
    g = adapter.parse(
        _ham({"hosts": [None, 42, "iyi.firma.com"], "emails": [None, "a@firma.com"]})
    )
    assert _adlar(g) == {"iyi.firma.com"}
    assert _adlar(g, EntityType.EMAIL) == {"a@firma.com"}


# --------------------------------------------------------------------------- #
# Spec ve zincirleme
# --------------------------------------------------------------------------- #


def test_spec(adapter):
    s = adapter.spec
    assert s.passivity is Passivity.P0
    assert s.yetki_ister() is False
    assert s.varsayilan_guven == 60
    assert s.calistirma == "docker"
    assert s.image == IMAJ
    assert s.kabul_eder == {EntityType.DOMAIN}
    assert s.uretir == {EntityType.EMAIL, EntityType.SUBDOMAIN}


def test_registry_theharvesteri_buluyor():
    assert ToolRegistry(TOOL_KOK).get("theharvester") is not None


def test_zincirleme():
    r = ToolRegistry(TOOL_KOK)
    assert "theharvester" in {a.spec.name for a in r.tuketenler(EntityType.DOMAIN)}
    # Ürettiği SUBDOMAIN'i dns-resolver tüketir → zincir devam eder
    assert "theharvester" in {a.spec.name for a in r.uretenler(EntityType.SUBDOMAIN)}
    assert r.tuketenler(EntityType.SUBDOMAIN)
    # EMAIL tüketen tool yok (kişi araştırması kapsam dışı) — zincir burada biter
    assert r.tuketenler(EntityType.EMAIL) == []
    assert "theharvester" in {a.spec.name for a in r.uretenler(EntityType.EMAIL)}


def test_theharvester_subdomain_tuketmez():
    """DOMAIN kabul eder; sub → sub döngüsü kurulmaz."""
    r = ToolRegistry(TOOL_KOK)
    assert "theharvester" not in {
        a.spec.name for a in r.tuketenler(EntityType.SUBDOMAIN)
    }


# --------------------------------------------------------------------------- #
# Canlı container — YAVAŞ
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_gercek_container_read_only_altinda_kosuyor(adapter):
    """read_only + cap_drop=ALL + uid 1000 altında GERÇEKTEN çalışıyor mu.

    subfinder'da olduğu gibi: imajın tek başına çalışması yetmez, runner'ın
    dayattığı kısıtlar altında çalışması gerekir.
    """
    import uuid

    import docker
    from docker.errors import DockerException

    from app.models import JobStatus
    from app.runner import RunnerConfig, ToolRunner

    try:
        istemci = docker.from_env()
        istemci.ping()
        istemci.images.get(IMAJ)
    except (DockerException, Exception) as e:  # noqa: BLE001
        pytest.skip(f"Docker ya da imaj yok: {e}")

    import tempfile

    with tempfile.TemporaryDirectory() as d:
        r = ToolRunner(RunnerConfig(raw_kok=Path(d)), client=istemci)
        sonuc = r.calistir(
            adapter, "python.org", uuid.uuid4(), komut=adapter.komut("python.org")
        )

    assert sonuc.durum is JobStatus.SUCCESS, f"kısıtlar altında düştü: {sonuc.hata_mesaji}"
    gozlemler = adapter.parse(sonuc.ham)
    assert gozlemler, "canlı koşudan hiç gözlem çıkmadı"
    for g in gozlemler:
        normalize(g.tip, g.deger_ham)
