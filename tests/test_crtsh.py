"""crt.sh adapter'ı — `parse()` saf olduğu için ağsız koşar.

Fixture GERÇEK crt.sh çıktısıdır (`%.example.com`, 12 kayıt seçilmiş): çok
satırlı `name_value`, wildcard SAN'lar, e-posta SAN'ı ve üçüncü taraf alan
adları dahil. crt.sh çıktı formatı sessizce değişirse burası kırılır.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalize import EntityType, NormalizeError, normalize
from app.tools._base import (
    Passivity,
    RawResult,
    RelationType,
    ToolConfig,
    ToolRegistry,
)
from app.tools.crtsh.adapter import CrtShAdapter

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE = TOOL_KOK / "crtsh" / "fixtures" / "sample_output.json"


@pytest.fixture
def adapter() -> CrtShAdapter:
    return CrtShAdapter()


def _ham(icerik: bytes | str) -> RawResult:
    if isinstance(icerik, str):
        icerik = icerik.encode("utf-8")
    return RawResult(icerik=icerik, format="json", cikis_kodu=0)


@pytest.fixture
def fixture_ham() -> RawResult:
    return _ham(FIXTURE.read_bytes())


def _adlar(gozlemler, tip=EntityType.SUBDOMAIN) -> set[str]:
    return {g.deger_ham for g in gozlemler if g.tip is tip}


# --------------------------------------------------------------------------- #
# Fixture
# --------------------------------------------------------------------------- #


def test_fixture_gercek_crtsh_ciktisi():
    """Fixture'sız tool kabul edilmez (docs/kapsam.md 5.2)."""
    assert FIXTURE.is_file() and FIXTURE.stat().st_size > 0
    kayitlar = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(kayitlar, list) and kayitlar
    # crt.sh'ın gerçek alan adları
    for alan in ("name_value", "serial_number", "issuer_name", "not_after"):
        assert alan in kayitlar[0], f"crt.sh alanı kayıp: {alan}"
    # Kenar durumlar fixture'da GERÇEKTEN var olmalı
    assert any("\n" in k["name_value"] for k in kayitlar), "çok satırlı kayıt yok"
    assert any("*" in k["name_value"] for k in kayitlar), "wildcard kayıt yok"


def test_parse_subdomain_ve_cert_uretir(adapter, fixture_ham):
    gozlemler = adapter.parse(fixture_ham)
    tipler = {g.tip for g in gozlemler}
    assert tipler == {EntityType.SUBDOMAIN, EntityType.CERT}
    assert len(gozlemler) > 0


def test_cok_satirli_name_value_ayrilir(adapter):
    """`name_value` çok satırlıdır; her satır AYRI bir isimdir."""
    kayit = [
        {
            "name_value": "a.firma.com\nb.firma.com\nc.firma.com",
            "serial_number": "0624d0ab311558780b7d5213b9631831",
        }
    ]
    gozlemler = adapter.parse(_ham(json.dumps(kayit)))
    assert _adlar(gozlemler) == {"a.firma.com", "b.firma.com", "c.firma.com"}


def test_common_name_de_toplanir(adapter):
    kayit = [{"name_value": "a.firma.com", "common_name": "b.firma.com"}]
    assert _adlar(adapter.parse(_ham(json.dumps(kayit)))) == {
        "a.firma.com",
        "b.firma.com",
    }


def test_wildcard_niteliklerde_isaretlenir(adapter, fixture_ham):
    """Anahtardan temizlenir (normalize'de), bilgisi niteliklerde yaşar."""
    gozlemler = adapter.parse(fixture_ham)
    wild = [g for g in gozlemler if g.deger_ham.startswith("*.")]
    assert wild, "fixture'da wildcard yok"
    assert all(g.nitelikler.get("wildcard") is True for g in wild)
    duz = [
        g
        for g in gozlemler
        if g.tip is EntityType.SUBDOMAIN and not g.deger_ham.startswith("*.")
    ]
    assert all("wildcard" not in g.nitelikler for g in duz)
    # normalize wildcard'ı zaten temizliyor → aynı anahtara düşüyorlar
    assert normalize(EntityType.SUBDOMAIN, "*.example.com") == "example.com"


def test_eposta_san_atlanir(adapter):
    """rfc822Name SAN'ı SUBDOMAIN sanılırsa UYDURMA veri üretilir.

    `subjectname@example.com` normalize'de 'example.com'a düşer — yani var
    olmayan bir alt alan adı gözlemi doğar. Manifest EMAIL üretmediği için
    kayıt atlanır.
    """
    kayit = [
        {
            "name_value": "subjectname@example.com\ngercek.example.com",
            "serial_number": "0624d0ab311558780b7d5213b9631831",
        }
    ]
    adlar = _adlar(adapter.parse(_ham(json.dumps(kayit))))
    assert adlar == {"gercek.example.com"}
    assert not any("@" in a for a in adlar)


def test_hostname_olmayan_common_name_atlanir():
    """CANLI ÇAĞRIDA YAKALANDI — fixture bunu kaçırmıştı.

    `common_name` her zaman DNS adı değildir; ara sertifika otoritelerinde
    okunabilir bir etikettir. Gerçek crt.sh yanıtından alınan örnek:
        'AS207960 Test Intermediate - example.com'
    Süzülmezse `normalize` 'etikette geçersiz karakter' ile reddeder ve her
    CA sertifikası için gereksiz bir WARNING basılır.
    """
    adapter = CrtShAdapter()
    kayit = [
        {
            "name_value": "a.firma.com",
            "common_name": "AS207960 Test Intermediate - example.com",
            "serial_number": "0624d0ab31155878",
        }
    ]
    adlar = _adlar(adapter.parse(_ham(json.dumps(kayit))))
    assert adlar == {"a.firma.com"}
    assert not any(" " in a for a in adlar)


def test_uretilen_her_ad_normalize_edilebilir(adapter, fixture_ham):
    """Adapter'ın verdiği hiçbir SUBDOMAIN ingest'te WARNING'e düşmemeli."""
    for g in adapter.parse(fixture_ham):
        if g.tip is EntityType.SUBDOMAIN:
            normalize(EntityType.SUBDOMAIN, g.deger_ham)


# --------------------------------------------------------------------------- #
# CERT ve ilişki
# --------------------------------------------------------------------------- #


def test_cert_degeri_normalize_edilebiliyor(adapter, fixture_ham):
    """CERT `deger_norm` üretilemezse ingest bu gözlemleri sessizce atardı."""
    certler = [g for g in adapter.parse(fixture_ham) if g.tip is EntityType.CERT]
    assert certler
    for c in certler:
        normalize(EntityType.CERT, c.deger_ham)  # NormalizeError fırlatmamalı


def test_cert_for_iliskisi_dogru_yonde(adapter, fixture_ham):
    """`cert_for` = cert → domain/sub. Gözlem SUBDOMAIN olduğu için yön 'gelen'."""
    gozlemler = adapter.parse(fixture_ham)
    subler = [g for g in gozlemler if g.tip is EntityType.SUBDOMAIN and g.iliskiler]
    assert subler
    il = subler[0].iliskiler[0]
    assert il.tip is RelationType.CERT_FOR
    assert il.hedef_tip is EntityType.CERT
    assert il.yon == "gelen"
    # Hedef, aynı kayıttan üretilen CERT gözlemiyle AYNI değer olmalı
    cert_degerleri = {g.deger_ham for g in gozlemler if g.tip is EntityType.CERT}
    assert il.hedef_deger in cert_degerleri


def test_serial_yoksa_cert_ve_iliski_yok(adapter):
    """Kimliği olmayan sertifika uydurulmaz; isimler yine toplanır."""
    kayit = [{"name_value": "a.firma.com"}]
    gozlemler = adapter.parse(_ham(json.dumps(kayit)))
    assert _adlar(gozlemler) == {"a.firma.com"}
    assert not [g for g in gozlemler if g.tip is EntityType.CERT]
    assert gozlemler[0].iliskiler == ()


def test_ayni_sertifika_tekrar_donebilir(adapter):
    """Dedup ingest'in işi; parser aynı sertifikayı iki kez bildirebilir."""
    seri = "0624d0ab311558780b7d5213b9631831"
    kayit = [
        {"name_value": "a.firma.com", "serial_number": seri},
        {"name_value": "b.firma.com", "serial_number": seri},
    ]
    certler = [
        g for g in adapter.parse(_ham(json.dumps(kayit))) if g.tip is EntityType.CERT
    ]
    assert len(certler) == 2
    assert {c.deger_ham for c in certler} == {seri}


def test_kaynak_yol_dolu(adapter, fixture_ham):
    """İlke 2: her gözlem ham çıktının neresinden geldiğini bilmeli."""
    for g in adapter.parse(fixture_ham):
        assert g.kaynak_yol and g.kaynak_yol.startswith("$[")


# --------------------------------------------------------------------------- #
# Bozuk girdi — İSTİSNA FIRLATMAZ
# --------------------------------------------------------------------------- #


def test_bozuk_kayit_digerlerini_dusurmez(adapter):
    kayit = [
        {"name_value": "a.firma.com", "serial_number": "0624d0ab31155878"},
        "bu bir sozluk degil",
        {"baska": "alan"},  # name_value yok
        {"name_value": None},  # yanlis tip
        {"name_value": "c.firma.com", "serial_number": "0624d0ab31155879"},
    ]
    assert _adlar(adapter.parse(_ham(json.dumps(kayit)))) == {
        "a.firma.com",
        "c.firma.com",
    }


@pytest.mark.parametrize(
    "govde",
    [
        b"",
        b"<html><body>502 Bad Gateway</body></html>",  # crt.sh sik dusen servis
        b"{}",  # dizi degil
        b'"metin"',
        b"[]",
        b"[1, 2, 3]",
        b"\xff\xfe bozuk bayt",
    ],
)
def test_bozuk_govde_istisna_firlatmaz(adapter, govde):
    assert adapter.parse(_ham(govde)) == []


def test_parse_saf_fonksiyon(adapter, fixture_ham, monkeypatch):
    import socket

    def _yasak(*a, **k):  # pragma: no cover
        raise AssertionError("parse() ağa çıktı!")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "getaddrinfo", _yasak)

    bir = adapter.parse(fixture_ham)
    iki = adapter.parse(fixture_ham)
    assert [(g.tip, g.deger_ham) for g in bir] == [(g.tip, g.deger_ham) for g in iki]


# --------------------------------------------------------------------------- #
# Spec ve registry
# --------------------------------------------------------------------------- #


def test_spec_pasif_ve_otoriter(adapter):
    s = adapter.spec
    assert s.passivity is Passivity.P0
    assert s.yetki_ister() is False
    assert s.varsayilan_guven == 90  # CT logu otoriter kaynak
    assert s.calistirma == "api"
    assert s.image is None
    assert s.timeout_sn == 45
    assert s.dakikalik_istek == 5


def test_registry_crtsh_i_buluyor():
    r = ToolRegistry(TOOL_KOK)
    assert r.get("crtsh") is not None


def test_tuketenler_domain_iki_tool_donduruyor():
    """Yetenek grafiği: DOMAIN girince İKİ tool birden zincirlenmeli."""
    r = ToolRegistry(TOOL_KOK)
    adlar = {a.spec.name for a in r.tuketenler(EntityType.DOMAIN)}
    assert {"subfinder", "crtsh"} <= adlar


def test_cert_ureten_tek_tool():
    r = ToolRegistry(TOOL_KOK)
    assert {a.spec.name for a in r.uretenler(EntityType.CERT)} == {"crtsh"}


def test_crtsh_subdomain_tuketmez():
    """sub → sub döngüsü kurulmaz; crtsh yalnızca DOMAIN kabul eder."""
    r = ToolRegistry(TOOL_KOK)
    assert "crtsh" not in {a.spec.name for a in r.tuketenler(EntityType.SUBDOMAIN)}


# --------------------------------------------------------------------------- #
# Gerçek crt.sh çağrısı — YAVAŞ
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_gercek_crtsh_cagrisi(adapter):
    """crt.sh'a gerçek istek. Servis düşükse (502 olağandır) atlanır."""
    ham = adapter.calistir("example.com", ToolConfig())

    if ham.cikis_kodu != 0:
        pytest.skip(f"crt.sh şu an erişilemiyor (HTTP {ham.cikis_kodu})")

    assert ham.format == "json"
    assert ham.icerik
    gozlemler = adapter.parse(ham)
    assert gozlemler, "crt.sh 200 döndü ama hiç gözlem çıkmadı"

    subler = [g for g in gozlemler if g.tip is EntityType.SUBDOMAIN]
    assert subler
    # Gerçek veri normalize edilebiliyor mu — fixture'ın yakalamadığı sürprizler
    for g in subler:
        try:
            normalize(EntityType.SUBDOMAIN, g.deger_ham)
        except NormalizeError as e:  # pragma: no cover
            pytest.fail(f"gerçek crt.sh verisi normalize edilemedi: {g.deger_ham!r} {e}")


@pytest.mark.slow
def test_gercek_crtsh_dustugunde_cokmez(adapter):
    """Servis 502 verirse adapter istisna değil, çıkış kodu döndürür."""
    ham = adapter.calistir("example.com", ToolConfig())
    assert isinstance(ham.icerik, bytes)
    assert adapter.parse(ham) is not None  # her hâlükârda liste döner
