"""subfinder parser'ı ve tool keşfi — hiçbir dış bağımlılık YOK.

`parse()` saf fonksiyon olduğu için bu testler ağ, Docker ve veritabanı
olmadan koşar. Fixture gerçek subfinder çıktısıdır (`-d example.com -silent
-json`, ilk 24 satır): subfinder'ın çıktı formatı sessizce değişirse burası
kırılır. Fixture'ın var olma sebebi budur.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.normalize import EntityType
from app.tools._base import (
    Passivity,
    RawResult,
    RelationType,
    ToolRegistry,
    ToolYuklemeHatasi,
)
from app.tools.subfinder.adapter import SubfinderAdapter

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE = TOOL_KOK / "subfinder" / "fixtures" / "sample_output.jsonl"


@pytest.fixture
def adapter() -> SubfinderAdapter:
    return SubfinderAdapter()


def _ham(icerik: bytes) -> RawResult:
    return RawResult(icerik=icerik, format="json", cikis_kodu=0)


@pytest.fixture
def fixture_ham() -> RawResult:
    return _ham(FIXTURE.read_bytes())


# --------------------------------------------------------------------------- #
# parse() — fixture
# --------------------------------------------------------------------------- #


def test_fixture_var_ve_bos_degil():
    """Fixture'sız tool kabul edilmez (docs/kapsam.md 5.2)."""
    assert FIXTURE.is_file()
    assert FIXTURE.stat().st_size > 0


def test_parse_fixture(adapter, fixture_ham):
    gozlemler = adapter.parse(fixture_ham)

    satir_sayisi = len(
        [s for s in FIXTURE.read_text(encoding="utf-8").splitlines() if s.strip()]
    )
    assert len(gozlemler) == satir_sayisi

    for g in gozlemler:
        assert g.tip is EntityType.SUBDOMAIN
        assert g.deger_ham.endswith(".example.com")
        assert g.kaynak_yol is not None and g.kaynak_yol.startswith("$[")
        assert "subfinder_kaynak" in g.nitelikler


def test_parse_iliski_kuruyor(adapter, fixture_ham):
    """`input` alanı kök domain'dir: sub -> domain `subdomain_of` ilişkisi."""
    gozlemler = adapter.parse(fixture_ham)
    g = gozlemler[0]
    assert len(g.iliskiler) == 1
    il = g.iliskiler[0]
    assert il.tip is RelationType.SUBDOMAIN_OF
    assert il.hedef_tip is EntityType.DOMAIN
    assert il.hedef_deger == "example.com"
    assert il.yon == "giden"


def test_parse_saf_fonksiyon(adapter, fixture_ham, monkeypatch):
    """Ağ yok, saat yok, rastgelelik yok — iki çağrı aynı sonucu verir."""
    import socket

    def _yasak(*a, **k):  # pragma: no cover
        raise AssertionError("parse() ağa çıktı!")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "getaddrinfo", _yasak)

    bir = adapter.parse(fixture_ham)
    iki = adapter.parse(fixture_ham)
    assert [(g.tip, g.deger_ham) for g in bir] == [(g.tip, g.deger_ham) for g in iki]


# --------------------------------------------------------------------------- #
# parse() — bozuk girdi. İSTİSNA FIRLATMAZ.
# --------------------------------------------------------------------------- #


def test_bozuk_satir_digerlerini_dusurmez(adapter):
    """Tek yarım satır yüzünden diğer bulgular çöpe atılmaz."""
    icerik = b"""{"host":"a.firma.com","input":"firma.com","source":"crtsh"}
{"host":"b.firma.com","input":"firma.com","son
{"host":"c.firma.com","input":"firma.com","source":"crtsh"}
"""
    gozlemler = adapter.parse(icerik and _ham(icerik))
    assert [g.deger_ham for g in gozlemler] == ["a.firma.com", "c.firma.com"]


@pytest.mark.parametrize(
    "icerik",
    [
        b"",
        b"\n\n\n",
        b"tamamen json degil\n",
        b"[1,2,3]\n",  # JSON ama dict degil
        b'{"input":"firma.com"}\n',  # host yok
        b'{"host":"","input":"firma.com"}\n',  # host bos
        b'{"host":null,"input":"firma.com"}\n',  # host null
        b'"sadece string"\n',
    ],
)
def test_bozuk_girdi_istisna_firlatmaz(adapter, icerik):
    assert adapter.parse(_ham(icerik)) == []


def test_kismi_cikti_ayristirilir(adapter):
    """Timeout'ta stdout ortadan kesilir; kalan satırlar yine kullanılır."""
    icerik = (
        b'{"host":"a.firma.com","input":"firma.com","source":"crtsh"}\n'
        b'{"host":"b.firma.com","in'
    )
    gozlemler = adapter.parse(_ham(icerik))
    assert [g.deger_ham for g in gozlemler] == ["a.firma.com"]


def test_kok_domain_kendisi_iliski_kurmaz(adapter):
    """`host == input` ise kendine `subdomain_of` ilişkisi kurulmaz."""
    icerik = b'{"host":"firma.com","input":"firma.com","source":"crtsh"}\n'
    (g,) = adapter.parse(_ham(icerik))
    assert g.iliskiler == ()


def test_utf8_olmayan_bayt_cokmez(adapter):
    icerik = b'{"host":"a.firma.com","input":"firma.com","source":"x"}\n\xff\xfe\n'
    gozlemler = adapter.parse(_ham(icerik))
    assert [g.deger_ham for g in gozlemler] == ["a.firma.com"]


# --------------------------------------------------------------------------- #
# Komut kurulumu
# --------------------------------------------------------------------------- #


def test_komut_pasif_kalir(adapter):
    komut = adapter.komut("firma.com")
    assert komut == ["-d", "firma.com", "-silent", "-json"]
    # Brute-force Seviye A'dır: bu bayraklar ASLA geçmemeli.
    assert "-brute" not in komut
    assert "-all" not in komut


def test_calistir_dogrudan_cagrilmaz(adapter):
    """docker tool'unda `calistir()` sessizce boş dönmek yerine bağırır."""
    from app.tools._base import ToolConfig

    with pytest.raises(NotImplementedError):
        adapter.calistir("firma.com", ToolConfig())


# --------------------------------------------------------------------------- #
# Registry — keşif ve yetenek grafiği
# --------------------------------------------------------------------------- #


def test_registry_subfinderi_buluyor():
    r = ToolRegistry(TOOL_KOK)
    adapter = r.get("subfinder")
    assert adapter is not None
    assert adapter.spec.passivity is Passivity.P0
    assert adapter.spec.varsayilan_guven == 70
    assert adapter.spec.calistirma == "docker"


def test_tuketenler_zincirlemenin_kalbi():
    """DOMAIN üretildiğinde subfinder kuyruğa girmeli — elle kural yazılmadan."""
    r = ToolRegistry(TOOL_KOK)
    assert "subfinder" in [a.spec.name for a in r.tuketenler(EntityType.DOMAIN)]
    assert "subfinder" in [a.spec.name for a in r.uretenler(EntityType.SUBDOMAIN)]
    # subfinder SUBDOMAIN tüketmez: sub -> sub döngüsü kurulmaz
    assert "subfinder" not in [a.spec.name for a in r.tuketenler(EntityType.SUBDOMAIN)]
    assert r.tuketenler(EntityType.IP) == []


def test_bos_klasorle_cokmez(tmp_path):
    """Kabul kriteri: boş klasörle sorunsuz açılır, tuketenler() boş döner."""
    r = ToolRegistry(tmp_path)
    assert len(r) == 0
    assert r.tuketenler(EntityType.DOMAIN) == []
    assert ToolRegistry(tmp_path / "hic-yok") is not None


def test_manifestsiz_klasor_sessizce_atlanir(tmp_path):
    """manifest.yaml yoksa burası tool değildir — hata değil."""
    (tmp_path / "yardimci").mkdir()
    (tmp_path / "yardimci" / "adapter.py").write_text("# tool degil")
    assert len(ToolRegistry(tmp_path)) == 0


# --------------------------------------------------------------------------- #
# Registry — bozuk manifest SESSİZCE ATLANMAZ
# --------------------------------------------------------------------------- #


def _tool_yaz(kok: Path, manifest: str, adapter_kaynak: str = "", fixture=True) -> Path:
    d = kok / "bozuk"
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.yaml").write_text(manifest, encoding="utf-8")
    (d / "adapter.py").write_text(adapter_kaynak, encoding="utf-8")
    if fixture:
        (d / "fixtures").mkdir(exist_ok=True)
        (d / "fixtures" / "ornek.json").write_text("{}", encoding="utf-8")
    return d


SAGLAM_MANIFEST = """
name: bozuk
version: "1.0"
passivity: P0
kabul_eder: [DOMAIN]
uretir: [SUBDOMAIN]
calistirma: docker
"""

SAGLAM_ADAPTER = """
from app.normalize import EntityType
from app.tools._base import Passivity, ToolSpec

class BozukAdapter:
    spec = ToolSpec(
        name="bozuk", version="1.0", passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.SUBDOMAIN}),
        calistirma="docker",
    )
    def parse(self, ham): return []
"""


def test_saglam_tool_yuklenir(tmp_path):
    """Negatif testlerin anlamlı olması için önce pozitif durum."""
    _tool_yaz(tmp_path, SAGLAM_MANIFEST, SAGLAM_ADAPTER)
    assert ToolRegistry(tmp_path).get("bozuk") is not None


@pytest.mark.parametrize(
    "manifest,beklenen",
    [
        ("name: bozuk\n", "zorunlu alan eksik"),
        (SAGLAM_MANIFEST.replace("P0", "P9"), "geçersiz passivity"),
        (SAGLAM_MANIFEST.replace("[DOMAIN]", "[HAYVAN]"), "bilinmeyen varlık tipi"),
        (SAGLAM_MANIFEST.replace("kabul_eder: [DOMAIN]", "kabul_eder: DOMAIN"), "liste olmalı"),
        ("[1, 2, 3]\n", "sözlük olmalı"),
        ("name: [bozuk\n", "ayrıştırılamadı"),
    ],
)
def test_bozuk_manifest_net_hata(tmp_path, manifest, beklenen):
    _tool_yaz(tmp_path, manifest, SAGLAM_ADAPTER)
    with pytest.raises(ToolYuklemeHatasi, match=beklenen):
        ToolRegistry(tmp_path)


def test_adaptersiz_manifest_hata(tmp_path):
    d = _tool_yaz(tmp_path, SAGLAM_MANIFEST, SAGLAM_ADAPTER)
    (d / "adapter.py").unlink()
    with pytest.raises(ToolYuklemeHatasi, match="adapter.py yok"):
        ToolRegistry(tmp_path)


def test_fixturesiz_tool_reddedilir(tmp_path):
    """Fixture'sız tool KABUL EDİLMEZ — kural koda gömülü."""
    _tool_yaz(tmp_path, SAGLAM_MANIFEST, SAGLAM_ADAPTER, fixture=False)
    with pytest.raises(ToolYuklemeHatasi, match="fixture"):
        ToolRegistry(tmp_path)


def test_import_edilemeyen_adapter_hata(tmp_path):
    _tool_yaz(tmp_path, SAGLAM_MANIFEST, "import yok_boyle_bir_modul\n")
    with pytest.raises(ToolYuklemeHatasi, match="import edilemedi"):
        ToolRegistry(tmp_path)


def test_specsiz_adapter_hata(tmp_path):
    _tool_yaz(tmp_path, SAGLAM_MANIFEST, "class Bos:\n    pass\n")
    with pytest.raises(ToolYuklemeHatasi, match="ToolSpec.*bulunamadı"):
        ToolRegistry(tmp_path)


def test_manifest_spec_uyusmazligi_hata(tmp_path):
    """İki doğruluk kaynağı birbirinden kayarsa sessiz kalmaz."""
    _tool_yaz(
        tmp_path, SAGLAM_MANIFEST.replace('version: "1.0"', 'version: "9.9"'),
        SAGLAM_ADAPTER,
    )
    with pytest.raises(ToolYuklemeHatasi, match="uyuşmuyor"):
        ToolRegistry(tmp_path)


def test_manifest_spec_uretir_uyusmazligi(tmp_path):
    _tool_yaz(
        tmp_path, SAGLAM_MANIFEST.replace("uretir: [SUBDOMAIN]", "uretir: [IP]"),
        SAGLAM_ADAPTER,
    )
    with pytest.raises(ToolYuklemeHatasi, match="uretir"):
        ToolRegistry(tmp_path)
