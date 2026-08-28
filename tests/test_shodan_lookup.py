"""shodan-lookup adapter'ı — `parse()` saf, testler ağsız.

Fixture GERÇEK Shodan yanıtıdır (`/shodan/host/140.82.121.4`, GitHub): 3 servis,
1303 karakterlik SSH banner'ı, org ve tazelik damgaları.

Bu tool API anahtarı gerektiren TEK tool'dur; testlerin bir kısmı anahtarın
hiçbir yere SIZMADIĞINI doğrular.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models import JobStatus
from app.normalize import EntityType, normalize
from app.runner import GECICI_KODLAR, KALICI_KODLAR, anahtar_engeli, gecici_mi
from app.tools._base import Passivity, RawResult, RelationType, ToolConfig, ToolRegistry
from app.tools.shodan_lookup.adapter import (
    BANNER_SINIRI,
    ShodanLookupAdapter,
)

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE = TOOL_KOK / "shodan_lookup" / "fixtures" / "host_response.json"

SAHTE_ANAHTAR = "SAHTE_ANAHTAR_abc123XYZ"


@pytest.fixture
def adapter() -> ShodanLookupAdapter:
    return ShodanLookupAdapter()


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


def _host(**ek):
    d = {
        "ip_str": "1.2.3.4",
        "org": "Test Kurumu",
        "data": [{"port": 443, "transport": "tcp"}],
    }
    d.update(ek)
    return d


# --------------------------------------------------------------------------- #
# Fixture
# --------------------------------------------------------------------------- #


def test_fixture_gercek_shodan_yaniti():
    assert FIXTURE.is_file() and FIXTURE.stat().st_size > 0
    d = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert {"ip_str", "data", "org", "ports"} <= set(d)
    assert d["data"], "servis kaydı yok"


def test_fixturede_anahtar_yok():
    """Fixture'a anahtar sızmamış olmalı."""
    metin = FIXTURE.read_text(encoding="utf-8")
    assert "key=" not in metin
    assert "api_key" not in metin.lower()


def test_uretilen_her_deger_normalize_edilebilir(adapter, fixture_ham):
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
# API ANAHTARI — sızıntı ve eksiklik
# --------------------------------------------------------------------------- #


def test_anahtar_ham_arsive_sizmiyor(adapter, tmp_path):
    """Anahtar URL parametresinde gider; ham arşivde GÖRÜNMEMELİ."""
    import uuid

    from app.runner import ApiRunner, RunnerConfig

    class _Sahte(ShodanLookupAdapter):
        def calistir(self, hedef, cfg):
            # Gerçek adapter'ın hata yolunu taklit et: httpx istisnası URL'i
            # (ve anahtarı) mesaja koyar.
            import httpx

            hata = httpx.ConnectError(
                f"connection failed to https://api.shodan.io/shodan/host/1.2.3.4"
                f"?key={cfg.env.get('SHODAN_API_KEY')}"
            )
            return RawResult(
                icerik=self._temizle(str(hata), cfg.env.get("SHODAN_API_KEY", "")).encode(),
                format="text",
                cikis_kodu=-1,
            )

    a = _Sahte()
    job_id = uuid.uuid4()
    kosucu = ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))

    import os

    os.environ["SHODAN_API_KEY"] = SAHTE_ANAHTAR
    try:
        sonuc = kosucu.calistir(a, "1.2.3.4", job_id)
    finally:
        os.environ.pop("SHODAN_API_KEY", None)

    arsiv = Path(sonuc.ham_cikti_ref).read_text(encoding="utf-8")
    assert SAHTE_ANAHTAR not in arsiv, "API ANAHTARI HAM ARŞİVDE!"
    assert SAHTE_ANAHTAR not in (sonuc.hata_mesaji or ""), "ANAHTAR HATA MESAJINDA!"
    assert "***" in arsiv


@pytest.mark.parametrize(
    "metin",
    [
        "https://api.shodan.io/shodan/host/1.2.3.4?key=GIZLI123&minify=false",
        "ConnectError: ...?key=GIZLI123",
        "hata: GIZLI123 gecersiz",
    ],
)
def test_temizle_anahtari_siliyor(adapter, metin):
    temiz = adapter._temizle(metin, "GIZLI123")
    assert "GIZLI123" not in temiz
    assert "***" in temiz


def test_temizle_bilinmeyen_anahtari_da_maskeler(adapter):
    """Anahtar elde yoksa bile `key=` parametresi maskelenir."""
    temiz = adapter._temizle("...?key=BASKA_BIR_SEY&x=1", "")
    assert "BASKA_BIR_SEY" not in temiz


def test_meta_url_icermiyor(adapter):
    """`RawResult.meta` job'a ve loga gider; URL oraya konmaz."""
    ham = adapter.calistir("10.0.0.1", ToolConfig(env={"SHODAN_API_KEY": SAHTE_ANAHTAR}))
    assert "url" not in ham.meta
    assert SAHTE_ANAHTAR not in json.dumps(ham.meta)


# --- anahtar YOKKEN davranış ---------------------------------------------- #


def test_anahtar_zorunlu_isaretli(adapter):
    """subfinder'ın opsiyonel anahtarından FARKI budur."""
    assert adapter.spec.auth_gerekli is True
    assert adapter.spec.auth_env == ("SHODAN_API_KEY",)


def test_anahtar_yoksa_skipped(adapter, monkeypatch):
    """Sessizce kaybolmaz: listede kalır, seçilince EKSİĞİN ADIYLA SKIPPED."""
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    engel = anahtar_engeli(adapter.spec)

    assert engel is not None
    assert engel.durum is JobStatus.SKIPPED  # FAILED değil
    assert "SHODAN_API_KEY" in engel.hata_mesaji
    assert "shodan-lookup" in engel.hata_mesaji


def test_anahtar_varsa_engel_yok(adapter, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", SAHTE_ANAHTAR)
    assert anahtar_engeli(adapter.spec) is None


def test_anahtar_bos_string_de_eksik_sayilir(adapter, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "")
    assert anahtar_engeli(adapter.spec) is not None


def test_registryde_gorunmeye_devam_ediyor(monkeypatch):
    """Anahtar yokken bile registry'de KALIR — analist neden çalışmadığını görsün."""
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    r = ToolRegistry(TOOL_KOK)
    assert r.get("shodan-lookup") is not None
    assert "shodan-lookup" in {a.spec.name for a in r.tuketenler(EntityType.IP)}


def test_opsiyonel_anahtarli_tool_engellenmiyor():
    """subfinder anahtarsız da çalışır; `auth_gerekli=False`."""
    a = ToolRegistry(TOOL_KOK).get("subfinder")
    assert a.spec.auth_gerekli is False
    assert anahtar_engeli(a.spec) is None


def test_adapter_anahtarsiz_istek_atmaz(adapter):
    """İkinci savunma: adapter doğrudan çağrılırsa da ağa çıkmaz."""
    ham = adapter.calistir("8.8.8.8", ToolConfig(env={}))
    assert ham.cikis_kodu == 401
    assert b"SHODAN_API_KEY" in ham.icerik


# --------------------------------------------------------------------------- #
# HTTP kodları — retry sınıflandırması
# --------------------------------------------------------------------------- #


def test_401_retry_edilmiyor():
    """Geçersiz anahtar tekrar denemekle düzelmez."""
    assert 401 in KALICI_KODLAR
    assert gecici_mi(401, JobStatus.FAILED) is False


def test_429_retry_ediliyor():
    """Kota doldu — beklersek geçer."""
    assert 429 in GECICI_KODLAR
    assert gecici_mi(429, JobStatus.FAILED) is True


def test_404_bos_sonuc_failed_degil(adapter):
    """IP indekste yok. Hata değil, bilgi."""
    assert adapter.parse(_ham({"error": "No information available for that IP."})) == []


# --------------------------------------------------------------------------- #
# Özel aralıklar
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ip,sebep",
    [
        ("10.0.0.1", "ozel_aralik"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("240.0.0.1", "ayrilmis"),
    ],
)
def test_ozel_ip_sorgulanmaz(adapter, ip, sebep):
    """Kota boşa harcanmaz; adres reddedilmez, yalnızca sorulmaz."""
    ham = adapter.calistir(ip, ToolConfig(env={"SHODAN_API_KEY": SAHTE_ANAHTAR}))
    assert ham.cikis_kodu == 0  # FAILED değil
    assert json.loads(ham.icerik)["atlandi"] == sebep
    assert adapter.parse(ham) == []


# --------------------------------------------------------------------------- #
# SERVICE / TECH / ORG
# --------------------------------------------------------------------------- #


def test_servisler_ve_runs_on(adapter, fixture_ham):
    g = adapter.parse(fixture_ham)
    servisler = _tip(g, EntityType.SERVICE)

    assert {s.deger_ham for s in servisler} == {
        "140.82.121.4:22/tcp",
        "140.82.121.4:80/tcp",
        "140.82.121.4:443/tcp",
    }
    il = servisler[0].iliskiler[0]
    assert il.tip is RelationType.RUNS_ON
    assert il.hedef_tip is EntityType.IP
    assert il.yon == "giden"  # kaynak = servis
    assert il.hedef_deger == "140.82.121.4"


def test_ipv6_servis_kose_parantezli(adapter):
    """§3.7: parantezsiz IPv6 belirsizdir, `runs_on` yanlış IP'ye bağlanır."""
    g = adapter.parse(
        _ham(_host(ip_str="2001:db8::1", data=[{"port": 443, "transport": "tcp"}]))
    )
    (s,) = _tip(g, EntityType.SERVICE)

    assert s.deger_ham == "[2001:db8::1]:443/tcp"
    assert normalize(EntityType.SERVICE, s.deger_ham) == "[2001:db8::1]:443/tcp"


def test_veri_tazeligi_kaydediliyor(adapter, fixture_ham):
    """Altı ay önceki port bilgisi bugün geçerli olmayabilir."""
    for s in _tip(adapter.parse(fixture_ham), EntityType.SERVICE):
        assert "son_gorulme_shodan" in s.nitelikler


def test_tech_ve_uses_tech(adapter):
    g = adapter.parse(
        _ham(
            _host(
                data=[
                    {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24.0"}
                ]
            )
        )
    )
    (t,) = _tip(g, EntityType.TECH)

    assert t.deger_ham == "nginx:nginx:1.24.0"
    assert normalize(EntityType.TECH, t.deger_ham) == "nginx:nginx:1.24.0"
    il = t.iliskiler[0]
    assert il.tip is RelationType.USES_TECH
    assert il.hedef_tip is EntityType.SERVICE
    assert il.yon == "gelen"


def test_surum_yoksa_yildiz(adapter):
    g = adapter.parse(_ham(_host(data=[{"port": 80, "transport": "tcp", "product": "Apache"}])))
    assert _tip(g, EntityType.TECH)[0].deger_ham == "Apache:Apache:*"


def test_urun_yoksa_tech_uydurulmaz(adapter, fixture_ham):
    """Fixture'daki üç serviste de `product` yok — TECH üretilmemeli."""
    assert _tip(adapter.parse(fixture_ham), EntityType.TECH) == []


def test_org_ve_owned_by(adapter, fixture_ham):
    (o,) = _tip(adapter.parse(fixture_ham), EntityType.ORG)

    assert o.deger_ham == "GitHub, Inc."
    assert normalize(EntityType.ORG, o.deger_ham) == "github"
    il = o.iliskiler[0]
    assert il.tip is RelationType.OWNED_BY
    assert il.hedef_tip is EntityType.IP
    assert il.yon == "gelen"


def test_org_yoksa_isp_kullanilir(adapter):
    g = adapter.parse(_ham(_host(org=None, isp="Bir ISP")))
    assert [o.deger_ham for o in _tip(g, EntityType.ORG)] == ["Bir ISP"]


# --------------------------------------------------------------------------- #
# BANNER — güvenilmeyen veri
# --------------------------------------------------------------------------- #


def test_banner_uzunluk_siniri(adapter):
    uzun = "A" * (BANNER_SINIRI * 3)
    g = adapter.parse(_ham(_host(data=[{"port": 80, "transport": "tcp", "data": uzun}])))
    banner = _tip(g, EntityType.SERVICE)[0].nitelikler["banner"]

    assert len(banner) < len(uzun)
    assert banner.endswith("[kirpildi]")


def test_banner_kontrol_karakterleri_temizleniyor(adapter):
    """ANSI kaçışları ve null baytlar JSONB'yi ve log görünümünü bozar."""
    kirli = "SSH-2.0\x00\x1b[31mKIRMIZI\x1b[0m\x07\x08son"
    g = adapter.parse(_ham(_host(data=[{"port": 22, "transport": "tcp", "data": kirli}])))
    banner = _tip(g, EntityType.SERVICE)[0].nitelikler["banner"]

    assert "\x00" not in banner
    assert "\x1b" not in banner
    assert "\x07" not in banner
    assert "SSH-2.0" in banner and "son" in banner


def test_banner_satir_sonlari_korunuyor(adapter):
    """Satır sonu kontrol karakteri değil, anlamlı içeriktir."""
    g = adapter.parse(
        _ham(_host(data=[{"port": 80, "transport": "tcp", "data": "HTTP/1.1 200\r\nServer: x"}]))
    )
    banner = _tip(g, EntityType.SERVICE)[0].nitelikler["banner"]
    assert "\n" in banner


def test_gercek_banner_korunuyor(adapter, fixture_ham):
    """Gerçek SSH banner'ı (1303 karakter) sınır altında, kırpılmamalı."""
    ssh = next(
        s
        for s in _tip(adapter.parse(fixture_ham), EntityType.SERVICE)
        if s.deger_ham.endswith(":22/tcp")
    )
    assert "SSH" in ssh.nitelikler["banner"]
    assert not ssh.nitelikler["banner"].endswith("[kirpildi]")


# --------------------------------------------------------------------------- #
# Bozuk girdi
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "govde", [b"", b"bozuk", b"[1,2]", b'"metin"', b"{}", b'{"data":[]}', b"\xff\xfe"]
)
def test_bozuk_govde_istisna_firlatmaz(adapter, govde):
    assert adapter.parse(_ham(govde)) == []


@pytest.mark.parametrize("port", [0, -1, 70000, "443", None])
def test_gecersiz_port_eleniyor(adapter, port):
    g = adapter.parse(_ham(_host(data=[{"port": port, "transport": "tcp"}])))
    assert _tip(g, EntityType.SERVICE) == []


def test_bozuk_kayit_digerlerini_dusurmez(adapter):
    g = adapter.parse(
        _ham(_host(data=["sozluk degil", {"port": None}, {"port": 443, "transport": "tcp"}]))
    )
    assert len(_tip(g, EntityType.SERVICE)) == 1


# --------------------------------------------------------------------------- #
# Spec ve zincirleme
# --------------------------------------------------------------------------- #


def test_spec(adapter):
    s = adapter.spec
    assert s.passivity is Passivity.P0  # indeks sorgusu, tarama DEĞİL
    assert s.varsayilan_guven == 75  # indeks eski olabilir
    assert s.calistirma == "api"
    assert s.kabul_eder == {EntityType.IP}
    assert s.uretir == {EntityType.SERVICE, EntityType.TECH, EntityType.ORG}
    assert s.dakikalik_istek == 60
    assert s.aylik_kota == 100


def test_zincirleme():
    """dns-resolver IP üretir → shodan-lookup onu tüketir."""
    r = ToolRegistry(TOOL_KOK)
    assert "dns-resolver" in {a.spec.name for a in r.uretenler(EntityType.IP)}
    assert "shodan-lookup" in {a.spec.name for a in r.tuketenler(EntityType.IP)}
    assert "shodan-lookup" in {a.spec.name for a in r.uretenler(EntityType.SERVICE)}


def test_yedi_cekirdek_tool_tamam():
    """v1 çekirdeği 7 tool ile sınırlıdır (docs/kapsam.md Bölüm 3.3)."""
    adlar = {a.spec.name for a in ToolRegistry(TOOL_KOK).hepsi()}
    assert adlar == {
        "subfinder",
        "crtsh",
        "dns-resolver",
        "whois-rdap",
        "asn-bgp",
        "theharvester",
        "shodan-lookup",
    }


# --------------------------------------------------------------------------- #
# Canlı sorgu — YAVAŞ, anahtar varsa
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_gercek_shodan_sorgusu(adapter):
    import os

    anahtar = os.getenv("SHODAN_API_KEY")
    if not anahtar:
        pytest.skip("SHODAN_API_KEY tanımlı değil")

    ham = adapter.calistir("140.82.121.4", ToolConfig(env={"SHODAN_API_KEY": anahtar}))
    if ham.cikis_kodu != 0:
        pytest.skip(f"Shodan erişilemiyor (kod {ham.cikis_kodu})")

    assert anahtar not in ham.icerik.decode("utf-8", errors="replace")
    for g in adapter.parse(ham):
        normalize(g.tip, g.deger_ham)
