"""asn-bgp adapter'ı — `parse()` saf, testler ağsız.

İki fixture de GERÇEK RIPEstat yanıtıdır:
  `ip_kurumsal.json`  140.82.121.4 → AS36459 GitHub, 26 prefiks (sınırın ALTINDA)
  `asn_bulut.json`    AS24940 Hetzner, 95 prefiks (sınırın ÜSTÜNDE, bulut listesinde)

Sınırın gerekçesi ölçümdür — bu tool yazılırken canlı alınan prefiks sayıları:
GitHub 26, Hetzner 95, Linode 446, DigitalOcean 886, Fastly 1.820,
Akamai 4.725, Cloudflare 5.326 (614 KB).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalize import EntityType, normalize
from app.tools._base import Passivity, RawResult, RelationType, ToolRegistry
from app.tools.asn_bgp.adapter import BULUT_ASN, PREFIX_SINIRI, AsnBgpAdapter

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE_KOK = TOOL_KOK / "asn_bgp" / "fixtures"


@pytest.fixture
def adapter() -> AsnBgpAdapter:
    return AsnBgpAdapter()


def _ham(veri) -> RawResult:
    if isinstance(veri, (dict, list)):
        veri = json.dumps(veri)
    if isinstance(veri, str):
        veri = veri.encode("utf-8")
    return RawResult(icerik=veri, format="json", cikis_kodu=0)


def _fixture(ad: str) -> RawResult:
    return _ham((FIXTURE_KOK / f"{ad}.json").read_bytes())


def _tip(gozlemler, tip):
    return [g for g in gozlemler if g.tip is tip]


def _zarf(asn="64500", sayi=3, holder="TEST - Test Kurumu", prefix="1.2.3.0/24", **ek):
    """Sahte RIPEstat zarfı."""
    z = {
        "hedef": "1.2.3.4",
        "tip": "ip",
        "atlandi": None,
        "network_info": {"prefix": prefix, "asns": [asn]},
        "asn_bilgi": {asn: {"holder": holder}},
        "prefixler": {
            asn: {"sayi": sayi, "liste": [f"10.{i}.0.0/16" for i in range(sayi)]}
        },
    }
    z.update(ek)
    return z


# --------------------------------------------------------------------------- #
# Fixture'lar
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("ad", ["ip_kurumsal", "asn_bulut"])
def test_fixture_gercek_ripestat_yaniti(ad):
    yol = FIXTURE_KOK / f"{ad}.json"
    assert yol.is_file() and yol.stat().st_size > 0
    d = json.loads(yol.read_text(encoding="utf-8"))
    assert {"hedef", "tip", "asn_bilgi", "prefixler"} <= set(d)
    assert d["asn_bilgi"], "ASN bilgisi yok"


def test_uretilen_her_deger_normalize_edilebilir(adapter):
    for ad in ("ip_kurumsal", "asn_bulut"):
        for g in adapter.parse(_fixture(ad)):
            normalize(g.tip, g.deger_ham)


def test_parse_saf_fonksiyon(adapter, monkeypatch):
    import socket

    def _yasak(*a, **k):  # pragma: no cover
        raise AssertionError("parse() ağa çıktı!")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "getaddrinfo", _yasak)

    ham = _fixture("ip_kurumsal")
    assert [(g.tip, g.deger_ham) for g in adapter.parse(ham)] == [
        (g.tip, g.deger_ham) for g in adapter.parse(ham)
    ]


# --------------------------------------------------------------------------- #
# Kurumsal ASN — sınırın altında
# --------------------------------------------------------------------------- #


def test_kurumsal_asn_prefiksleri_yazilir(adapter):
    """26 prefiks sınırın altında: hepsi NETBLOCK olur."""
    g = adapter.parse(_fixture("ip_kurumsal"))

    asn = _tip(g, EntityType.ASN)[0]
    assert asn.deger_ham == "36459"
    assert asn.nitelikler["duyurulan_prefiks_sayisi"] == 26
    assert "prefiks_sinir_asildi" not in asn.nitelikler
    assert "hedefe_ait_degil" not in asn.nitelikler

    bloklar = _tip(g, EntityType.NETBLOCK)
    assert len(bloklar) == 26


def test_asn_normalizasyonu(adapter):
    """'AS13335' → '13335' (normalize.py §3.6)."""
    assert normalize(EntityType.ASN, "AS36459") == "36459"
    asn = _tip(adapter.parse(_fixture("ip_kurumsal")), EntityType.ASN)[0]
    assert normalize(EntityType.ASN, asn.deger_ham) == "36459"


def test_as_sahibi_org_ve_owned_by(adapter):
    g = adapter.parse(_fixture("ip_kurumsal"))
    orglar = _tip(g, EntityType.ORG)

    assert [o.deger_ham for o in orglar] == ["GitHub, Inc."]
    il = orglar[0].iliskiler[0]
    assert il.tip is RelationType.OWNED_BY
    assert il.hedef_tip is EntityType.ASN
    assert il.hedef_deger == "36459"
    assert il.yon == "gelen"  # kaynak ASN, hedef ORG


@pytest.mark.parametrize(
    "holder,beklenen",
    [
        ("GITHUB - GitHub, Inc.", "GitHub, Inc."),
        ("HETZNER-AS Hetzner Online GmbH", "Hetzner Online GmbH"),
        ("CLOUDFLARENET - Cloudflare, Inc.", "Cloudflare, Inc."),
        ("AKAMAI-AS Akamai Technologies", "Akamai Technologies"),
        ("TekBirKelime", "TekBirKelime"),
    ],
)
def test_holder_handle_temizlenir(holder, beklenen):
    """RIPEstat İKİ biçim kullanıyor; handle temizlenmezse ORG tekilleşmez."""
    assert AsnBgpAdapter._holder_kurum(holder) == beklenen


def test_announced_by_yonleri(adapter):
    """ASN gözleminde 'gelen', NETBLOCK gözleminde 'giden'."""
    g = adapter.parse(_fixture("ip_kurumsal"))

    asn = _tip(g, EntityType.ASN)[0]
    il = asn.iliskiler[0]
    assert il.tip is RelationType.ANNOUNCED_BY
    assert il.hedef_tip is EntityType.NETBLOCK
    assert il.yon == "gelen"  # kaynak netblock, hedef asn

    blok = _tip(g, EntityType.NETBLOCK)[0]
    il2 = blok.iliskiler[0]
    assert il2.tip is RelationType.ANNOUNCED_BY
    assert il2.hedef_tip is EntityType.ASN
    assert il2.yon == "giden"  # kaynak = gözlem (netblock)


def test_kapsayan_prefix_yoksa_asn_iliskisiz(adapter):
    """ASN doğrudan sorgulandığında kapsayan blok bilinmez."""
    g = adapter.parse(_fixture("asn_bulut"))
    assert _tip(g, EntityType.ASN)[0].iliskiler == ()


# --------------------------------------------------------------------------- #
# KAPSAM PATLAMASI SINIRI
# --------------------------------------------------------------------------- #


def test_sinir_asilinca_netblock_yazilmaz(adapter):
    """95 prefiks > 50: hiçbiri entity olmaz, sayı niteliklerde kalır."""
    g = adapter.parse(_fixture("asn_bulut"))

    assert _tip(g, EntityType.NETBLOCK) == [], "sınır aşıldı ama blok yazıldı"
    n = _tip(g, EntityType.ASN)[0].nitelikler
    assert n["prefiks_sinir_asildi"] is True
    assert n["duyurulan_prefiks_sayisi"] == 95  # BİLGİ KAYBOLMADI
    assert n["prefiks_siniri"] == PREFIX_SINIRI


def test_sinirin_tam_altinda_yazilir(adapter):
    g = adapter.parse(_ham(_zarf(sayi=PREFIX_SINIRI)))
    assert len(_tip(g, EntityType.NETBLOCK)) == PREFIX_SINIRI
    assert "prefiks_sinir_asildi" not in _tip(g, EntityType.ASN)[0].nitelikler


def test_sinirin_tam_ustunde_yazilmaz(adapter):
    g = adapter.parse(_ham(_zarf(sayi=PREFIX_SINIRI + 1)))
    assert _tip(g, EntityType.NETBLOCK) == []
    assert _tip(g, EntityType.ASN)[0].nitelikler["prefiks_sinir_asildi"] is True


def test_sinir_asan_bilinmeyen_asn_saglayici_isaretlenir(adapter):
    """Listede yok ama binlerce prefiks: büyük olasılıkla sağlayıcı."""
    n = _tip(adapter.parse(_ham(_zarf(asn="64999", sayi=900))), EntityType.ASN)[
        0
    ].nitelikler
    assert n["saglayici_olabilir"] is True
    assert "bulut_saglayici" not in n


# --------------------------------------------------------------------------- #
# Bulut / CDN işaretleme
# --------------------------------------------------------------------------- #


def test_bulut_asn_isaretleniyor(adapter):
    """104.21.x.x Cloudflare'e aittir, MÜŞTERİSİNE değil."""
    n = _tip(adapter.parse(_fixture("asn_bulut")), EntityType.ASN)[0].nitelikler
    assert n["bulut_saglayici"] == "Hetzner"
    assert n["hedefe_ait_degil"] is True


def test_cloudflare_isaretleniyor(adapter):
    n = _tip(adapter.parse(_ham(_zarf(asn="13335", sayi=5326))), EntityType.ASN)[
        0
    ].nitelikler
    assert n["bulut_saglayici"] == "Cloudflare"
    assert n["hedefe_ait_degil"] is True
    assert _tip(adapter.parse(_ham(_zarf(asn="13335", sayi=5326))), EntityType.NETBLOCK) == []


def test_kurumsal_asn_bulut_isareti_almaz(adapter):
    n = _tip(adapter.parse(_fixture("ip_kurumsal")), EntityType.ASN)[0].nitelikler
    assert "bulut_saglayici" not in n
    assert "hedefe_ait_degil" not in n


def test_bulut_listesi_asn_anahtarlari_normalize(adapter):
    """Liste anahtarları `normalize(ASN, ...)` çıktısıyla aynı biçimde olmalı."""
    for asn in BULUT_ASN:
        assert normalize(EntityType.ASN, asn) == asn


# --------------------------------------------------------------------------- #
# Özel/ayrılmış aralıklar
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ip,sebep",
    [
        ("10.0.0.1", "ozel_aralik"),
        ("192.168.1.1", "ozel_aralik"),
        ("172.16.0.1", "ozel_aralik"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link_local"),
        ("224.0.0.1", "multicast"),
        ("240.0.0.1", "ayrilmis"),
        ("fd00::1", "ozel_aralik"),
    ],
)
def test_ozel_aralik_taniniyor(adapter, ip, sebep):
    assert adapter._ozel_mi(ip) == sebep


@pytest.mark.parametrize("ip", ["8.8.8.8", "140.82.121.4", "2606:4700::1111"])
def test_genel_ip_atlanmaz(adapter, ip):
    assert adapter._ozel_mi(ip) is None


def test_ozel_ip_sorgulanmaz_ve_bos_doner(adapter):
    """Sorgu hiç yapılmaz; uydurulacak veri de yok."""
    from app.tools._base import ToolConfig

    ham = adapter.calistir("10.0.0.1", ToolConfig())  # AĞA ÇIKMAZ
    d = json.loads(ham.icerik)

    assert ham.cikis_kodu == 0  # FAILED değil
    assert d["atlandi"] == "ozel_aralik"
    assert "asn_bilgi" not in d
    assert adapter.parse(ham) == []


@pytest.mark.parametrize(
    "hedef,asn", [("AS13335", "13335"), ("13335", "13335"), ("as13335", "13335"), ("1.2.3.4", None)]
)
def test_asn_hedefi_taniniyor(adapter, hedef, asn):
    assert adapter._asn_mi(hedef) == asn


# --------------------------------------------------------------------------- #
# Bozuk girdi
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "govde",
    [b"", b"bozuk", b"[1,2]", b'"metin"', b"{}", b'{"atlandi":"ozel_aralik"}', b"\xff\xfe"],
)
def test_bozuk_govde_istisna_firlatmaz(adapter, govde):
    assert adapter.parse(_ham(govde)) == []


def test_holder_yoksa_org_uydurulmaz(adapter):
    z = _zarf()
    z["asn_bilgi"]["64500"] = {}
    g = adapter.parse(_ham(z))
    assert _tip(g, EntityType.ORG) == []
    assert _tip(g, EntityType.ASN)  # ASN yine yazılır


def test_ripestat_none_dondurunce_cokmez(adapter):
    z = _zarf()
    z["asn_bilgi"]["64500"] = None
    z["prefixler"]["64500"] = None
    g = adapter.parse(_ham(z))
    assert [x.deger_ham for x in _tip(g, EntityType.ASN)] == ["64500"]
    assert _tip(g, EntityType.NETBLOCK) == []


# --------------------------------------------------------------------------- #
# Spec ve zincirleme
# --------------------------------------------------------------------------- #


def test_spec(adapter):
    s = adapter.spec
    assert s.passivity is Passivity.P0
    assert s.yetki_ister() is False
    assert s.varsayilan_guven == 85
    assert s.calistirma == "api"
    assert s.kabul_eder == {EntityType.IP, EntityType.ASN}


def test_registry_asn_bgpyi_buluyor():
    assert ToolRegistry(TOOL_KOK).get("asn-bgp") is not None


def test_dort_katmanli_zincir():
    """DOMAIN → SUBDOMAIN → IP → ASN/NETBLOCK.

    `asn-bgp` `kabul_eder: [IP, ASN]` olduğu için NETBLOCK'tan DEĞİL,
    ASN üzerinden zincirlenir. whois-rdap ikisini de ürettiği için zincir
    yine kurulur.
    """
    r = ToolRegistry(TOOL_KOK)

    # dns-resolver IP üretir → asn-bgp onu tüketir
    assert "dns-resolver" in {a.spec.name for a in r.uretenler(EntityType.IP)}
    assert "asn-bgp" in {a.spec.name for a in r.tuketenler(EntityType.IP)}

    # whois-rdap ASN üretir → asn-bgp onu tüketir
    assert "whois-rdap" in {a.spec.name for a in r.uretenler(EntityType.ASN)}
    assert "asn-bgp" in {a.spec.name for a in r.tuketenler(EntityType.ASN)}

    # asn-bgp'nin ürettiği NETBLOCK'u whois-rdap tüketir → çapraz besleme
    assert "asn-bgp" in {a.spec.name for a in r.uretenler(EntityType.NETBLOCK)}
    assert "whois-rdap" in {a.spec.name for a in r.tuketenler(EntityType.NETBLOCK)}


def test_asn_bgp_netblock_tuketmez():
    """`kabul_eder: [IP, ASN]` — NETBLOCK yok, sonsuz besleme kurulmaz."""
    r = ToolRegistry(TOOL_KOK)
    assert "asn-bgp" not in {a.spec.name for a in r.tuketenler(EntityType.NETBLOCK)}


# --------------------------------------------------------------------------- #
# Canlı sorgu — YAVAŞ
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_gercek_ripestat_ip(adapter):
    from app.tools._base import ToolConfig

    ham = adapter.calistir("140.82.121.4", ToolConfig())
    if ham.cikis_kodu != 0:
        pytest.skip(f"RIPEstat erişilemiyor (kod {ham.cikis_kodu})")

    g = adapter.parse(ham)
    assert _tip(g, EntityType.ASN), "ASN çıkmadı"
    for x in g:
        normalize(x.tip, x.deger_ham)


@pytest.mark.slow
def test_gercek_ripestat_bulut_asn_sinirlaniyor(adapter):
    """Cloudflare gerçekten binlerce prefiks duyuruyor; sınır tutmalı."""
    from app.tools._base import ToolConfig

    ham = adapter.calistir("AS13335", ToolConfig())
    if ham.cikis_kodu != 0:
        pytest.skip(f"RIPEstat erişilemiyor (kod {ham.cikis_kodu})")

    g = adapter.parse(ham)
    n = _tip(g, EntityType.ASN)[0].nitelikler
    assert n["duyurulan_prefiks_sayisi"] > PREFIX_SINIRI
    assert n["bulut_saglayici"] == "Cloudflare"
    assert _tip(g, EntityType.NETBLOCK) == [], "binlerce blok entity'ye çevrildi"
