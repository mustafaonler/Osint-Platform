"""whois-rdap adapter'ı — `parse()` saf, testler ağsız.

Üç fixture de GERÇEK RDAP yanıtıdır:
  `domain_normal.json`   nic.fr    — kayıt sahibi GÖRÜNÜR (AFNIC)
  `domain_redacted.json` sidn.nl   — 'REDACTED FOR PRIVACY'
  `ip_network.json`      140.82.121.4 — ağ bloğu + sahip kurum

Gizlilik korumalı kayıt kenar durum DEĞİL, NORMAL durumdur: GDPR sonrası
gTLD'lerin neredeyse tamamında kayıt sahibi gizlidir (ölçtük: github.com,
iana.org, python.org, wikipedia.org, kernel.org — hepsinde yalnızca registrar).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalize import EntityType, normalize
from app.tools._base import Passivity, RawResult, RelationType, ToolRegistry
from app.tools.whois_rdap.adapter import BITIS_UYARI_GUN, WhoisRdapAdapter

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE_KOK = TOOL_KOK / "whois_rdap" / "fixtures"


@pytest.fixture
def adapter() -> WhoisRdapAdapter:
    return WhoisRdapAdapter()


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


def _hedef_nitelikleri(gozlemler, tip=EntityType.DOMAIN):
    return _tip(gozlemler, tip)[0].nitelikler


def _domain_kaydi(**ek):
    d = {
        "objectClassName": "domain",
        "ldhName": "firma.com",
        "status": ["client transfer prohibited"],
        "events": [],
        "entities": [],
        "nameservers": [],
    }
    d.update(ek)
    return d


def _vcard(rol: str, ad: str, alan: str = "fn"):
    return {
        "roles": [rol],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], [alan, {}, "text", ad]]],
    }


# --------------------------------------------------------------------------- #
# Fixture'lar
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ad,sinif", [("domain_normal", "domain"), ("domain_redacted", "domain"), ("ip_network", "ip network")]
)
def test_fixture_gercek_rdap_yaniti(ad, sinif):
    yol = FIXTURE_KOK / f"{ad}.json"
    assert yol.is_file() and yol.stat().st_size > 0
    d = json.loads(yol.read_text(encoding="utf-8"))
    assert d["objectClassName"] == sinif
    assert "rdapConformance" in d, "gerçek RDAP yanıtı değil"


def test_uretilen_her_deger_normalize_edilebilir(adapter):
    """Hiçbir gözlem ingest'te WARNING'e düşmemeli."""
    for ad in ("domain_normal", "domain_redacted", "ip_network"):
        for g in adapter.parse(_fixture(ad)):
            normalize(g.tip, g.deger_ham)


def test_parse_saf_fonksiyon(adapter, monkeypatch):
    import socket

    def _yasak(*a, **k):  # pragma: no cover
        raise AssertionError("parse() ağa çıktı!")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "getaddrinfo", _yasak)

    ham = _fixture("domain_normal")
    assert [
        (g.tip, g.deger_ham) for g in adapter.parse(ham)
    ] == [(g.tip, g.deger_ham) for g in adapter.parse(ham)]


# --------------------------------------------------------------------------- #
# Gizlilik — ORG UYDURULMAZ
# --------------------------------------------------------------------------- #


def test_gizli_kayitta_org_uydurulmaz(adapter):
    """'REDACTED FOR PRIVACY' bir kurum adı DEĞİLDİR."""
    g = adapter.parse(_fixture("domain_redacted"))

    assert _tip(g, EntityType.ORG) == [], "gizli kayıttan ORG uyduruldu"
    n = _hedef_nitelikleri(g)
    assert n["kayit_sahibi_gizli"] is True
    # Yokluk da bilgidir: ham değer kaydedilir, sessizce atılmaz
    assert "REDACTED" in n["kayit_sahibi_ham"].upper()


@pytest.mark.parametrize(
    "deger",
    [
        "REDACTED FOR PRIVACY",
        "Redacted for privacy",
        "Privacy service provided by Withheld",
        "DATA REDACTED",
        "Not Disclosed",
        "GDPR Masked",
        "Statutory Masking Enabled",
        "   ",
    ],
)
def test_gizlilik_kaliplari_taniniyor(adapter, deger):
    g = adapter.parse(_ham(_domain_kaydi(entities=[_vcard("registrant", deger)])))
    assert _tip(g, EntityType.ORG) == [], f"{deger!r} kurum adı sanıldı"


def test_gercek_kurum_adi_org_olur(adapter):
    g = adapter.parse(_fixture("domain_normal"))
    orglar = _tip(g, EntityType.ORG)

    assert [o.deger_ham for o in orglar] == ["AFNIC"]
    assert _hedef_nitelikleri(g)["kayit_sahibi_gizli"] is False

    il = orglar[0].iliskiler[0]
    assert il.tip is RelationType.OWNED_BY
    assert il.hedef_tip is EntityType.DOMAIN
    # owned_by = domain → org. Gözlem ORG olduğu için yön "gelen".
    assert il.yon == "gelen"
    assert il.hedef_deger == "nic.fr"


def test_registrant_hic_yoksa_isaretlenir(adapter):
    g = adapter.parse(_ham(_domain_kaydi(entities=[_vcard("registrar", "Bir Registrar")])))
    n = _hedef_nitelikleri(g)
    assert n["kayit_sahibi_yok"] is True
    assert _tip(g, EntityType.ORG) == []


def test_registrar_org_entitysi_olmaz(adapter):
    """Registrar kurum adıdır ama hedefin SAHİBİ değildir."""
    g = adapter.parse(
        _ham(_domain_kaydi(entities=[_vcard("registrar", "GoDaddy.com, LLC")]))
    )
    assert _tip(g, EntityType.ORG) == []
    assert _hedef_nitelikleri(g)["registrar"] == "GoDaddy.com, LLC"


def test_org_alani_fn_yerine_yeglenir(adapter):
    """`fn` kişi adı olabilir; `org` kurumdur."""
    e = {
        "roles": ["registrant"],
        "vcardArray": [
            "vcard",
            [["fn", {}, "text", "Ahmet Yilmaz"], ["org", {}, "text", "ABC Teknoloji"]],
        ],
    }
    g = adapter.parse(_ham(_domain_kaydi(entities=[e])))
    assert [o.deger_ham for o in _tip(g, EntityType.ORG)] == ["ABC Teknoloji"]


# --------------------------------------------------------------------------- #
# Tarihler ve durum kodları
# --------------------------------------------------------------------------- #


def test_tarihler_ve_durum_kodlari(adapter):
    n = _hedef_nitelikleri(adapter.parse(_fixture("domain_normal")))
    assert n["olusturma"].startswith("19") or n["olusturma"].startswith("20")
    assert "bitis" in n
    assert isinstance(n["rdap_durum"], list) and n["rdap_durum"]


def test_bitis_yakinsa_isaretlenir(adapter):
    """Süresi dolan domain devralınabilir — Hafta 6 skorlayacak."""
    d = _domain_kaydi(
        events=[
            {"eventAction": "expiration", "eventDate": "2026-03-01T00:00:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-02-01T00:00:00Z"},
        ]
    )
    n = _hedef_nitelikleri(adapter.parse(_ham(d)))
    assert n["bitise_kalan_gun"] == 28
    assert n["bitis_yakin"] is True


def test_bitis_uzaksa_isaretlenmez(adapter):
    d = _domain_kaydi(
        events=[
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-01-01T00:00:00Z"},
        ]
    )
    n = _hedef_nitelikleri(adapter.parse(_ham(d)))
    assert n["bitise_kalan_gun"] > BITIS_UYARI_GUN
    assert n["bitis_yakin"] is False


def test_referans_tarih_yoksa_uyari_konmaz(adapter):
    """`parse()` SAF: 'bugün' okunmaz, referans yoksa hüküm verilmez."""
    d = _domain_kaydi(events=[{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}])
    n = _hedef_nitelikleri(adapter.parse(_ham(d)))
    assert n["bitis"] == "2030-01-01T00:00:00Z"
    assert "bitis_yakin" not in n


def test_bozuk_tarih_cokmez(adapter):
    d = _domain_kaydi(
        events=[
            {"eventAction": "expiration", "eventDate": "tarih degil"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-01-01T00:00:00Z"},
        ]
    )
    n = _hedef_nitelikleri(adapter.parse(_ham(d)))
    assert "bitis_yakin" not in n


# --------------------------------------------------------------------------- #
# Nameserver'lar
# --------------------------------------------------------------------------- #


def test_nameserverlar_subdomain_ve_ns_for(adapter):
    g = adapter.parse(_fixture("domain_normal"))
    nsler = [x for x in _tip(g, EntityType.SUBDOMAIN) if x.nitelikler.get("rol") == "nameserver"]

    assert nsler, "nameserver çıkmadı"
    il = nsler[0].iliskiler[0]
    assert il.tip is RelationType.NS_FOR
    assert il.hedef_tip is EntityType.DOMAIN
    # ns_for = sub → domain. Gözlem isim sunucusu: yön "giden".
    assert il.yon == "giden"
    assert il.hedef_deger == "nic.fr"


def test_nameserver_sondaki_nokta_atilir(adapter):
    d = _domain_kaydi(nameservers=[{"ldhName": "ns1.firma.com."}])
    g = adapter.parse(_ham(d))
    assert [x.deger_ham for x in _tip(g, EntityType.SUBDOMAIN)] == ["ns1.firma.com"]


# --------------------------------------------------------------------------- #
# IP / NETBLOCK / ASN
# --------------------------------------------------------------------------- #


def test_ip_agi_netblock_uretir(adapter):
    g = adapter.parse(_fixture("ip_network"))
    bloklar = _tip(g, EntityType.NETBLOCK)

    assert [b.deger_ham for b in bloklar] == ["140.82.112.0/20"]
    assert bloklar[0].nitelikler["rdap_name"] == "GITHU"


def test_ip_sahibi_org_ve_owned_by(adapter):
    g = adapter.parse(_fixture("ip_network"))
    orglar = _tip(g, EntityType.ORG)

    assert [o.deger_ham for o in orglar] == ["GitHub, Inc."]
    il = orglar[0].iliskiler[0]
    assert il.tip is RelationType.OWNED_BY
    assert il.hedef_tip is EntityType.NETBLOCK
    assert il.hedef_deger == "140.82.112.0/20"


def test_org_normalizasyonu_hukuki_eki_atar():
    """§3.8 kuralı: 'GitHub, Inc.' → 'github'."""
    assert normalize(EntityType.ORG, "GitHub, Inc.") == "github"


def test_in_netblock_iliskisi(adapter):
    """`in_netblock` = ip → netblock. Sorgulanan adres zarftan gelir.

    RDAP yanıtı SORGUYU geri döndürmez; `calistir()` hedefi zarfla birlikte
    arşivler, yoksa bu ilişki hiç kurulamazdı.
    """
    zarf = {
        "hedef": "140.82.121.4",
        "yol": "ip",
        "yanit": json.loads((FIXTURE_KOK / "ip_network.json").read_text(encoding="utf-8")),
    }
    bloklar = _tip(adapter.parse(_ham(zarf)), EntityType.NETBLOCK)

    assert bloklar
    il = bloklar[0].iliskiler[0]
    assert il.tip is RelationType.IN_NETBLOCK
    assert il.hedef_tip is EntityType.IP
    assert il.hedef_deger == "140.82.121.4"
    assert il.yon == "gelen"  # kaynak IP, hedef blok


def test_netblock_hedefinde_in_netblock_kurulmaz(adapter):
    """Bir bloğun kendi içinde olması anlamsız; `ck_rel_self`'e çarpardı."""
    zarf = {
        "hedef": "140.82.112.0/20",
        "yol": "ip",
        "yanit": json.loads((FIXTURE_KOK / "ip_network.json").read_text(encoding="utf-8")),
    }
    bloklar = _tip(adapter.parse(_ham(zarf)), EntityType.NETBLOCK)
    assert bloklar[0].iliskiler == ()


def test_hedef_bilinmiyorsa_in_netblock_yok(adapter):
    """Çıplak RDAP yanıtı (zarfsız) — hedef yok, ilişki uydurulmaz."""
    bloklar = _tip(adapter.parse(_fixture("ip_network")), EntityType.NETBLOCK)
    assert bloklar[0].iliskiler == ()


def test_zarf_ve_ciplak_bicim_ikisi_de_calisir(adapter):
    """Fixture'lar çıplak RDAP; canlı akış zarflı. İkisi de ayrıştırılmalı."""
    ciplak = adapter.parse(_fixture("domain_normal"))
    zarfli = adapter.parse(
        _ham(
            {
                "hedef": "nic.fr",
                "yol": "domain",
                "yanit": json.loads(
                    (FIXTURE_KOK / "domain_normal.json").read_text(encoding="utf-8")
                ),
            }
        )
    )
    assert [(g.tip, g.deger_ham) for g in ciplak] == [
        (g.tip, g.deger_ham) for g in zarfli
    ]


def test_asn_varsa_announced_by(adapter):
    """RDAP IP sorgusu ASN'i GENELDE vermez; verirse alınır."""
    d = {
        "objectClassName": "ip network",
        "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
        "arin_originas0_originautnums": [15169],
        "entities": [],
    }
    g = adapter.parse(_ham(d))
    asnler = _tip(g, EntityType.ASN)

    assert [a.deger_ham for a in asnler] == ["15169"]
    il = asnler[0].iliskiler[0]
    assert il.tip is RelationType.ANNOUNCED_BY
    assert il.hedef_tip is EntityType.NETBLOCK
    assert il.yon == "gelen"  # announced_by = netblock → asn


def test_asn_yoksa_uydurulmaz(adapter):
    """Ölçtük: ARIN'in bu alanı çoğu zaman boş döner."""
    g = adapter.parse(_fixture("ip_network"))
    assert _tip(g, EntityType.ASN) == []


def test_cidr_yoksa_netblock_uydurulmaz(adapter):
    """Aralıktan CIDR hesaplamak `parse()`'a ağ matematiği sokardı."""
    d = {
        "objectClassName": "ip network",
        "startAddress": "1.2.3.0",
        "endAddress": "1.2.3.255",
        "entities": [],
    }
    assert _tip(adapter.parse(_ham(d)), EntityType.NETBLOCK) == []


# --------------------------------------------------------------------------- #
# 404 ve bozuk girdi
# --------------------------------------------------------------------------- #


def test_404_bos_sonuc_failed_degil(adapter):
    """404 = kayıt bulunamadı. İş başarısız sayılmaz."""
    govde = _ham({"errorCode": 404, "title": "Not Found"})
    assert adapter.parse(govde) == []


@pytest.mark.parametrize(
    "govde",
    [b"", b"bozuk json", b"[1,2,3]", b'"metin"', b"{}", b'{"objectClassName":"autnum"}', b"\xff\xfe"],
)
def test_bozuk_govde_istisna_firlatmaz(adapter, govde):
    assert adapter.parse(_ham(govde)) == []


def test_ldhname_yoksa_bos(adapter):
    assert adapter.parse(_ham({"objectClassName": "domain", "entities": []})) == []


def test_bozuk_entity_digerlerini_dusurmez(adapter):
    d = _domain_kaydi(
        entities=["sozluk degil", {"roles": None}, _vcard("registrant", "ABC Teknoloji")]
    )
    assert [o.deger_ham for o in _tip(adapter.parse(_ham(d)), EntityType.ORG)] == [
        "ABC Teknoloji"
    ]


# --------------------------------------------------------------------------- #
# Hedef tipi ayrımı
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "hedef,ip_mi",
    [
        ("firma.com", False),
        ("a.firma.com", False),
        ("1.2.3.4", True),
        ("10.0.0.0/8", True),
        ("2001:db8::1", True),
        ("[2001:db8::1]", True),
    ],
)
def test_hedef_tipi_dogru_yola_gider(adapter, hedef, ip_mi):
    assert adapter._ip_gibi(hedef) is ip_mi


# --------------------------------------------------------------------------- #
# Spec ve zincirleme
# --------------------------------------------------------------------------- #


def test_spec_p0_otoriter(adapter):
    s = adapter.spec
    assert s.passivity is Passivity.P0
    assert s.yetki_ister() is False
    assert s.varsayilan_guven == 90
    assert s.calistirma == "api"
    assert s.dakikalik_istek == 10  # muhafazakâr: rdap.org 429 verir


def test_registry_whois_rdapi_buluyor():
    assert ToolRegistry(TOOL_KOK).get("whois-rdap") is not None


def test_uc_katmanli_zincir():
    """DOMAIN → SUBDOMAIN → IP → NETBLOCK/ORG."""
    r = ToolRegistry(TOOL_KOK)

    assert "dns-resolver" in {a.spec.name for a in r.tuketenler(EntityType.SUBDOMAIN)}
    # dns-resolver IP üretir → whois-rdap onu TÜKETİR (üçüncü katman açıldı)
    assert "dns-resolver" in {a.spec.name for a in r.uretenler(EntityType.IP)}
    assert "whois-rdap" in {a.spec.name for a in r.tuketenler(EntityType.IP)}
    # whois-rdap NETBLOCK üretir ve NETBLOCK'u da tüketir
    assert "whois-rdap" in {a.spec.name for a in r.uretenler(EntityType.NETBLOCK)}
    assert "whois-rdap" in {a.spec.name for a in r.tuketenler(EntityType.NETBLOCK)}


# --------------------------------------------------------------------------- #
# Canlı sorgu — YAVAŞ
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_gercek_rdap_domain(adapter):
    from app.tools._base import ToolConfig

    ham = adapter.calistir("github.com", ToolConfig())
    if ham.cikis_kodu != 0:
        pytest.skip(f"rdap.org erişilemiyor (kod {ham.cikis_kodu})")

    g = adapter.parse(ham)
    assert _tip(g, EntityType.DOMAIN), "hedef gözlemi yok"
    for x in g:
        normalize(x.tip, x.deger_ham)


@pytest.mark.slow
def test_gercek_rdap_404_cokmez(adapter):
    from app.tools._base import ToolConfig

    ham = adapter.calistir("bu-alan-adi-kesinlikle-yok-98765.com", ToolConfig())
    assert ham.cikis_kodu == 0, "404 başarısızlık sayıldı"
    assert adapter.parse(ham) == []
