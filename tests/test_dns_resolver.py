"""dns-resolver adapter'ı — `parse()` saf, testler ağsız.

Fixture GERÇEK DNS yanıtlarıdır (github.com, 1.1.1.1 üzerinden). dnspython
nesneleri değil, `calistir()`'in ürettiği serileştirilmiş JSON saklanır — bu
sayede `parse()` ağa hiç dokunmadan test edilir.

Fixture'ın kapsadığı gerçek kenar durumlar: BÖLÜNMÜŞ TXT kaydı (255 baytı aşan
SPF iki parçaya ayrılır), 8 NS, 7 CAA, `~all` nitelikli SPF, `p=quarantine`
DMARC.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.normalize import EntityType, normalize
from app.tools._base import (
    Passivity,
    RawResult,
    RelationType,
    ToolRegistry,
)
from app.tools.dns_resolver.adapter import CNAME_AZAMI_HOP, DnsResolverAdapter

TOOL_KOK = Path(__file__).resolve().parents[1] / "app" / "tools"
FIXTURE = TOOL_KOK / "dns_resolver" / "fixtures" / "sample_output.json"


@pytest.fixture
def adapter() -> DnsResolverAdapter:
    return DnsResolverAdapter()


def _ham(veri) -> RawResult:
    if isinstance(veri, (dict, list)):
        veri = json.dumps(veri)
    if isinstance(veri, str):
        veri = veri.encode("utf-8")
    return RawResult(icerik=veri, format="json", cikis_kodu=0)


@pytest.fixture
def fixture_ham() -> RawResult:
    return _ham(FIXTURE.read_bytes())


def _yanit(**kayitlar):
    """Sahte DNS yanıtı kurar. `A=['1.2.3.4']` → durum ok."""
    tam = {
        t: {"durum": "nodata", "veri": []}
        for t in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
    }
    for tip, veri in kayitlar.items():
        tam[tip] = (
            veri if isinstance(veri, dict) else {"durum": "ok", "veri": list(veri)}
        )
    return {"hedef": "firma.com", "resolver": "1.1.1.1", "kayitlar": tam}


def _hedef_gozlemi(gozlemler, hedef="firma.com"):
    return next(
        g
        for g in gozlemler
        if g.tip is EntityType.SUBDOMAIN and g.deger_ham == hedef
    )


# --------------------------------------------------------------------------- #
# Fixture
# --------------------------------------------------------------------------- #


def test_fixture_gercek_dns_yaniti():
    assert FIXTURE.is_file() and FIXTURE.stat().st_size > 0
    d = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert set(d) >= {"hedef", "resolver", "kayitlar", "dmarc", "cname_zinciri"}
    # dnspython nesnesi DEĞİL, metin saklanmalı ki parse saf kalsın
    assert all(isinstance(v, str) for v in d["kayitlar"]["NS"]["veri"])
    # Kenar durum fixture'da GERÇEKTEN var olmalı
    spf = [t for t in d["kayitlar"]["TXT"]["veri"] if "spf1" in t]
    assert spf, "fixture'da SPF yok"
    assert '" "' in spf[0], "bölünmüş TXT kenar durumu fixture'da yok"


def test_parse_fixture_tum_tipleri_uretir(adapter, fixture_ham):
    tipler = {g.tip for g in adapter.parse(fixture_ham)}
    assert EntityType.IP in tipler
    assert EntityType.SUBDOMAIN in tipler
    assert EntityType.TECH in tipler
    assert EntityType.ORG in tipler


def test_uretilen_her_deger_normalize_edilebilir(adapter, fixture_ham):
    """Adapter'ın verdiği hiçbir gözlem ingest'te WARNING'e düşmemeli."""
    for g in adapter.parse(fixture_ham):
        normalize(g.tip, g.deger_ham)


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
# A / AAAA / CNAME
# --------------------------------------------------------------------------- #


def test_a_kaydi_ip_ve_resolves_to(adapter):
    g = adapter.parse(_ham(_yanit(A=["1.2.3.4"], AAAA=["2001:db8::1"])))
    ipler = [x for x in g if x.tip is EntityType.IP]
    assert {x.deger_ham for x in ipler} == {"1.2.3.4", "2001:db8::1"}

    il = ipler[0].iliskiler[0]
    assert il.tip is RelationType.RESOLVES_TO
    # resolves_to = domain/sub -> ip. Gözlem IP olduğu için yön "gelen".
    assert il.yon == "gelen"
    assert il.hedef_deger == "firma.com"


def test_cname_zinciri_ve_iliski(adapter):
    veri = _yanit()
    veri["cname_zinciri"] = ["a.cdn.net", "b.cdn.net"]
    g = adapter.parse(_ham(veri))

    cnameler = [x for x in g if x.nitelikler.get("dns_kayit") == "CNAME"]
    assert [x.deger_ham for x in cnameler] == ["a.cdn.net", "b.cdn.net"]
    # Zincir: firma.com -> a.cdn.net -> b.cdn.net
    assert cnameler[0].iliskiler[0].hedef_deger == "firma.com"
    assert cnameler[1].iliskiler[0].hedef_deger == "a.cdn.net"
    assert cnameler[0].iliskiler[0].tip is RelationType.CNAME_FOR


def test_cname_dongusune_sinir_var():
    """`a -> b -> a` gerçek dünyada olur; sınırsız takip worker'ı kilitler."""
    assert CNAME_AZAMI_HOP > 0

    class _Donguluk:
        def resolve(self, ad, tip):
            raise AssertionError("bu test ağa çıkmamalı")

    a = DnsResolverAdapter()
    cagri = {"n": 0}

    def _sahte(cozumleyici, ad, tip):
        cagri["n"] += 1
        # Her zaman aynı iki adı döndür → döngü
        return {"durum": "ok", "veri": ["b.firma.com" if ad != "b.firma.com" else "firma.com"]}

    a._sorgu = staticmethod(_sahte)
    zincir = a._cname_zinciri(_Donguluk(), "firma.com")
    assert len(zincir) < CNAME_AZAMI_HOP + 2
    assert cagri["n"] <= CNAME_AZAMI_HOP


# --------------------------------------------------------------------------- #
# MX / NS — ilişki YÖNÜ
# --------------------------------------------------------------------------- #


def test_mx_for_yonu(adapter):
    """`mx_for` = sub → domain. Gözlem posta sunucusu, hedef alan adı."""
    g = adapter.parse(_ham(_yanit(MX=["10 mail.firma.com.", "20 yedek.firma.com."])))
    mxler = [x for x in g if x.nitelikler.get("dns_kayit") == "MX"]

    assert {x.deger_ham for x in mxler} == {"mail.firma.com", "yedek.firma.com"}
    il = mxler[0].iliskiler[0]
    assert il.tip is RelationType.MX_FOR
    assert il.yon == "giden"  # kaynak = posta sunucusu
    assert il.hedef_deger == "firma.com"
    assert {x.nitelikler["mx_oncelik"] for x in mxler} == {10, 20}


def test_ns_for_yonu(adapter):
    g = adapter.parse(_ham(_yanit(NS=["ns1.firma.com.", "ns2.firma.com."])))
    nsler = [x for x in g if x.nitelikler.get("dns_kayit") == "NS"]

    assert {x.deger_ham for x in nsler} == {"ns1.firma.com", "ns2.firma.com"}
    il = nsler[0].iliskiler[0]
    assert il.tip is RelationType.NS_FOR
    assert il.yon == "giden"
    assert il.hedef_deger == "firma.com"


def test_ns_saglayicisi_org_olarak(adapter):
    """`ns1.cloudflare.com` → ORG `cloudflare`. Kendi NS'i sağlayıcı değildir."""
    g = adapter.parse(
        _ham(_yanit(NS=["ns1.cloudflare.com.", "ns2.cloudflare.com.", "ns.firma.com."]))
    )
    orglar = [x for x in g if x.tip is EntityType.ORG]

    assert [x.deger_ham for x in orglar] == ["cloudflare"]  # tekilleşti
    assert orglar[0].nitelikler["ns_kok"] == "cloudflare.com"


# --------------------------------------------------------------------------- #
# SPF — ayrıştırma ve zayıflık
# --------------------------------------------------------------------------- #


def test_spf_include_tech_olur(adapter):
    spf = '"v=spf1 include:_spf.google.com include:sendgrid.net ~all"'
    g = adapter.parse(_ham(_yanit(TXT=[spf])))

    techler = {x.deger_ham for x in g if x.tip is EntityType.TECH}
    assert techler == {"spf-include:_spf.google.com", "spf-include:sendgrid.net"}

    n = _hedef_gozlemi(g).nitelikler
    assert n["spf_include"] == ["_spf.google.com", "sendgrid.net"]
    assert n["spf_yok"] is False


@pytest.mark.parametrize(
    "nitelik,zayif",
    [("~all", False), ("-all", False), ("?all", True), ("+all", True)],
)
def test_spf_all_niteligi(adapter, nitelik, zayif):
    """`?all` ve `+all` zayıftır: kimliksiz gönderici reddedilmez."""
    g = adapter.parse(_ham(_yanit(TXT=[f'"v=spf1 ip4:1.2.3.4 {nitelik}"'])))
    n = _hedef_gozlemi(g).nitelikler
    assert n["spf_all"] == nitelik
    assert n["spf_zayif"] is zayif


def test_spf_all_mekanizmasi_hic_yoksa_zayif(adapter):
    g = adapter.parse(_ham(_yanit(TXT=['"v=spf1 ip4:1.2.3.4"'])))
    n = _hedef_gozlemi(g).nitelikler
    assert n["spf_all"] is None
    assert n["spf_zayif"] is True


def test_spf_ip_mekanizmalari_niteliklerde(adapter):
    """ip4/ip6 TECH DEĞİL: teknoloji değil, SPF verisidir."""
    g = adapter.parse(
        _ham(_yanit(TXT=['"v=spf1 ip4:1.2.3.0/24 ip6:2001:db8::/32 -all"']))
    )
    n = _hedef_gozlemi(g).nitelikler
    assert n["spf_ip4"] == ["1.2.3.0/24"]
    assert n["spf_ip6"] == ["2001:db8::/32"]
    assert not [x for x in g if x.tip is EntityType.TECH]


def test_bolunmus_txt_birlestirilir(adapter):
    """255 baytı aşan TXT parçalara ayrılır; parçalar BOŞLUKSUZ birleşir."""
    g = adapter.parse(_ham(_yanit(TXT=['"v=spf1 ip4:62.253.2" "27.114 ~all"'])))
    n = _hedef_gozlemi(g).nitelikler
    assert n["spf_ip4"] == ["62.253.227.114"]
    assert n["spf_all"] == "~all"


def test_spf_yoksa_isaretlenir(adapter):
    """KAYIT YOKLUĞU DA BİLGİDİR — sessizce atlanmaz."""
    g = adapter.parse(_ham(_yanit(TXT=['"google-site-verification=abc"'])))
    n = _hedef_gozlemi(g).nitelikler
    assert n["spf_yok"] is True
    assert "spf_all" not in n


def test_txt_hic_yoksa_spf_yok(adapter):
    n = _hedef_gozlemi(adapter.parse(_ham(_yanit()))).nitelikler
    assert n["spf_yok"] is True


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #


def test_dmarc_politikasi_ayristirilir(adapter):
    veri = _yanit()
    veri["dmarc"] = {
        "durum": "ok",
        "veri": ['"v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:a@firma.com"'],
    }
    n = _hedef_gozlemi(adapter.parse(_ham(veri))).nitelikler

    assert n["dmarc_yok"] is False
    assert n["dmarc_p"] == "quarantine"
    assert n["dmarc_sp"] == "reject"
    assert n["dmarc_pct"] == "100"
    assert n["dmarc_rua"] == "mailto:a@firma.com"
    assert n["dmarc_zayif"] is False


def test_dmarc_p_none_zayif(adapter):
    """`p=none` izleme modudur, koruma sağlamaz."""
    veri = _yanit()
    veri["dmarc"] = {"durum": "ok", "veri": ['"v=DMARC1; p=none"']}
    n = _hedef_gozlemi(adapter.parse(_ham(veri))).nitelikler
    assert n["dmarc_p"] == "none"
    assert n["dmarc_zayif"] is True


def test_dmarc_yoksa_isaretlenir(adapter):
    veri = _yanit()
    veri["dmarc"] = {"durum": "nxdomain", "veri": []}
    n = _hedef_gozlemi(adapter.parse(_ham(veri))).nitelikler
    assert n["dmarc_yok"] is True


def test_dmarc_alt_cizgili_etiket_normalize_ediliyor():
    """`_dmarc.firma.com` normalize'de KORUNMALI — etiket bazlı punycode."""
    assert normalize(EntityType.SUBDOMAIN, "_dmarc.firma.com") == "_dmarc.firma.com"


def test_caa_ve_soa_niteliklerde(adapter):
    g = adapter.parse(
        _ham(_yanit(CAA=['0 issue "letsencrypt.org"'], SOA=["ns1.firma.com. a. 1 2 3 4 5"]))
    )
    n = _hedef_gozlemi(g).nitelikler
    assert n["caa_yok"] is False
    assert n["caa"] == ['0 issue "letsencrypt.org"']
    assert n["soa"].startswith("ns1.firma.com")


def test_caa_yoksa_isaretlenir(adapter):
    assert _hedef_gozlemi(adapter.parse(_ham(_yanit()))).nitelikler["caa_yok"] is True


# --------------------------------------------------------------------------- #
# Hata durumları — NXDOMAIN hata DEĞİL
# --------------------------------------------------------------------------- #


def test_nxdomain_bos_sonuc_failed_degil(adapter):
    """NXDOMAIN 'kayıt yok' demektir; iş başarısız sayılmaz."""
    kayitlar = {
        t: {"durum": "nxdomain", "veri": []}
        for t in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
    }
    assert adapter._cikis_kodu(kayitlar) == 0  # FAILED değil

    g = adapter.parse(_ham({"hedef": "yok.firma.com", "kayitlar": kayitlar}))
    # Varlık gözlemi yine üretilir: "SPF yok, DMARC yok" da bir bulgudur
    assert _hedef_gozlemi(g, "yok.firma.com").nitelikler["spf_yok"] is True
    assert not [x for x in g if x.tip is EntityType.IP]


def test_servfail_gecici_retrye_duser(adapter):
    """SERVFAIL geçicidir; 503 GECICI_KODLAR içindedir."""
    from app.runner import GECICI_KODLAR

    kayitlar = {t: {"durum": "gecici", "veri": []} for t in ("A", "MX")}
    kod = adapter._cikis_kodu(kayitlar)
    assert kod == 503
    assert kod in GECICI_KODLAR


def test_kismi_basari_retrye_dusmez(adapter):
    """Tek kayıt tipi bile geldiyse iş BAŞARILIDIR.

    Aksi hâlde runner turu tekrarlar, ham arşivi üzerine yazar ve elde edilmiş
    gerçek veri kaybolabilir.
    """
    kayitlar = {
        "A": {"durum": "ok", "veri": ["1.2.3.4"]},
        "MX": {"durum": "gecici", "veri": []},
    }
    assert adapter._cikis_kodu(kayitlar) == 0


def test_tek_kayit_patlarsa_digerleri_geliyor(adapter):
    """Kısmi sonuç kayıp değildir."""
    veri = _yanit(A=["1.2.3.4"])
    veri["kayitlar"]["MX"] = {"durum": "hata", "veri": [], "hata": "FormError"}
    veri["kayitlar"]["NS"] = {"durum": "gecici", "veri": []}

    g = adapter.parse(_ham(veri))
    assert [x.deger_ham for x in g if x.tip is EntityType.IP] == ["1.2.3.4"]


@pytest.mark.parametrize(
    "govde",
    [b"", b"bozuk json", b"[1,2,3]", b'{"kayitlar":{}}', b'{"hedef":""}', b"\xff\xfe"],
)
def test_bozuk_govde_istisna_firlatmaz(adapter, govde):
    assert adapter.parse(_ham(govde)) == []


# --------------------------------------------------------------------------- #
# Spec ve registry
# --------------------------------------------------------------------------- #


def test_spec_p1_yetki_istemez(adapter):
    s = adapter.spec
    assert s.passivity is Passivity.P1
    assert s.yetki_ister() is False  # public resolver → P1
    assert s.varsayilan_guven == 85
    assert s.calistirma == "api"
    assert s.image is None


def test_registry_dns_resolveri_buluyor():
    assert ToolRegistry(TOOL_KOK).get("dns-resolver") is not None


def test_iki_katmanli_zincir():
    """DOMAIN → SUBDOMAIN → IP. Elle kural yazılmadan kurulur."""
    r = ToolRegistry(TOOL_KOK)

    # 1. katman: DOMAIN girince subfinder + crtsh + dns-resolver
    domain_tuketen = {a.spec.name for a in r.tuketenler(EntityType.DOMAIN)}
    assert {"subfinder", "crtsh", "dns-resolver"} <= domain_tuketen

    # 2. katman: subfinder SUBDOMAIN üretir → dns-resolver onu tüketir
    assert "subfinder" in {a.spec.name for a in r.uretenler(EntityType.SUBDOMAIN)}
    assert "dns-resolver" in {a.spec.name for a in r.tuketenler(EntityType.SUBDOMAIN)}

    # 3. katman: dns-resolver IP üretir, whois-rdap onu tüketir
    assert "dns-resolver" in {a.spec.name for a in r.uretenler(EntityType.IP)}
    # SABİT SAYI YAZILMAZ: IP tüketen yeni tool (asn-bgp, shodan-lookup)
    # eklendiğinde bu iddia kırılmamalı, yalnızca zincirin varlığı önemli.
    assert r.tuketenler(EntityType.IP), "IP tüketen tool yok — zincir kesik"


def test_dns_resolver_ip_ve_org_uretir():
    r = ToolRegistry(TOOL_KOK)
    assert "dns-resolver" in {a.spec.name for a in r.uretenler(EntityType.IP)}
    # ORG'u whois-rdap da üretir; TEKEL iddiası edilmez.
    assert "dns-resolver" in {a.spec.name for a in r.uretenler(EntityType.ORG)}


# --------------------------------------------------------------------------- #
# Canlı sorgu — YAVAŞ
# --------------------------------------------------------------------------- #


@pytest.mark.slow
def test_gercek_dns_sorgusu(adapter):
    """Gerçek public resolver'a karşı. Fixture'ın kaçırdığı sürprizleri yakalar."""
    from app.tools._base import ToolConfig

    ham = adapter.calistir("github.com", ToolConfig())
    if ham.cikis_kodu != 0:
        pytest.skip(f"DNS erişilemiyor (kod {ham.cikis_kodu})")

    d = json.loads(ham.icerik)
    assert d["resolver"] == "1.1.1.1"
    assert d["kayitlar"]["A"]["durum"] == "ok"

    g = adapter.parse(ham)
    assert [x for x in g if x.tip is EntityType.IP], "hiç IP çıkmadı"
    for x in g:
        normalize(x.tip, x.deger_ham)  # canlı veri normalize edilebilmeli


@pytest.mark.slow
def test_gercek_nxdomain_cokmez(adapter):
    from app.tools._base import ToolConfig

    ham = adapter.calistir("bu-alan-adi-kesinlikle-yok-12345.com", ToolConfig())
    assert ham.cikis_kodu == 0, "NXDOMAIN başarısızlık sayıldı"
    g = adapter.parse(ham)
    assert not [x for x in g if x.tip is EntityType.IP]
