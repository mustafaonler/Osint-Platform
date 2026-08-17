"""`docs/veri-modeli.md` Bölüm 3.10 — projedeki en yüksek öncelikli test seti.

Buradaki bir hata tüm veritabanını sessizce bozar: yanlış `deger_norm` demek,
dedup'ın çalışmaması ve aynı varlığın iki satır olarak yaşaması demektir.
"""

from __future__ import annotations

import pytest

from app.normalize import (
    EntityType,
    NormalizeError,
    domain_mi,
    gecerli_mi,
    kok_domain,
    normalize,
    service_parcala,
)

# --------------------------------------------------------------------------- #
# 1) Doğru dönüşümler — her varlık tipi için en az bir vaka
#    (Bölüm 3.10'daki parametrik test + genişletme)
# --------------------------------------------------------------------------- #

DOGRU_VAKALAR = [
    # --- Bölüm 3.10'un orijinal seti ---------------------------------------
    (EntityType.SUBDOMAIN, "WWW.Firma.COM.", "www.firma.com"),
    (EntityType.SUBDOMAIN, "https://a.firma.com:8443/x", "a.firma.com"),
    # DÜZELTME: doküman v1.0'da 'xn--irket-bua.com.tr' yazıyordu, yanlıştı.
    # "şirket".encode("idna") == b"xn--irket-idb"
    (EntityType.DOMAIN, "şirket.com.tr", "xn--irket-idb.com.tr"),
    (EntityType.IP, "2001:0DB8:0000::1", "2001:db8::1"),
    (EntityType.NETBLOCK, "10.0.0.5/24", "10.0.0.0/24"),
    (EntityType.EMAIL, "Ahmet+spam@Firma.COM", "ahmet@firma.com"),
    (EntityType.ASN, "AS13335", "13335"),
    # --- DOMAIN / SUBDOMAIN (Bölüm 3.1) ------------------------------------
    (EntityType.DOMAIN, "  firma.com  ", "firma.com"),
    (EntityType.DOMAIN, "https://firma.com/a?b=1", "firma.com"),
    (EntityType.DOMAIN, "firma.com:443", "firma.com"),
    (EntityType.DOMAIN, "user@firma.com", "firma.com"),
    (EntityType.DOMAIN, "user:parola@firma.com/yol", "firma.com"),
    (EntityType.DOMAIN, "firma.com.", "firma.com"),
    (EntityType.SUBDOMAIN, "WWW.Firma.COM", "www.firma.com"),
    # 'www' ASLA atılmaz — ayrı bir subdomain'dir, farklı sunucuya çözülebilir.
    (EntityType.SUBDOMAIN, "www.firma.com", "www.firma.com"),
    # Wildcard temizlenir (wildcard bilgisi nitelikler'de taşınır, anahtarda değil)
    (EntityType.DOMAIN, "*.firma.com", "firma.com"),
    (EntityType.SUBDOMAIN, "*.api.firma.com", "api.firma.com"),
    # Alt çizgili etiket: IDNA'da patlar, etiket bazlı dönüşüm bunu kurtarır
    (EntityType.SUBDOMAIN, "_dmarc.firma.com", "_dmarc.firma.com"),
    (EntityType.SUBDOMAIN, "_dmarc.ŞİRKET.com", "_dmarc.xn--irket-idb.com"),
    # Türkçe: "İ".lower() birleşik aksan (i + U+0307) üretir; anahtarda istenmez
    (EntityType.SUBDOMAIN, "İSTANBUL.firma.com", "istanbul.firma.com"),
    (EntityType.SUBDOMAIN, "IstanbuL.Firma.Com", "istanbul.firma.com"),
    # PSL: çok etiketli son ek
    (EntityType.SUBDOMAIN, "MAIL.Firma.COM.TR.", "mail.firma.com.tr"),
    (EntityType.DOMAIN, "firma.co.uk", "firma.co.uk"),
    # --- IP (Bölüm 3.2) -----------------------------------------------------
    (EntityType.IP, " 1.2.3.4 ", "1.2.3.4"),
    (EntityType.IP, "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    (EntityType.IP, "[2001:DB8::1]", "2001:db8::1"),
    # IPv6'da port ayırırken ':' saymak yetmez — köşeli parantezli form
    (EntityType.IP, "[::1]:443", "::1"),
    (EntityType.IP, "1.2.3.4:8080", "1.2.3.4"),
    # Özel/ayrılmış aralık REDDEDİLMEZ (iç ağ sızıntısı tespiti için değerli)
    (EntityType.IP, "10.0.0.1", "10.0.0.1"),
    (EntityType.IP, "127.0.0.1", "127.0.0.1"),
    # --- NETBLOCK (Bölüm 3.3) ----------------------------------------------
    (EntityType.NETBLOCK, "192.168.1.77/24", "192.168.1.0/24"),
    (EntityType.NETBLOCK, "1.2.3.4/32", "1.2.3.4/32"),
    (EntityType.NETBLOCK, "2001:0DB8:0:0::5/64", "2001:db8::/64"),
    # --- EMAIL (Bölüm 3.4) --------------------------------------------------
    (EntityType.EMAIL, "A@Firma.COM", "a@firma.com"),
    (EntityType.EMAIL, "Ahmet@firma.com", "ahmet@firma.com"),
    (EntityType.EMAIL, "ahmet+test@firma.com", "ahmet@firma.com"),
    (EntityType.EMAIL, "AHMET@ŞİRKET.com.tr", "ahmet@xn--irket-idb.com.tr"),
    (EntityType.EMAIL, "  info@firma.com  ", "info@firma.com"),
    # --- CERT (Bölüm 3.5) ---------------------------------------------------
    (EntityType.CERT, "AB" * 32, "ab" * 32),
    (EntityType.CERT, ":".join(["AB"] * 32), "ab" * 32),
    # --- ASN (Bölüm 3.6) ----------------------------------------------------
    (EntityType.ASN, "as13335", "13335"),
    (EntityType.ASN, " AS 13335 ", "13335"),
    (EntityType.ASN, "13335", "13335"),
    (EntityType.ASN, "AS0009", "9"),
    # --- SERVICE (Bölüm 3.7) ------------------------------------------------
    (EntityType.SERVICE, "1.2.3.4:443/TCP", "1.2.3.4:443/tcp"),
    (EntityType.SERVICE, " 1.2.3.4:80/tcp ", "1.2.3.4:80/tcp"),
    (EntityType.SERVICE, "1.2.3.4:53/udp", "1.2.3.4:53/udp"),
    # IPv6'da köşeli parantez ZORUNLU ve anahtarda KORUNUR (RFC 3986)
    (EntityType.SERVICE, "[2001:0DB8::1]:443/tcp", "[2001:db8::1]:443/tcp"),
    (EntityType.SERVICE, "[::1]:80", "[::1]:80/tcp"),
    (EntityType.SERVICE, "[2001:db8:0:0:0:0:0:1]:8443/TCP", "[2001:db8::1]:8443/tcp"),
    # Protokol yoksa 'tcp' varsayılır — kaydı kaybetmek tahmin etmekten pahalıdır
    (EntityType.SERVICE, "1.2.3.4:80", "1.2.3.4:80/tcp"),
    (EntityType.SERVICE, " 1.2.3.4:443 ", "1.2.3.4:443/tcp"),
    (EntityType.SERVICE, "[2001:0DB8::1]:443", "[2001:db8::1]:443/tcp"),
    # --- ORG (Bölüm 3.8) ----------------------------------------------------
    (EntityType.ORG, "ABC   Teknoloji  A.Ş.", "abc teknoloji"),
    (EntityType.ORG, "ABC Teknoloji Ltd. Şti.", "abc teknoloji"),
    (EntityType.ORG, "Acme Inc.", "acme"),
    (EntityType.ORG, "Acme LLC", "acme"),
    (EntityType.ORG, "Beispiel GmbH", "beispiel"),
    (EntityType.ORG, "Voorbeeld B.V.", "voorbeeld"),
    (EntityType.ORG, "Örnek A.Ş.", "örnek"),
    # --- TECH (Bölüm 3.9) ---------------------------------------------------
    (EntityType.TECH, "nginx:nginx:1.24.0", "nginx:nginx:1.24.0"),
    (EntityType.TECH, "Nginx:Nginx", "nginx:nginx:*"),
    (EntityType.TECH, "nginx", "nginx:nginx:*"),
    (EntityType.TECH, "Apache:HTTP Server:2.4.58", "apache:http server:2.4.58"),
]


@pytest.mark.parametrize("tip,ham,beklenen", DOGRU_VAKALAR)
def test_normalize(tip, ham, beklenen):
    assert normalize(tip, ham) == beklenen


def test_her_varlik_tipi_kapsandi():
    """Kabul kriteri: normalize() 10 varlık tipinin tamamını kapsıyor."""
    kapsanan = {tip for tip, _, _ in DOGRU_VAKALAR}
    assert kapsanan == set(EntityType)
    assert len(EntityType) == 10


# --------------------------------------------------------------------------- #
# 2) İDEMPOTENSİ — normalize(normalize(x)) == normalize(x)
#    Bu bozulursa ikinci kez ingest edilen aynı değer YENİ satır açar.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tip,ham,beklenen", DOGRU_VAKALAR)
def test_idempotens(tip, ham, beklenen):
    bir = normalize(tip, ham)
    iki = normalize(tip, bir)
    assert iki == bir
    assert normalize(tip, iki) == bir


@pytest.mark.parametrize("tip,ham,beklenen", DOGRU_VAKALAR)
def test_normalize_ciktisi_gecerli(tip, ham, beklenen):
    """`gecerli_mi` kanonik biçim denetçisidir: kendi çıktımızı reddetmemeli."""
    assert gecerli_mi(tip, normalize(tip, ham)) is True


# --------------------------------------------------------------------------- #
# 3) Farklı yazımlar TEK anahtara düşer — dedup'ın kalbi
# --------------------------------------------------------------------------- #

TEK_ANAHTAR_KUMELERI = [
    (
        EntityType.SUBDOMAIN,
        [
            "API.Firma.com",
            "api.firma.com.",
            "https://api.firma.com/v1",
            "api.firma.com:8080",
            "  api.firma.com  ",
            "http://user:pw@API.FIRMA.COM:80/x?y=1#z",
            "*.api.firma.com",
            "API.FIRMA.COM.",
        ],
        "api.firma.com",
    ),
    (
        EntityType.IP,
        ["2001:0DB8:0000::1", "2001:db8::1", "[2001:db8:0:0:0:0:0:1]", "2001:DB8::1"],
        "2001:db8::1",
    ),
    (
        EntityType.NETBLOCK,
        ["10.0.0.5/24", "10.0.0.0/24", "10.0.0.255/24"],
        "10.0.0.0/24",
    ),
    (
        EntityType.EMAIL,
        [
            "Ahmet+spam@Firma.COM",
            "ahmet@firma.com",
            "AHMET+x+y@FIRMA.com",
            "mailto:Ahmet@Firma.Com",
        ],
        "ahmet@firma.com",
    ),
    (EntityType.ASN, ["AS13335", "as13335", "13335", " AS 13335 "], "13335"),
    (
        EntityType.ORG,
        ["ABC Teknoloji A.Ş.", "abc   teknoloji", "ABC Teknoloji"],
        "abc teknoloji",
    ),
    (
        EntityType.SERVICE,
        ["1.2.3.4:443/tcp", " 1.2.3.4:443/TCP ", "1.2.3.4:443"],
        "1.2.3.4:443/tcp",
    ),
    (
        EntityType.SERVICE,
        ["[2001:0DB8::1]:443/tcp", "[2001:db8:0:0::1]:443", "[2001:DB8::1]:443/TCP"],
        "[2001:db8::1]:443/tcp",
    ),
    (EntityType.CERT, ["AB" * 32, "ab" * 32, ":".join(["Ab"] * 32)], "ab" * 32),
    (EntityType.TECH, ["nginx", "NGINX:nginx", "nginx:NGINX:*"], "nginx:nginx:*"),
]


@pytest.mark.parametrize("tip,yazimlar,beklenen", TEK_ANAHTAR_KUMELERI)
def test_farkli_yazimlar_tek_anahtara_duser(tip, yazimlar, beklenen):
    anahtarlar = {normalize(tip, y) for y in yazimlar}
    assert anahtarlar == {beklenen}, f"dedup kırık: {anahtarlar}"


def test_ipv6_service_cakismasi_yok():
    """'2001:db8::1:443' kendisi de geçerli bir IPv6 adresidir.

    Parantezsiz biçimde "IP 2001:db8::1 port 443" ile "IP 2001:db8::1:443"
    aynı anahtara çakışırdı ve RUNS_ON YANLIŞ IP entity'sine bağlanırdı.
    Köşeli parantez adres sınırını anahtarda işaretler.
    """
    a = normalize(EntityType.SERVICE, "[2001:db8::1]:443/tcp")
    b = normalize(EntityType.SERVICE, "[2001:db8::1:443]:443/tcp")
    assert a == "[2001:db8::1]:443/tcp"
    assert b == "[2001:db8::1:443]:443/tcp"
    assert a != b

    # Her iki servisin IP'si de farklı bir IP entity'sine çözülür
    assert service_parcala(a)[0] == normalize(EntityType.IP, "2001:db8::1")
    assert service_parcala(b)[0] == normalize(EntityType.IP, "2001:db8::1:443")
    assert service_parcala(a)[0] != service_parcala(b)[0]

    # Çakışmanın kaynağı olan parantezsiz biçim artık hiç kabul edilmiyor
    with pytest.raises(NormalizeError):
        normalize(EntityType.SERVICE, "2001:db8::1:443/tcp")


@pytest.mark.parametrize(
    "norm,beklenen",
    [
        ("1.2.3.4:443/tcp", ("1.2.3.4", 443, "tcp")),
        ("[2001:db8::1]:443/tcp", ("2001:db8::1", 443, "tcp")),
        ("[::1]:80/tcp", ("::1", 80, "tcp")),
        ("1.2.3.4:53/udp", ("1.2.3.4", 53, "udp")),
    ],
)
def test_service_parcala(norm, beklenen):
    """Ingest, RUNS_ON hedefini bu üçlüden çözer."""
    assert service_parcala(norm) == beklenen
    ip, port, proto = service_parcala(norm)
    # Dönen IP, IP tipi için de kanoniktir → doğrudan entity anahtarı olur
    assert gecerli_mi(EntityType.IP, ip)
    # Tam tur: parçala → yeniden kur → aynı anahtar
    ipv6 = ":" in ip
    yeniden = f"[{ip}]:{port}/{proto}" if ipv6 else f"{ip}:{port}/{proto}"
    assert normalize(EntityType.SERVICE, yeniden) == norm


@pytest.mark.parametrize(
    "bozuk",
    [
        "2001:db8::1:443/tcp",  # parantezsiz IPv6
        "1.2.3.4:443",  # protokolsüz → kanonik değil
        "1.2.3.4:443/TCP",  # büyük harf → kanonik değil
        "firma.com:443/tcp",
        "",
    ],
)
def test_service_parcala_kanonik_olmayani_reddeder(bozuk):
    with pytest.raises(NormalizeError):
        service_parcala(bozuk)


def test_www_asla_atilmaz():
    """`www.firma.com` ayrı bir subdomain'dir; atmak veri kaybıdır."""
    assert normalize(EntityType.SUBDOMAIN, "www.firma.com") != normalize(
        EntityType.DOMAIN, "firma.com"
    )
    assert normalize(EntityType.SUBDOMAIN, "WWW.FIRMA.COM") == "www.firma.com"


def test_turkce_buyuk_i_birlesik_aksan_uretmez():
    """'İ'.lower() → 'i' + U+0307. Eşleştirme anahtarında bu KABUL EDİLEMEZ."""
    norm = normalize(EntityType.SUBDOMAIN, "İstanbul.firma.com")
    assert "̇" not in norm
    assert norm == "istanbul.firma.com"
    assert norm == normalize(EntityType.SUBDOMAIN, "istanbul.firma.com")


def test_alt_cizgili_etiket_idna_patlatmaz():
    """'_dmarc' ASCII'dir; IDNA'ya sokulmaz, olduğu gibi bırakılır."""
    assert normalize(EntityType.SUBDOMAIN, "_dmarc.firma.com") == "_dmarc.firma.com"
    assert (
        normalize(EntityType.SUBDOMAIN, "_dkim._domainkey.firma.com")
        == "_dkim._domainkey.firma.com"
    )


# --------------------------------------------------------------------------- #
# 4) Hatalı girdiler → NormalizeError
# --------------------------------------------------------------------------- #

HATALI_VAKALAR = [
    (EntityType.DOMAIN, ""),
    (EntityType.DOMAIN, "   "),
    (EntityType.DOMAIN, "localhost"),  # PSL'de karşılığı yok
    (EntityType.DOMAIN, "firma.gecersiztld"),
    (EntityType.DOMAIN, "firma..com"),
    (EntityType.DOMAIN, "*"),
    (EntityType.DOMAIN, "fir ma.com"),
    (EntityType.DOMAIN, "https:///yol"),
    (EntityType.SUBDOMAIN, "a" * 64 + ".firma.com"),  # etiket > 63
    (EntityType.SUBDOMAIN, "[::1"),  # kapanmayan parantez
    (EntityType.IP, "999.999.999.999"),
    (EntityType.IP, "firma.com"),
    (EntityType.IP, ""),
    (EntityType.IP, "1.2.3.4/24"),
    (EntityType.NETBLOCK, "10.0.0.0/33"),
    (EntityType.NETBLOCK, "abc"),
    (EntityType.NETBLOCK, ""),
    (EntityType.EMAIL, "firma.com"),  # '@' yok
    (EntityType.EMAIL, "@firma.com"),
    (EntityType.EMAIL, "ahmet@"),
    (EntityType.EMAIL, "+tag@firma.com"),  # plus-tag sonrası local boş
    (EntityType.EMAIL, "ah met@firma.com"),
    (EntityType.EMAIL, "ahmet@localhost"),
    (EntityType.ASN, "ASxyz"),
    (EntityType.ASN, ""),
    (EntityType.ASN, "AS-5"),
    (EntityType.ASN, "AS4294967296"),  # 32-bit aralık dışı
    (EntityType.SERVICE, "1.2.3.4/tcp"),  # port yok
    (EntityType.SERVICE, "1.2.3.4"),  # port yok (protokol yokluğu hata DEĞİL)
    # Parantezsiz IPv6 → belirsiz, REDDEDİLİR (tahmin yürütülmez)
    (EntityType.SERVICE, "2001:db8::1:443"),
    (EntityType.SERVICE, "2001:db8::1:443/tcp"),
    (EntityType.SERVICE, "::1:80/tcp"),
    (EntityType.SERVICE, "2001:db8::1"),
    (EntityType.SERVICE, "[2001:db8::1]"),  # parantez var ama port yok
    (EntityType.SERVICE, "[2001:db8::1:443/tcp"),  # kapanmayan parantez
    (EntityType.SERVICE, "[firma.com]:443/tcp"),  # IP değil
    (EntityType.SERVICE, "1.2.3.4:70000/tcp"),
    (EntityType.SERVICE, "firma.com:443/tcp"),  # IP olmalı
    (EntityType.SERVICE, "1.2.3.4:http/tcp"),
    (EntityType.CERT, "kisa"),
    (EntityType.CERT, "zz" * 32),  # hex değil
    (EntityType.CERT, ""),
    (EntityType.ORG, ""),
    (EntityType.ORG, "   "),
    (EntityType.ORG, "A.Ş."),  # yalnızca hukuki ek → geriye bir şey kalmaz
    (EntityType.TECH, ""),
    (EntityType.TECH, ":"),
    (EntityType.TECH, "nginx::1.0"),  # product boş
]


@pytest.mark.parametrize("tip,ham", HATALI_VAKALAR)
def test_hatali_girdi_normalize_error(tip, ham):
    with pytest.raises(NormalizeError):
        normalize(tip, ham)


@pytest.mark.parametrize("tip,ham", HATALI_VAKALAR)
def test_hatali_girdi_gecerli_mi_false(tip, ham):
    """Ingest hattı `gecerli_mi` ile süzer: istisna değil, sessiz atlama."""
    assert gecerli_mi(tip, ham) is False


def test_bilinmeyen_tip():
    with pytest.raises(NormalizeError):
        normalize("hayvan", "firma.com")


def test_metin_olmayan_girdi():
    with pytest.raises(NormalizeError):
        normalize(EntityType.DOMAIN, None)


def test_gecerli_mi_normalize_edilmemis_degeri_reddeder():
    """Kanoniklik denetimi: ham hâliyle gelen değer geçerli sayılmaz."""
    assert gecerli_mi(EntityType.SUBDOMAIN, "WWW.Firma.COM.") is False
    assert gecerli_mi(EntityType.SUBDOMAIN, "www.firma.com") is True
    assert gecerli_mi(EntityType.NETBLOCK, "10.0.0.5/24") is False
    assert gecerli_mi(EntityType.NETBLOCK, "10.0.0.0/24") is True


# --------------------------------------------------------------------------- #
# 5) PSL testleri — domain_mi / kok_domain / host_tipi
#    Nokta sayarak KARAR VERİLMEZ: .com.tr, .co.uk, .gov.tr yanlış çıkar.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host,beklenen",
    [
        ("firma.com", True),
        ("firma.com.tr", True),  # 'com.tr' public suffix → DOMAIN
        ("firma.co.uk", True),
        ("firma.gov.tr", True),
        ("firma.org.tr", True),
        ("FIRMA.COM.TR.", True),  # normalize edilmemiş yazım da kabul
        ("www.firma.com", False),
        ("mail.firma.com.tr", False),
        ("a.b.firma.co.uk", False),
        ("_dmarc.firma.com", False),
        ("localhost", False),
        ("", False),
    ],
)
def test_domain_mi(host, beklenen):
    assert domain_mi(host) is beklenen


@pytest.mark.parametrize(
    "host,beklenen",
    [
        ("firma.com", "firma.com"),
        ("www.firma.com", "firma.com"),
        ("mail.firma.com.tr", "firma.com.tr"),
        ("firma.com.tr", "firma.com.tr"),
        ("a.b.c.firma.co.uk", "firma.co.uk"),
        ("https://API.Firma.com.tr:8443/x", "firma.com.tr"),
        ("_dmarc.firma.gov.tr", "firma.gov.tr"),
    ],
)
def test_kok_domain(host, beklenen):
    assert kok_domain(host) == beklenen


def test_kok_domain_gecersizde_hata():
    with pytest.raises(NormalizeError):
        kok_domain("localhost")


def _tip(host: str) -> EntityType:
    """Ingest katmanının tip düzeltmesi — `domain_mi` tek karar kaynağıdır."""
    return EntityType.DOMAIN if domain_mi(host) else EntityType.SUBDOMAIN


@pytest.mark.parametrize(
    "host,beklenen",
    [
        ("firma.com.tr", EntityType.DOMAIN),
        ("firma.com", EntityType.DOMAIN),
        ("firma.co.uk", EntityType.DOMAIN),
        ("mail.firma.com.tr", EntityType.SUBDOMAIN),
        ("www.firma.com", EntityType.SUBDOMAIN),
    ],
)
def test_tip_karari(host, beklenen):
    assert _tip(host) is beklenen


def test_psl_nokta_sayma_tuzagi():
    """İki nokta = subdomain varsayımı yanlıştır."""
    # 'firma.com.tr' iki nokta içerir ama SUBDOMAIN DEĞİLDİR.
    assert domain_mi("firma.com.tr") is True
    assert _tip("firma.com.tr") is EntityType.DOMAIN
    # 'www.firma.com' de iki nokta içerir ve SUBDOMAIN'dir.
    assert domain_mi("www.firma.com") is False
    assert _tip("www.firma.com") is EntityType.SUBDOMAIN


# --------------------------------------------------------------------------- #
# 6) Saflık — normalize() ağ/DB/dosya/saat/rastgelelik kullanmaz
# --------------------------------------------------------------------------- #


def test_saf_fonksiyon_tekrarlanabilir():
    """Aynı girdi, aynı çıktı — 100 kez."""
    ciktilar = {normalize(EntityType.SUBDOMAIN, "https://WWW.Şirket.com.tr:443/x") for _ in range(100)}
    assert ciktilar == {"www.xn--irket-idb.com.tr"}


def test_normalize_aga_cikmaz(monkeypatch):
    """PSL gömülü anlık görüntüden okunur; soket açılırsa test patlar."""
    import socket

    def _yasak(*a, **k):  # pragma: no cover - çağrılırsa zaten hata
        raise AssertionError("normalize() ağa çıktı!")

    monkeypatch.setattr(socket, "socket", _yasak)
    monkeypatch.setattr(socket, "create_connection", _yasak)
    monkeypatch.setattr(socket, "getaddrinfo", _yasak)

    for tip, ham, beklenen in DOGRU_VAKALAR:
        assert normalize(tip, ham) == beklenen
