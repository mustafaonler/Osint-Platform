"""Değer normalizasyonu — `docs/veri-modeli.md` Bölüm 3.

Altın kural: normalizasyon **yazma anında** yapılır, sorgu anında değil.

`normalize()` SAF FONKSİYONDUR:
  - ağ erişimi yok
  - veritabanı erişimi yok
  - dosya erişimi yok
  - saat okuma yok
  - rastgelelik yok

Aynı girdi her zaman aynı çıktıyı verir. Bu dosyadaki bir hata tüm veritabanını
sessizce bozar; `tests/test_normalize.py` projedeki en yüksek öncelikli test setidir.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from enum import StrEnum

import tldextract

__all__ = [
    "EntityType",
    "NormalizeError",
    "normalize",
    "gecerli_mi",
    "domain_mi",
    "kok_domain",
    "service_parcala",
]


# --------------------------------------------------------------------------- #
# Enum — docs/veri-modeli.md Bölüm 1
# --------------------------------------------------------------------------- #


class EntityType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    NETBLOCK = "netblock"
    ASN = "asn"
    EMAIL = "email"
    SERVICE = "service"
    CERT = "cert"
    ORG = "org"
    TECH = "tech"


class NormalizeError(ValueError):
    """Girdi bu varlık tipi için normalize edilemedi."""


# --------------------------------------------------------------------------- #
# PSL — gömülü anlık görüntü
# --------------------------------------------------------------------------- #

# `suffix_list_urls=()` → çalışma zamanında ASLA ağa çıkılmaz; tldextract ile
# birlikte gelen gömülü Public Suffix List anlık görüntüsü kullanılır.
# `cache_dir=None` → disk önbelleği de kapalı; fonksiyon saf kalır.
#
# PSL anlık görüntüsünü güncellemek = tldextract sürümünü yükseltmek. Bu bilinçli
# bir tercihtir: normalizasyon çıktısı sürüm sabitlendiği sürece deterministiktir.
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    cache_dir=None,
)


# --------------------------------------------------------------------------- #
# Küçültme — Türkçe tuzağı
# --------------------------------------------------------------------------- #

# "İ".lower() Python'da 'i' + U+0307 (COMBINING DOT ABOVE) üretir; yani iki kod
# noktası. Eşleştirme anahtarında bu istenmez — "İSTANBUL.com" ile "istanbul.com"
# farklı anahtarlara düşer. Çözüm: .lower() çağrılmadan ÖNCE İ/I → i eşlemesi.
_TR_KUCULTME = str.maketrans({"İ": "i", "I": "i"})


def _kucult(s: str) -> str:
    """Unicode-güvenli küçültme. Türkçe 'İ' için birleşik aksan üretmez."""
    # Önce NFC: girdi ayrışık gelmişse ('I' + U+0307) tek kod noktasına toplanır,
    # böylece aşağıdaki eşleme yakalar.
    s = unicodedata.normalize("NFC", s)
    return s.translate(_TR_KUCULTME).lower()


# --------------------------------------------------------------------------- #
# Host ayrıştırma (DOMAIN / SUBDOMAIN / EMAIL domain kısmı / SERVICE)
# --------------------------------------------------------------------------- #

_SEMA_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_ETIKET_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-]*[a-z0-9_])?$")


def _port_ayir(s: str) -> str:
    """host[:port] → host. IPv6 için ':' saymak yeterli değildir.

    'firma.com:8080'  → 'firma.com'
    '[::1]:443'       → '::1'
    '[2001:db8::1]'   → '2001:db8::1'
    '2001:db8::1'     → '2001:db8::1'   (çıplak IPv6, port YOK)
    """
    if s.startswith("["):
        kapanis = s.find("]")
        if kapanis == -1:
            raise NormalizeError(f"kapanmayan IPv6 köşeli parantezi: {s!r}")
        icerik = s[1:kapanis]
        kalan = s[kapanis + 1 :]
        if kalan and not kalan.startswith(":"):
            raise NormalizeError(f"']' sonrası beklenmeyen içerik: {s!r}")
        return icerik
    if s.count(":") == 1:
        # Tek iki nokta → host:port. (Çıplak IPv6'da her zaman >1 tane vardır.)
        return s.split(":", 1)[0]
    # 0 tane → port yok; >1 tane → köşeli parantezsiz çıplak IPv6, port ayrılmaz.
    return s


def _host_ayikla(ham: str) -> tuple[str, bool]:
    """Serbest metinden host çıkarır. (host, wildcard_mi) döner.

    Şema, yol, sorgu, fragment, kullanıcı bilgisi, port ve sondaki nokta atılır.
    'www' ASLA atılmaz — ayrı bir subdomain'dir ve farklı sunucuya çözülebilir.
    """
    s = ham.strip()
    if not s:
        raise NormalizeError("boş girdi")

    s = _SEMA_RE.sub("", s)  # https://  →  (at)
    s = re.split(r"[/?#]", s, maxsplit=1)[0]  # yol / sorgu / fragment  → (at)
    if "@" in s:  # user:pass@host  → host
        s = s.rsplit("@", 1)[1]
    if not s:
        raise NormalizeError(f"host bulunamadı: {ham!r}")

    s = _port_ayir(s)
    s = s.rstrip(".")  # 'firma.com.' → 'firma.com'  (kök nokta)
    if not s:
        raise NormalizeError(f"host bulunamadı: {ham!r}")

    wildcard = False
    while s.startswith("*."):
        wildcard = True
        s = s[2:]
    if s == "*":
        raise NormalizeError(f"yalnızca wildcard: {ham!r}")

    return _kucult(s), wildcard


def _punycode(host: str) -> str:
    """IDN → punycode, ETİKET BAZINDA.

    Tüm adı birden `.encode("idna")` ile geçirmek '_dmarc.firma.com' gibi alt
    çizgili etiketlerde patlar (IDNA alt çizgiye izin vermez). Zaten ASCII olan
    etiketler olduğu gibi bırakılır; yalnızca ASCII-dışı etiketler dönüştürülür.
    """
    cikti: list[str] = []
    for etiket in host.split("."):
        if not etiket:
            raise NormalizeError(f"boş etiket: {host!r}")
        if etiket.isascii():
            cikti.append(etiket)
            continue
        try:
            cikti.append(etiket.encode("idna").decode("ascii"))
        except UnicodeError as e:
            raise NormalizeError(f"IDNA dönüşümü başarısız ({etiket!r}): {e}") from e
    return ".".join(cikti)


def _host_dogrula(host: str) -> None:
    """Punycode sonrası biçim + PSL kontrolü. Geçersizse NormalizeError."""
    if len(host) > 253:
        raise NormalizeError(f"host 253 karakteri aşıyor: {host[:40]!r}...")
    etiketler = host.split(".")
    if len(etiketler) < 2:
        raise NormalizeError(f"tek etiketli host: {host!r}")
    for etiket in etiketler:
        if not 1 <= len(etiket) <= 63:
            raise NormalizeError(f"etiket uzunluğu geçersiz: {etiket!r}")
        if not _ETIKET_RE.match(etiket):
            raise NormalizeError(f"etikette geçersiz karakter: {etiket!r}")
    # PSL'de karşılığı olmayan ad (localhost, firma.yokboyle) kabul edilmez.
    r = _EXTRACT(host)
    if not r.suffix or not r.domain:
        raise NormalizeError(f"public suffix bulunamadı: {host!r}")


def _norm_host(ham: str) -> str:
    host, _wildcard = _host_ayikla(ham)
    host = _punycode(host)
    _host_dogrula(host)
    return host


# --------------------------------------------------------------------------- #
# PSL yardımcıları — nokta sayarak KARAR VERİLMEZ
# --------------------------------------------------------------------------- #


def domain_mi(host: str) -> bool:
    """Bu host kayıtlanabilir kök alan adı mı? (PSL'e göre)

    'firma.com.tr'      → True   ('com.tr' bir public suffix)
    'mail.firma.com.tr' → False
    'firma.co.uk'       → True
    'www.firma.com'     → False

    Elle nokta sayılmaz; '.com.tr', '.co.uk', '.gov.tr' gibi çok etiketli
    son eklerde nokta sayma her zaman yanlış sonuç verir.

    DOMAIN/SUBDOMAIN tip kararının TEK kaynağıdır. Ingest katmanı parser'ın
    verdiği tipi bununla düzeltir — bir parser her şeyi SUBDOMAIN
    işaretleyebilir, kök hedefin kendisi dahil:

        tip = EntityType.DOMAIN if domain_mi(norm) else EntityType.SUBDOMAIN
    """
    try:
        r = _EXTRACT(_norm_host(host))
    except NormalizeError:
        return False
    return bool(r.domain) and bool(r.suffix) and not r.subdomain


def kok_domain(host: str) -> str:
    """Kayıtlanabilir kök alan adını döndürür (PSL ile).

    'mail.firma.com.tr' → 'firma.com.tr'
    'a.b.c.firma.co.uk' → 'firma.co.uk'
    """
    norm = _norm_host(host)
    r = _EXTRACT(norm)
    if not r.domain or not r.suffix:
        raise NormalizeError(f"kök domain çıkarılamadı: {host!r}")
    return f"{r.domain}.{r.suffix}"


# --------------------------------------------------------------------------- #
# Tip bazlı normalizasyon — Bölüm 3.1 … 3.9
# --------------------------------------------------------------------------- #


def _norm_ip(ham: str) -> str:
    """Bölüm 3.2. IPv6 sıkıştırılmış küçük harf kanonik forma döner."""
    s = _port_ayir(ham.strip())
    try:
        return str(ipaddress.ip_address(s))
    except ValueError as e:
        raise NormalizeError(f"geçersiz IP: {ham!r}") from e


def _norm_netblock(ham: str) -> str:
    """Bölüm 3.3. strict=False şart — tool'lar host bitli CIDR döndürür."""
    s = ham.strip()
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError as e:
        raise NormalizeError(f"geçersiz CIDR: {ham!r}") from e


def _norm_email(ham: str) -> str:
    """Bölüm 3.4. Local küçültülür, plus-tag ayrılır, domain punycode'lanır."""
    s = ham.strip()
    if s.lower().startswith("mailto:"):
        s = s[len("mailto:") :]
    if "@" not in s:
        raise NormalizeError(f"'@' yok: {ham!r}")
    local, _, alan = s.rpartition("@")
    if not local or not alan:
        raise NormalizeError(f"eksik e-posta parçası: {ham!r}")
    if any(c.isspace() for c in local):
        raise NormalizeError(f"local kısımda boşluk: {ham!r}")

    local = _kucult(local)
    local = local.split("+", 1)[0]  # plus-tag at; deger_ham'da korunur
    if not local:
        raise NormalizeError(f"plus-tag sonrası local boş: {ham!r}")

    return f"{local}@{_norm_host(alan)}"


# X.509 seri numarası 1-20 bayt (2-40 hex), SHA-256 parmak izi 64 hex.
_CERT_HEX_ALT, _CERT_HEX_UST = 8, 64


def _norm_cert(ham: str) -> str:
    """Bölüm 3.5 + 4.3 — sertifikanın en güçlü hex tanımlayıcısı.

    SPESİFİKASYON KENDİ İÇİNDE ÇELİŞİYOR, çözüm burada
    ------------------------------------------------------------------
    Bölüm 3.5 "kimlik = SHA-256 parmak izi (64 hex)" diyor. Ama Bölüm 4.3'teki
    örnek crt.sh adapter'ı `serial_number` alanını CERT değeri olarak
    kullanıyor ve crt.sh'ın arama uç noktası parmak izini HİÇ döndürmüyor —
    ölçtük: dönen serial 32 hex. Yalnızca 64 hex kabul edilirse crt.sh'tan
    gelen her sertifika gözlemi `gecerli_mi` süzgecine takılır ve tüm CT log
    ailesi (crtsh, certspotter) CERT üretemez hâle gelir.

    Karar: 8-64 hex aralığındaki tanımlayıcılar kabul edilir. Parmak izi
    varsa (TLS el sıkışması, certspotter) o kullanılır; yoksa X.509 seri
    numarası kullanılır.

    KABUL EDİLEN SINIRLAMA: iki kaynak aynı sertifikayı farklı tanımlayıcıyla
    bildirirse (biri parmak izi, biri seri) tekilleşme OLMAZ, iki entity
    oluşur. v1'de bu bilinçli bir eksiktir — ayrı kalmak, yanlış birleştirmekten
    daha az zararlıdır (aynı gerekçe ORG tipinde de geçerli, Bölüm 3.8).
    Kalıcı çözüm sertifikanın tamamını çekip parmak izini hesaplamaktır;
    sertifika başına ek bir HTTP isteği demektir, v1 kapsamında değildir.
    """
    s = "".join(ham.split()).replace(":", "").lower()
    if s.startswith("sha256"):
        s = s[len("sha256") :]
    if any(c not in "0123456789abcdef" for c in s):
        raise NormalizeError(f"hex olmayan sertifika tanımlayıcısı: {ham!r}")
    if not _CERT_HEX_ALT <= len(s) <= _CERT_HEX_UST:
        raise NormalizeError(
            f"sertifika tanımlayıcısı {_CERT_HEX_ALT}-{_CERT_HEX_UST} hex "
            f"olmalı, {len(s)} geldi: {ham!r}"
        )
    return s


def _norm_asn(ham: str) -> str:
    """Bölüm 3.6. 'AS13335' → '13335'."""
    s = ham.strip().upper().removeprefix("AS").strip()
    try:
        n = int(s)
    except ValueError as e:
        raise NormalizeError(f"geçersiz ASN: {ham!r}") from e
    if not 0 <= n <= 4294967295:  # 32-bit ASN aralığı
        raise NormalizeError(f"ASN aralık dışı: {ham!r}")
    return str(n)


_VARSAYILAN_PROTO = "tcp"


def _norm_service(ham: str) -> str:
    """Bölüm 3.7 — ip:port/proto.

        IPv4:  '1.2.3.4:443/tcp'
        IPv6:  '[2001:db8::1]:443/tcp'      ← köşeli parantez ZORUNLU (RFC 3986)

    IPv6'da köşeli parantez neden zorunlu: parantezsiz '2001:db8::1:443'
    ifadesi AYNI ANDA iki geçerli okumaya sahiptir — "adres 2001:db8::1, port
    443" ve "adres 2001:db8::1:443" (kendisi de geçerli bir IPv6 adresidir).
    Parantezsiz biçimde bu iki servis aynı `deger_norm` anahtarına çakışır ve
    `RUNS_ON` ilişkisi YANLIŞ IP entity'sine bağlanır. Parantez, anahtarda
    adres sınırını açıkça işaretleyerek çakışmayı imkânsız kılar.

    Protokol belirtilmemişse 'tcp' varsayılır ve HATA FIRLATILMAZ. Gerekçe:
    ingest hattı geçersiz kaydı sessizce atlar (Bölüm 4.5), yani burada
    fırlatılan her istisna doğrudan VERİ KAYBIDIR. Pasif kaynaklardan gelen
    servis verisinin neredeyse tamamı TCP'dir; eksik protokolü tahmin etmenin
    maliyeti, kaydı büsbütün kaybetmenin maliyetinden çok daha düşüktür.

    PARANTEZSİZ IPv6 GİRDİSİ REDDEDİLİR — protokolün aksine burada tahmin
    yürütülmez. Fark şudur: eksik protokolde okumalardan biri (tcp) pratikte
    neredeyse her zaman doğrudur; parantezsiz IPv6'da iki okuma da eşit derecede
    geçerlidir ve yanlış seçim, kaydı kaybetmekten DAHA KÖTÜDÜR. Kayıp görünür
    bir eksiktir; yanlış IP'ye bağlanmış bir servis ise sessizce UYDURULMUŞ bir
    ilişkidir ve analiste doğru bulgu gibi görünür (İlke 2: her bulgu izlenebilir
    olmalı). Doğru çözüm kaynakta ucuzdur: adapter, IPv6'yı RFC 3986 biçiminde
    üretir.
    """
    s = ham.strip()
    if "/" in s:
        adres, _, proto_ham = s.rpartition("/")
        proto = _kucult(proto_ham.strip()) or _VARSAYILAN_PROTO
    else:
        adres, proto = s, _VARSAYILAN_PROTO

    adres = adres.strip()
    if adres.startswith("["):
        kapanis = adres.find("]")
        if kapanis == -1:
            raise NormalizeError(f"kapanmayan IPv6 köşeli parantezi: {ham!r}")
        ip_ham = adres[1:kapanis]
        kalan = adres[kapanis + 1 :]
        if not kalan.startswith(":"):
            raise NormalizeError(f"']' sonrası port yok: {ham!r}")
        port_ham = kalan[1:]
    elif adres.count(":") == 1:
        ip_ham, _, port_ham = adres.partition(":")
    elif adres.count(":") == 0:
        raise NormalizeError(f"port yok: {ham!r}")
    else:
        # Birden fazla ':' + parantez yok → parantezsiz IPv6. Belirsiz; bkz. docstring.
        raise NormalizeError(
            f"parantezsiz IPv6 servis adresi belirsiz, RFC 3986 biçimi zorunlu "
            f"([adres]:port): {ham!r}"
        )

    try:
        ip = ipaddress.ip_address(ip_ham.strip())
    except ValueError as e:
        raise NormalizeError(f"geçersiz servis IP'si: {ham!r}") from e
    try:
        port = int(port_ham.strip())
    except ValueError as e:
        raise NormalizeError(f"geçersiz port: {ham!r}") from e
    if not 1 <= port <= 65535:
        raise NormalizeError(f"port aralık dışı: {ham!r}")

    if ip.version == 6:
        return f"[{ip}]:{port}/{proto}"
    return f"{ip}:{port}/{proto}"


def service_parcala(norm: str) -> tuple[str, int, str]:
    """Kanonik SERVICE anahtarını (ip, port, proto) üçlüsüne geri ayrıştırır.

    Ingest, `RUNS_ON` ilişkisini kurarken servisin hangi IP entity'sine
    bağlanacağını buradan öğrenir. Dönen `ip`, IP tipi için de kanoniktir:
    `normalize(EntityType.IP, ip) == ip`.

    Ayrıştırmanın `_norm_service` ile aynı biçim varsayımlarını paylaşması şart
    olduğu için ikisi yan yana durur — biri değişirse diğeri de değişmelidir.

    Kanonik olmayan girdide `NormalizeError` fırlatır.
    """
    if not isinstance(norm, str) or normalize(EntityType.SERVICE, norm) != norm:
        raise NormalizeError(f"kanonik olmayan SERVICE değeri: {norm!r}")
    adres, _, proto = norm.rpartition("/")
    if adres.startswith("["):
        kapanis = adres.index("]")
        return adres[1:kapanis], int(adres[kapanis + 2 :]), proto
    ip, _, port = adres.partition(":")
    return ip, int(port), proto


# Bölüm 3.8'de listelenen hukuki ekler — bu liste bilinçli olarak kısadır.
_HUKUKI_EKLER = (
    "ltd. şti.",
    "ltd. sti.",
    "a.ş.",
    "a.s.",
    "inc.",
    "llc",
    "gmbh",
    "b.v.",
    "co.",
)
_NOKTALAMA_RE = re.compile(r"[^\w\s]", re.UNICODE)
_BOSLUK_RE = re.compile(r"\s+")


def _norm_org(ham: str) -> str:
    """Bölüm 3.8 — en kirli tip.

    Tam tekilleştirme mümkün değildir. 'ABC Teknoloji' ile
    'ABC Teknoloji ve Danışmanlık' ayrı varlık olarak kalır; v1'de bu KABUL
    EDİLMİŞ bir sınırlamadır. Bulanık eşleştirme v2 işidir — gereksiz
    birleştirme, ayrı kalmaktan daha zararlıdır.
    """
    s = _BOSLUK_RE.sub(" ", _kucult(ham)).strip()
    if not s:
        raise NormalizeError("boş kurum adı")

    # Hukuki ekleri sondan at (birden fazla olabilir: "... a.ş. ltd. şti.")
    degisti = True
    while degisti:
        degisti = False
        for ek in _HUKUKI_EKLER:
            if s.endswith(" " + ek) or s == ek:
                s = s[: -len(ek)].strip()
                degisti = True
                break

    s = _BOSLUK_RE.sub(" ", _NOKTALAMA_RE.sub(" ", s)).strip()
    if not s:
        raise NormalizeError(f"kurum adı sadeleştirmeden sonra boş: {ham!r}")
    return s


def _norm_tech(ham: str) -> str:
    """Bölüm 3.9. 'vendor:product:version' — sürüm yoksa '*'.

    Tek parçalı girdi ('nginx') CPE geleneğine uyularak 'nginx:nginx:*' olur.
    """
    s = _kucult(ham).strip()
    if not s:
        raise NormalizeError("boş teknoloji adı")
    parcalar = [p.strip() for p in s.split(":")]
    if len(parcalar) == 1:
        vendor = product = parcalar[0]
        version = ""
    elif len(parcalar) == 2:
        vendor, product = parcalar
        version = ""
    else:
        vendor, product = parcalar[0], parcalar[1]
        version = ":".join(parcalar[2:])
    if not vendor or not product:
        raise NormalizeError(f"eksik vendor/product: {ham!r}")
    return f"{vendor}:{product}:{version or '*'}"


_NORMALIZERS = {
    EntityType.DOMAIN: _norm_host,
    EntityType.SUBDOMAIN: _norm_host,
    EntityType.IP: _norm_ip,
    EntityType.NETBLOCK: _norm_netblock,
    EntityType.ASN: _norm_asn,
    EntityType.EMAIL: _norm_email,
    EntityType.SERVICE: _norm_service,
    EntityType.CERT: _norm_cert,
    EntityType.ORG: _norm_org,
    EntityType.TECH: _norm_tech,
}


def normalize(tip: EntityType, ham: str) -> str:
    """Ham değeri `deger_norm` eşleştirme anahtarına çevirir.

    SAF FONKSİYON: ağ erişimi yok, DB erişimi yok, dosya erişimi yok,
    saat okuma yok, rastgelelik yok. Aynı girdi her zaman aynı çıktıyı verir
    ve idempotenttir: normalize(tip, normalize(tip, x)) == normalize(tip, x).

    Geçersiz girdide `NormalizeError` fırlatır.
    """
    if not isinstance(ham, str):
        raise NormalizeError(f"metin bekleniyordu, {type(ham).__name__} geldi")
    try:
        fn = _NORMALIZERS[EntityType(tip)]
    except ValueError as e:
        raise NormalizeError(f"bilinmeyen varlık tipi: {tip!r}") from e
    return fn(ham)


def gecerli_mi(tip: EntityType, norm: str) -> bool:
    """`norm` bu tip için geçerli ve KANONİK biçimde mi?

    Ingest hattının süzgeci (Bölüm 4.5): bozuk kayıt sessizce atlanır, istisna
    fırlatılmaz. Kanoniklik kontrolü idempotensiyi de doğrular — normalize
    edilmemiş bir değer buradan geçemez.

    DİKKAT: DOMAIN ile SUBDOMAIN burada birbirinden AYIRT EDİLMEZ; ikisi de
    "geçerli host" olarak kabul edilir. Tip kararı `domain_mi()`'nin işidir.
    Aksi halde her şeyi SUBDOMAIN etiketleyen bir parser'ın bulduğu kök hedef
    sessizce çöpe giderdi.
    """
    try:
        return normalize(tip, norm) == norm
    except (NormalizeError, TypeError):
        return False
