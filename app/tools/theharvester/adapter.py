"""theHarvester adapter — pasif e-posta ve subdomain keşfi, P0.

KAYNAK SEÇİMİ — YALNIZCA PASİF MODÜLLER
------------------------------------------------------------------
theHarvester'ın bazı yetenekleri **Seviye A**'dır ve v1 kapsamı dışındadır.
Bunlar komuta ASLA eklenmez:

    -c / --dns-brute   DNS brute-force  → hedefin NS'ine binlerce sorgu
    -t                 DNS TLD genişletme → aynı sebeple aktif
    --screenshot       hedefin sayfasına HTTP isteği → P2, üstelik gereksiz
    -b shodan          ayrı bir tool olacak (shodan-lookup), burada yok

Seçilen kaynakların HEPSİ üçüncü taraf veri tabanı sorgular; hedefin
sunucusuna tek paket gitmez:

    anubis         pasif subdomain veri tabanı (jonlu.ca)
    duckduckgo     arama motoru indeksi
    hackertarget   pasif DNS/API arşivi
    otx            AlienVault Open Threat Exchange pasif DNS
    rapiddns       pasif DNS toplayıcı
    threatminer    tehdit istihbaratı arşivi
    urlscan        gönderilmiş tarama arşivi

`crtsh` BİLİNÇLİ OLARAK YOK: kendi tool'umuz var (`app/tools/crtsh`). Aynı
veriyi iki kez toplamak crt.sh'a gereksiz yük bindirir ve dedup yükü yaratır —
`docs/kapsam.md` Bölüm 3.3'ün `dig` için verdiği gerekçenin aynısı.

API key isteyen kaynaklar (censys, hunter, intelx, netlas...) listeye
alınmadı: key yoksa theHarvester onları zaten atlar ama gereksiz gürültü ve
bekleme üretir.

KVKK: e-posta kişisel veridir. Bu tool yalnızca HEDEF DOMAIN'e bağlı kurumsal
adresleri toplar; kişi araştırması (`docs/kapsam.md` Bölüm 4) kapsam dışıdır.
"""

from __future__ import annotations

import json
from typing import Any

from app.normalize import EntityType
from app.tools._base import (
    Observation,
    ObservedRelation,
    Passivity,
    RawResult,
    RelationType,
    ToolConfig,
    ToolSpec,
)

# Yalnızca P0, anahtarsız kaynaklar. Gerekçesi modül docstring'inde.
PASIF_KAYNAKLAR = (
    "anubis",
    "duckduckgo",
    "hackertarget",
    "otx",
    "rapiddns",
    "threatminer",
    "urlscan",
)

# Komutta ASLA bulunmaması gereken bayraklar — testle sabitlenir.
YASAK_BAYRAKLAR = ("-c", "--dns-brute", "-t", "--screenshot", "--takeover")


class TheHarvesterAdapter:
    cikti_formati = "json"

    spec = ToolSpec(
        name="theharvester",
        version="4.6.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.EMAIL, EntityType.SUBDOMAIN}),
        calistirma="docker",
        image="osint-theharvester:1.0",
        timeout_sn=180,
        dakikalik_istek=5,
        # Kaynakları KARIŞIK: bir kısmı pasif DNS arşivi, bir kısmı arama
        # motoru kazıması. Otoriter değil, tahmin de değil — CT logunun (90)
        # ve RDAP'ın altında, subfinder'ın (70) da altında.
        varsayilan_guven=60,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Container'da koşar: komutu KURAR, çalıştırmaz."""
        raise NotImplementedError(
            "theharvester container'da koşar; runner `komut()` kullanır"
        )

    @staticmethod
    def komut(hedef: str) -> list[str]:
        """Container'a geçirilecek argümanlar.

        ENTRYPOINT bir sarmalayıcıdır (`calistir.sh`): theHarvester'ı `-f` ile
        koşturup ürettiği JSON'u stdout'a basar. `-f` argümanı BURADA GEÇMEZ,
        sarmalayıcı ekler — dosya yolu container'ın iç meselesidir.

        Aktif bayraklar (`-c`, `-t`, `--screenshot`) YOKTUR ve olmamalıdır.
        """
        return ["-d", hedef, "-b", ",".join(PASIF_KAYNAKLAR)]

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """theHarvester JSON çıktısı → gözlemler. SAF FONKSİYON.

        Çıktı yapısı (gerçek koşudan): `emails`, `hosts`, `ips`, `asns`,
        `interesting_urls`, `shodan`. Bizim manifest'imiz yalnızca EMAIL ve
        SUBDOMAIN ürettiği için ilk ikisi kullanılır.

        SONUÇ BULUNAMAMASI NORMALDİR ve hata değildir: boş liste döner.
        """
        try:
            d = json.loads(ham.icerik.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(d, dict):
            return []

        hedef = self._hedef_bul(d)
        cikti: list[Observation] = []
        cikti.extend(self._hostlar(d, hedef))
        cikti.extend(self._epostalar(d, hedef))
        return cikti

    @staticmethod
    def _hedef_bul(d: dict) -> str | None:
        """Sorgulanan domain — e-postaların `email_at` hedefi.

        theHarvester çıktısı hedefi ayrı bir alanda vermez; e-postaların ortak
        alan adından türetilir. Tek bir ortak alan yoksa ilişki kurulmaz —
        yanlış bir bağ kurmaktansa bağsız bırakmak yeğdir.
        """
        alanlar = {
            e.rsplit("@", 1)[1].strip().lower()
            for e in (d.get("emails") or [])
            if isinstance(e, str) and "@" in e and e.rsplit("@", 1)[1].strip()
        }
        return alanlar.pop() if len(alanlar) == 1 else None

    def _hostlar(self, d: dict, hedef: str | None) -> list[Observation]:
        """`hosts` → SUBDOMAIN gözlemleri.

        GERÇEK ÇIKTIDA ÜÇ BİÇİM VAR (ölçtük, python.org: 155 kayıt):
            'blog.python.org'                    düz ad
            'blog.python.org:142.251.45.211'     ad:IP  (129 kayıt)
            '2Fblog.python.org'                  URL-kodlu ÇÖP (%2F sızıntısı)

        IP kısmı `nitelikler`'e yazılır, IP entity'si ÜRETİLMEZ: manifest
        `uretir: [EMAIL, SUBDOMAIN]` diyor ve yetenek grafiği bu beyana
        dayanıyor. IP'yi burada üretmek, beyan edilmemiş bir tipi sessizce
        zincire sokardı — `dns-resolver` zaten IP üreten tool'dur.
        """
        cikti: list[Observation] = []
        for i, kayit in enumerate(d.get("hosts") or []):
            if not isinstance(kayit, str):
                continue
            ad, _, ip = kayit.strip().partition(":")
            ad = ad.strip().rstrip(".")
            if not self._ad_gecerli(ad):
                continue

            nitelikler: dict[str, Any] = {"kaynak": "theharvester"}
            if ip.strip():
                nitelikler["cozumlenen_ip"] = ip.strip()

            cikti.append(
                Observation(
                    tip=EntityType.SUBDOMAIN,
                    deger_ham=ad,
                    nitelikler=nitelikler,
                    kaynak_yol=f"$.hosts[{i}]",
                )
            )
        return cikti

    @staticmethod
    def _ad_gecerli(ad: str) -> bool:
        """Bariz çöpü eler. `gecerli_mi` süzgeci ingest'te ZATEN var.

        Buradaki eleme onun yerine geçmez, ÖNÜNE geçer: bunlar BEKLENEN
        bozukluklardır (theHarvester'ın kendi kazıma artıkları), anomali
        değil. Her biri için ingest'te WARNING basmak, uyarı kanalını
        gürültüye boğar ve gerçek bozuklukların görülmemesine yol açar —
        crtsh'ta CA adları için verilen kararın aynısı.
        """
        if not ad or "." not in ad:
            return False
        if any(c.isspace() for c in ad):
            return False
        # '%2F' URL kodlamasının sızıntısı: '2Fblog.python.org'. Ölçtük,
        # python.org çıktısında 10 tane vardı.
        if "%" in ad or ad.startswith("2F"):
            return False
        # '@' varsa bu bir e-posta, host değil (crtsh'taki aynı tuzak).
        return "@" not in ad

    def _epostalar(self, d: dict, hedef: str | None) -> list[Observation]:
        """`emails` → EMAIL gözlemleri + `email_at` ilişkisi.

        KVKK: yalnızca hedef domain'e bağlı kurumsal adresler. Kişi
        araştırması yapılmaz.

        `deger_ham` OLDUĞU GİBİ korunur; plus-tag ayıklaması ve küçültme
        `normalize()`'ın işidir (§3.4) ve `deger_ham` ilk görülen hâli tutar.
        """
        cikti: list[Observation] = []
        for i, kayit in enumerate(d.get("emails") or []):
            if not isinstance(kayit, str):
                continue
            eposta = kayit.strip()
            if not self._eposta_gecerli(eposta):
                continue

            alan = eposta.rsplit("@", 1)[1].strip().rstrip(".")
            cikti.append(
                Observation(
                    tip=EntityType.EMAIL,
                    deger_ham=eposta,
                    nitelikler={"kaynak": "theharvester"},
                    kaynak_yol=f"$.emails[{i}]",
                    # email_at = email → domain. Gözlem e-posta olduğu için
                    # yön "giden"; ingest takas YAPMAZ.
                    iliskiler=(
                        ObservedRelation(
                            tip=RelationType.EMAIL_AT,
                            hedef_tip=EntityType.DOMAIN,
                            hedef_deger=alan,
                            yon="giden",
                        ),
                    )
                    if alan
                    else (),
                )
            )
        return cikti

    @staticmethod
    def _eposta_gecerli(eposta: str) -> bool:
        """Bariz bozuk adresleri eler."""
        if eposta.count("@") != 1:
            return False
        yerel, _, alan = eposta.partition("@")
        if not yerel or not alan or "." not in alan:
            return False
        if any(c.isspace() for c in eposta):
            return False
        return "%" not in eposta and not alan.startswith(".")

    def saglik(self) -> bool:
        """Anahtar gerektirmez; imajın varlığını runner doğrular."""
        return True
