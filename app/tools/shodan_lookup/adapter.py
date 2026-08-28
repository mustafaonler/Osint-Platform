"""shodan-lookup adapter — Shodan host indeksi sorgusu, P0.

"SHODAN TARAMA YAPAR, BU NASIL P0?"
------------------------------------------------------------------
Bu soruyu ileride biri soracak; cevabı burada.

Shodan'ın kendisi internet çapında tarama yapar — ama BİZ ONU YAPMIYORUZ.
Biz Shodan'ın **zaten toplamış olduğu indeksi** sorguluyoruz. Trafik akışı:

    biz  →  api.shodan.io        (üçüncü taraf veri kaynağı)
    biz  ↛  hedefin sunucusu     (TEK PAKET GİTMEZ)

Bu, `crt.sh`'a sertifika sormakla aynı sınıftır: veriyi bir başkası topladı,
biz arşivine bakıyoruz. Tarama yapan taraf olsaydık Seviye A olurdu ve v1
kapsamı dışında kalırdı (`docs/kapsam.md` Bölüm 3.2).

BEDELİ: indeks ESKİ OLABİLİR. Shodan bir portu altı ay önce görmüş olabilir
ve bugün kapalı olabilir. Bu yüzden `varsayilan_guven` 75'tir (CT logunun 90'ı
ve RDAP'ın 90'ı ile kıyaslanamaz) ve son tarama tarihi `nitelikler`'e yazılır —
analist tazeliği kendisi değerlendirebilsin.

BANNER GÜVENİLMEYEN VERİDİR
------------------------------------------------------------------
Banner metnini HEDEFİN SUNUCUSU yazar. İçine ne isterse koyabilir; Hafta 6'da
bu veri dil modeline gidecek. Prompt injection savunmasının İLK KATMANI burada
başlar: `_banner_temizle` kontrol karakterlerini atar ve uzunluğu sınırlar.
Bu tek başına yeterli DEĞİLDİR — `<untrusted_data>` sınırlayıcısı ve structured
output zorunluluğu AI katmanında eklenecektir.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

import httpx

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

SHODAN_URL = "https://api.shodan.io/shodan/host"

# Banner tek başına megabaytlarca olabilir (HTML sayfası, sertifika dökümü).
# Sınır hem veritabanını hem de Hafta 6'daki token bütçesini korur.
BANNER_SINIRI = 2000

# Kontrol karakterleri: ANSI kaçışları, satır beslemeleri, null baytlar.
# Temizlenmezse hem JSONB'yi hem log görünümünü bozar, hem de metin tabanlı
# bir sınırlayıcıyı (ör. `<untrusted_data>`) kaçış dizileriyle kırma denemesi
# için yüzey açar.
_KONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ShodanLookupAdapter:
    cikti_formati = "json"

    spec = ToolSpec(
        name="shodan-lookup",
        version="1.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.IP}),
        uretir=frozenset({EntityType.SERVICE, EntityType.TECH, EntityType.ORG}),
        calistirma="api",
        image=None,
        auth_env=("SHODAN_API_KEY",),
        # ZORUNLU: anahtarsız bu tool HİÇ çalışamaz. subfinder'ın opsiyonel
        # anahtarından farkı budur; runner buna bakıp SKIPPED döner.
        auth_gerekli=True,
        timeout_sn=30,
        # Ücretsiz katman 1 istek/saniye.
        dakikalik_istek=60,
        # Kota takibi HENÜZ UYGULANMADI (paylaşılan sayaç gerekir); değer
        # manifest'te ve burada dursun ki uygulanınca yeri hazır olsun.
        aylik_kota=100,
        # İndeks verisi ESKİ OLABİLİR — otoriter kaynakların (90) altında.
        varsayilan_guven=75,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Shodan host indeksini sorgular.

        ANAHTAR URL PARAMETRESİNDE GİDER — Shodan'ın API tasarımı, bizim
        seçimimiz değil. Bu yüzden URL hiçbir yere yazılmaz: ham arşive
        yalnızca YANIT GÖVDESİ girer, hata mesajları `_temizle`'den geçer.
        `RawResult.meta`'ya da URL konmaz.
        """
        anahtar = cfg.env.get("SHODAN_API_KEY", "")
        if not anahtar:
            # Runner bunu zaten önlüyor (`anahtar_engeli`); burası ikinci
            # savunma — adapter doğrudan çağrılırsa anahtarsız istek atmasın.
            return RawResult(
                icerik=b'{"error":"SHODAN_API_KEY tanimli degil"}',
                format="json",
                cikis_kodu=401,
            )

        ozel = self._ozel_mi(hedef)
        if ozel:
            # Özel/ayrılmış adresler Shodan indeksinde bulunmaz; sorgu kotayı
            # boşa harcar. Adres REDDEDİLMEZ, yalnızca sorulmaz.
            return RawResult(
                icerik=json.dumps({"atlandi": ozel}).encode("utf-8"),
                format="json",
                cikis_kodu=0,
            )

        try:
            with httpx.Client(
                timeout=self.spec.timeout_sn,
                proxy=cfg.proxy,
                headers={"User-Agent": "osint-platform/1.0 (+ekip ici arac)"},
            ) as istemci:
                y = istemci.get(
                    f"{SHODAN_URL}/{hedef}",
                    params={"key": anahtar, "minify": "false"},
                )
        except httpx.HTTPError as e:
            return RawResult(
                icerik=self._temizle(str(e), anahtar).encode("utf-8"),
                format="text",
                cikis_kodu=-1,
                meta={"hata": type(e).__name__},
            )

        # 404 = IP indekste YOK. Hata değil, bilgi: Shodan bu adreste hiçbir
        # açık servis görmemiş.
        # 401 = anahtar geçersiz. KALICI hata (KALICI_KODLAR içinde) —
        #       retry edilmez, yanlış anahtar tekrar denemekle düzelmez.
        # 429 = kota doldu. GEÇİCİ (GECICI_KODLAR içinde) — retry'a düşer.
        kod = 0 if y.status_code in (200, 404) else y.status_code

        return RawResult(
            # Gövde Shodan'dan gelir ve anahtarı İÇERMEZ; yine de temizlikten
            # geçiriyoruz — sürpriz bir yankılamaya karşı.
            icerik=self._temizle(y.text, anahtar).encode("utf-8"),
            format="json",
            cikis_kodu=kod,
            meta={"http_durum": y.status_code},  # URL YOK
        )

    @staticmethod
    def _temizle(metin: str, anahtar: str) -> str:
        """Anahtarı metinden söker. Ham arşive ve hata mesajına giren TEK yol.

        httpx istisnaları URL'i mesaja koyar ve URL'de anahtar vardır. Bu
        fonksiyon olmadan API anahtarı diske yazılır ve `job.hata_mesaji`
        üzerinden arayüzde görünür.
        """
        if anahtar and anahtar in metin:
            metin = metin.replace(anahtar, "***")
        # `key=` parametresi başka bir biçimde de geçebilir (kodlanmış vb.).
        return re.sub(r"(key=)[^&\s\"']+", r"\1***", metin)

    @staticmethod
    def _ozel_mi(hedef: str) -> str | None:
        try:
            adres = ipaddress.ip_address(hedef.strip())
        except ValueError:
            return None
        if adres.is_loopback:
            return "loopback"
        if adres.is_link_local:
            return "link_local"
        if adres.is_multicast:
            return "multicast"
        if adres.is_reserved:
            return "ayrilmis"
        if adres.is_private:
            return "ozel_aralik"
        return None

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """Shodan host yanıtı → gözlemler. SAF FONKSİYON."""
        try:
            d = json.loads(ham.icerik.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(d, dict) or d.get("atlandi") or d.get("error"):
            # 404 gövdesi `{"error": "No information available..."}` biçiminde
            # gelir — bilgi yok, uydurulacak veri de yok.
            return []

        ip = str(d.get("ip_str") or "").strip()
        if not ip:
            return []

        cikti: list[Observation] = []
        cikti.extend(self._kurum(d, ip))
        cikti.extend(self._servisler(d, ip))
        return cikti

    def _kurum(self, d: dict, ip: str) -> list[Observation]:
        """`org` / `isp` → ORG + `owned_by`."""
        ad = d.get("org") or d.get("isp")
        if not isinstance(ad, str) or not ad.strip():
            return []
        return [
            Observation(
                tip=EntityType.ORG,
                deger_ham=ad.strip(),
                nitelikler={
                    "kaynak": "shodan",
                    "isp": d.get("isp"),
                    "ulke": d.get("country_code"),
                },
                kaynak_yol="$.org",
                iliskiler=(
                    # owned_by = netblock/domain → org. Burada kaynak IP'dir;
                    # gözlem ORG olduğu için yön "gelen".
                    ObservedRelation(
                        tip=RelationType.OWNED_BY,
                        hedef_tip=EntityType.IP,
                        hedef_deger=ip,
                        yon="gelen",
                    ),
                ),
            )
        ]

    def _servisler(self, d: dict, ip: str) -> list[Observation]:
        """`data[]` → SERVICE + `runs_on`, ürün/sürüm → TECH + `uses_tech`."""
        cikti: list[Observation] = []
        for i, kayit in enumerate(d.get("data") or []):
            if not isinstance(kayit, dict):
                continue
            port = kayit.get("port")
            if not isinstance(port, int) or not 1 <= port <= 65535:
                continue

            proto = kayit.get("transport") or "tcp"
            servis = self._servis_anahtari(ip, port, str(proto))

            nitelikler: dict[str, Any] = {
                "kaynak": "shodan",
                "port": port,
                "proto": str(proto).lower(),
            }
            for alan in ("product", "version", "_shodan"):
                if kayit.get(alan) is not None and alan != "_shodan":
                    nitelikler[alan] = kayit[alan]
            # VERİ TAZELİĞİ: altı ay önceki bir port bilgisi bugün geçerli
            # olmayabilir. Analist bunu görmeli.
            if isinstance(kayit.get("timestamp"), str):
                nitelikler["son_gorulme_shodan"] = kayit["timestamp"]
            if isinstance(kayit.get("banner"), str) or isinstance(
                kayit.get("data"), str
            ):
                ham_banner = kayit.get("banner") or kayit.get("data") or ""
                nitelikler["banner"] = self._banner_temizle(ham_banner)

            cikti.append(
                Observation(
                    tip=EntityType.SERVICE,
                    deger_ham=servis,
                    nitelikler=nitelikler,
                    kaynak_yol=f"$.data[{i}]",
                    iliskiler=(
                        # runs_on = service → ip. Gözlem SERVICE: yön "giden".
                        ObservedRelation(
                            tip=RelationType.RUNS_ON,
                            hedef_tip=EntityType.IP,
                            hedef_deger=ip,
                            yon="giden",
                        ),
                    ),
                )
            )

            tech = self._tech(kayit)
            if tech:
                cikti.append(
                    Observation(
                        tip=EntityType.TECH,
                        deger_ham=tech,
                        nitelikler={"kaynak": "shodan", "port": port},
                        kaynak_yol=f"$.data[{i}].product",
                        iliskiler=(
                            # uses_tech = sub/service → tech. Gözlem TECH:
                            # yön "gelen", kaynak servistir.
                            ObservedRelation(
                                tip=RelationType.USES_TECH,
                                hedef_tip=EntityType.SERVICE,
                                hedef_deger=servis,
                                yon="gelen",
                            ),
                        ),
                    )
                )
        return cikti

    @staticmethod
    def _servis_anahtari(ip: str, port: int, proto: str) -> str:
        """`normalize.py` §3.7 biçimi. IPv6'da KÖŞELİ PARANTEZ ZORUNLU.

        Parantezsiz `2001:db8::1:443` aynı anda iki farklı servise karşılık
        gelir ve `runs_on` yanlış IP'ye bağlanır — normalize bu yüzden
        parantezsiz IPv6'yı reddeder.
        """
        try:
            adres = ipaddress.ip_address(ip)
        except ValueError:
            return f"{ip}:{port}/{proto.lower()}"
        if adres.version == 6:
            return f"[{adres}]:{port}/{proto.lower()}"
        return f"{adres}:{port}/{proto.lower()}"

    @staticmethod
    def _tech(kayit: dict) -> str | None:
        """`product` + `version` → `vendor:product:version` (§3.9)."""
        urun = kayit.get("product")
        if not isinstance(urun, str) or not urun.strip():
            return None
        urun = urun.strip()
        surum = kayit.get("version")
        surum = surum.strip() if isinstance(surum, str) and surum.strip() else "*"
        # Vendor bilinmiyor; CPE geleneğine uyup ürün adı iki kez yazılır —
        # `normalize` tek parçalı girdide zaten aynısını yapar.
        return f"{urun}:{urun}:{surum}"

    @staticmethod
    def _banner_temizle(banner: str) -> str:
        """Kontrol karakterlerini atar, uzunluğu sınırlar.

        HEDEFİN KONTROLÜNDEKİ METİNDİR. Prompt injection savunmasının ilk
        katmanı; tek başına yeterli değildir (bkz. modül docstring'i).
        """
        temiz = _KONTROL_RE.sub("", banner)
        if len(temiz) > BANNER_SINIRI:
            temiz = temiz[:BANNER_SINIRI] + "…[kirpildi]"
        return temiz

    def saglik(self) -> bool:
        """Anahtar kontrolü runner'ın işi (`anahtar_engeli`)."""
        return True
