"""asn-bgp adapter — BGP duyuru verisi, P0.

DEĞERİ: tek bir IP'yi kurumun TÜM IP bloklarına genişletir. Diğer tool'lar
varlıkları tek tek bulurken bu, keşif yüzeyini tek hamlede büyütür
(`docs/kapsam.md` Bölüm 3.3).

KAYNAK SEÇİMİ — RIPEstat
------------------------------------------------------------------
Kriterler: API key GEREKTİRMEMELİ, ücretsiz olmalı, JSON döndürmeli.

    RIPEstat      key yok · ücretsiz · JSON · ihtiyacın ÜÇÜNÜ DE karşılıyor
    ipinfo.io     key'siz çalışır ama günlük 1000 istekle sınırlı ve bir
                  ASN'in TÜM prefikslerini vermez — asıl değerimiz o
    bgpview.io    key yok ama kesintileri ve daha sıkı limitleri bildirilmiş
    Team Cymru    DNS tabanlı, JSON değil; ayrıştırması serbest metne döner

RIPEstat TEK KAYNAK olarak seçildi çünkü üç sorgunun üçünü de veriyor:

    /network-info        IP  → prefix + duyuran ASN'ler
    /as-overview         ASN → sahip kurum (holder)
    /announced-prefixes  ASN → duyurulan tüm prefiksler

Birden çok sağlayıcıyı birleştirmek, her birinin ayrı hata/limit davranışını
runner'a taşırdı; tek kaynak yeterken bu karmaşıklık gereksizdir.
"""

from __future__ import annotations

import ipaddress
import json
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

RIPESTAT = "https://stat.ripe.net/data"

# --------------------------------------------------------------------------- #
# KAPSAM PATLAMASI SINIRI
# --------------------------------------------------------------------------- #
#
# ÖLÇÜM (bu tool yazılırken canlı alındı):
#     AS36459  GitHub          26 prefix     3.5 KB
#     AS24940  Hetzner         95 prefix    10.8 KB
#     AS63949  Linode         446 prefix    49.1 KB
#     AS14061  DigitalOcean   886 prefix    96.8 KB
#     AS54113  Fastly       1.820 prefix   203.0 KB
#     AS20940  Akamai       4.725 prefix   513.5 KB
#     AS13335  Cloudflare   5.326 prefix   614.3 KB
#
# Cloudflare'in 5.326 prefiksini NETBLOCK entity'si yapmak, tek bir işten
# 5.326 alakasız satır demektir. Gürültü bu projenin BİR NUMARALI riskidir:
# değer önerisi "önceliklendirme"dir ve analistin listesi kullanılamaz hâle
# gelirse tool işe yaramaz.
#
# KARAR: prefiks sayısı sınırı aşarsa HİÇBİRİ yazılmaz. Sayı ve ASN
# `nitelikler`'e kaydedilir; bilgi kaybolmaz, yalnızca entity'ye çevrilmez.
# Ham çıktı zaten arşivde durur (İlke 2) — analist gerektiğinde tam listeye
# ulaşabilir.
#
# BEDELİ: sınırın hemen altındaki bir sağlayıcının blokları yazılır, hemen
# üstündekinin yazılmaz. Kesin bir eşik yok; 50, "bir kurumun kendi blokları"
# ile "bir sağlayıcının envanteri" arasındaki tipik ayrımı yakalıyor
# (ölçümde GitHub 26 ile altında, Hetzner 95 ile üstünde kaldı).
PREFIX_SINIRI = 50

# Bilinen bulut/CDN ASN'leri. Bu ASN'lerdeki IP'ler HEDEFİN DEĞİL,
# SAĞLAYICININDIR: 104.21.x.x Cloudflare'e aittir, müşterisine değil.
# İşaretlenmezse analist "hedefin 5.000 IP bloğu var" diye yanılır.
#
# Liste kısa ve kasıtlı olarak eksiktir: kapsayıcı olmaya çalışmak bakım
# yüküdür. Asıl genel kural PREFIX_SINIRI'dır — bir kurumun binlerce prefiks
# duyurması zaten onun bir altyapı sağlayıcısı olduğunun kanıtıdır. Bu liste
# yalnızca en sık karşılaşılanları HIZLI ve AÇIK biçimde etiketler.
BULUT_ASN = {
    "13335": "Cloudflare",
    "16509": "AWS",
    "14618": "AWS",
    "15169": "Google",
    "396982": "Google Cloud",
    "8075": "Microsoft Azure",
    "54113": "Fastly",
    "20940": "Akamai",
    "16625": "Akamai",
    "14061": "DigitalOcean",
    "24940": "Hetzner",
    "16276": "OVH",
    "63949": "Linode",
    "13414": "Twitter",
    "32934": "Meta",
}


class AsnBgpAdapter:
    cikti_formati = "json"

    spec = ToolSpec(
        name="asn-bgp",
        version="1.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.IP, EntityType.ASN}),
        uretir=frozenset({EntityType.ASN, EntityType.NETBLOCK, EntityType.ORG}),
        calistirma="api",
        image=None,
        timeout_sn=45,
        dakikalik_istek=20,
        # BGP tablosu gözlemlenmiş gerçektir ama RIPEstat toplayıcıdır,
        # tescil otoritesi değil: RDAP'ın (90) hemen altı.
        varsayilan_guven=85,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """IP ya da ASN için RIPEstat sorguları; hepsi tek zarfta arşivlenir.

        ÖZEL/AYRILMIŞ ARALIKLAR SORGULANMAZ: 10.x, 192.168.x, 127.x gibi
        adresler BGP'de duyurulmaz, sorgu boşa gider ve üçüncü tarafa
        gereksiz yük bindirir. Bu adresler REDDEDİLMEZ — iç ağ sızıntısı
        tespiti için değerlidirler (`docs/veri-modeli.md` 3.2) — yalnızca
        BGP'ye sorulmazlar.
        """
        zarf: dict[str, Any] = {"hedef": hedef, "tip": None, "atlandi": None}

        asn = self._asn_mi(hedef)
        if asn is None:
            ozel = self._ozel_mi(hedef)
            if ozel:
                zarf.update(tip="ip", atlandi=ozel)
                return self._sonuc(zarf, 0)
            zarf["tip"] = "ip"
        else:
            zarf["tip"] = "asn"

        try:
            with httpx.Client(
                timeout=self.spec.timeout_sn,
                proxy=cfg.proxy,
                headers={"User-Agent": "osint-platform/1.0 (+ekip ici arac)"},
            ) as istemci:
                if asn is None:
                    ag = self._sorgu(istemci, "network-info", hedef)
                    zarf["network_info"] = ag
                    asnler = [
                        str(a) for a in ((ag or {}).get("asns") or []) if str(a).strip()
                    ]
                else:
                    zarf["network_info"] = None
                    asnler = [asn]

                zarf["asn_bilgi"] = {}
                zarf["prefixler"] = {}
                for a in asnler:
                    zarf["asn_bilgi"][a] = self._sorgu(istemci, "as-overview", f"AS{a}")
                    p = self._sorgu(istemci, "announced-prefixes", f"AS{a}")
                    liste = [
                        x.get("prefix")
                        for x in ((p or {}).get("prefixes") or [])
                        if isinstance(x, dict) and x.get("prefix")
                    ]
                    # TAM liste arşivlenir (İlke 2); sınırı `parse()` uygular.
                    zarf["prefixler"][a] = {"sayi": len(liste), "liste": liste}
        except httpx.HTTPError as e:
            return RawResult(
                icerik=json.dumps(
                    {**zarf, "hata": f"{type(e).__name__}: {e}"}, ensure_ascii=False
                ).encode("utf-8"),
                format="json",
                cikis_kodu=-1,  # taşıma hatası → runner retry'a düşer
                meta={"hata": type(e).__name__},
            )

        return self._sonuc(zarf, 0)

    @staticmethod
    def _sonuc(zarf: dict, kod: int) -> RawResult:
        return RawResult(
            icerik=json.dumps(zarf, ensure_ascii=False).encode("utf-8"),
            format="json",
            cikis_kodu=kod,
        )

    @staticmethod
    def _sorgu(istemci: Any, uc: str, kaynak: str) -> dict | None:
        """RIPEstat çağrısı. 404/hata → None, istisna fırlatmaz."""
        y = istemci.get(f"{RIPESTAT}/{uc}/data.json", params={"resource": kaynak})
        if y.status_code != 200:
            return None
        try:
            govde = y.json()
        except ValueError:
            return None
        # RIPEstat kendi durumunu gövdede bildirir; "ok" değilse veri yok.
        if govde.get("status") != "ok":
            return None
        veri = govde.get("data")
        return veri if isinstance(veri, dict) else None

    @staticmethod
    def _asn_mi(hedef: str) -> str | None:
        """'AS13335' / '13335' → '13335'. IP ise None."""
        s = hedef.strip().upper()
        s = s[2:] if s.startswith("AS") else s
        return s if s.isdigit() else None

    @staticmethod
    def _ozel_mi(hedef: str) -> str | None:
        """Özel/ayrılmış aralık mı? Sebebi döner, değilse None."""
        try:
            adres = ipaddress.ip_address(hedef.strip())
        except ValueError:
            return None
        # SIRA ÖNEMLİ: `is_private` en genel kontroldür ve loopback ile
        # link-local'ı da KAPSAR (ikisi de IANA özel aralıklarındandır).
        # Önce sorulursa spesifik etiketler hiç görünmez ve analist
        # 'ozel_aralik' yerine 'loopback' bilgisini kaybeder.
        if adres.is_loopback:
            return "loopback"
        if adres.is_link_local:
            return "link_local"
        if adres.is_multicast:
            return "multicast"
        # `is_reserved` de `is_private` içinde kalır (240.0.0.0/4 ikisine de
        # uyar); spesifik olan önce sorulur.
        if adres.is_reserved:
            return "ayrilmis"
        if adres.is_private:
            return "ozel_aralik"
        return None

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """RIPEstat zarfı → gözlemler. SAF FONKSİYON."""
        try:
            d = json.loads(ham.icerik.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(d, dict) or d.get("atlandi"):
            # Özel aralık atlandı — sorgu hiç yapılmadı, uydurulacak veri yok.
            return []

        asn_bilgi = d.get("asn_bilgi") or {}
        prefixler = d.get("prefixler") or {}
        if not isinstance(asn_bilgi, dict) or not isinstance(prefixler, dict):
            return []

        # Sorgulanan IP'nin içinde bulunduğu prefiks — ASN'e bağlanacak blok.
        ag = d.get("network_info") or {}
        kapsayan = ag.get("prefix") if isinstance(ag, dict) else None

        cikti: list[Observation] = []
        for asn in sorted(asn_bilgi):
            cikti.extend(
                self._asn_gozlemleri(asn, asn_bilgi.get(asn), prefixler.get(asn), kapsayan)
            )
        return cikti

    def _asn_gozlemleri(
        self, asn: str, bilgi: Any, prefiks: Any, kapsayan: str | None
    ) -> list[Observation]:
        cikti: list[Observation] = []
        bilgi = bilgi if isinstance(bilgi, dict) else {}
        prefiks = prefiks if isinstance(prefiks, dict) else {}

        sayi = prefiks.get("sayi")
        sayi = sayi if isinstance(sayi, int) else 0
        liste = [p for p in (prefiks.get("liste") or []) if isinstance(p, str)]
        bulut = BULUT_ASN.get(asn)
        sinir_asildi = sayi > PREFIX_SINIRI

        nitelikler: dict[str, Any] = {
            "kaynak": "ripestat",
            "duyurulan_prefiks_sayisi": sayi,
        }
        if isinstance(bilgi.get("holder"), str) and bilgi["holder"].strip():
            nitelikler["as_holder"] = bilgi["holder"].strip()
        if bulut:
            # ANALİSTİ YANILTMAMAK İÇİN: bu ASN'deki IP'ler hedefin değil,
            # sağlayıcınındır. 104.21.x.x Cloudflare'e aittir, müşterisine değil.
            nitelikler["bulut_saglayici"] = bulut
            nitelikler["hedefe_ait_degil"] = True
        elif sinir_asildi:
            # Liste dışı ama binlerce prefiks duyuruyor: büyük olasılıkla o da
            # bir altyapı sağlayıcısı. Kesin hüküm değil, işaret.
            nitelikler["saglayici_olabilir"] = True
        if sinir_asildi:
            nitelikler["prefiks_sinir_asildi"] = True
            nitelikler["prefiks_siniri"] = PREFIX_SINIRI

        # 1) ASN entity — kapsayan blok üzerinden announced_by
        cikti.append(
            Observation(
                tip=EntityType.ASN,
                deger_ham=asn,
                nitelikler=nitelikler,
                kaynak_yol=f"$.asn_bilgi.{asn}",
                iliskiler=(
                    # announced_by = netblock → asn. Gözlem ASN olduğu için
                    # yön "gelen"; ingest kaynağı/hedefi takas eder.
                    ObservedRelation(
                        tip=RelationType.ANNOUNCED_BY,
                        hedef_tip=EntityType.NETBLOCK,
                        hedef_deger=kapsayan,
                        yon="gelen",
                    ),
                )
                if kapsayan
                else (),
            )
        )

        # 2) AS sahibi kurum → ORG + owned_by
        holder = nitelikler.get("as_holder")
        if holder:
            cikti.append(
                Observation(
                    tip=EntityType.ORG,
                    deger_ham=self._holder_kurum(holder),
                    nitelikler={"kaynak": "ripestat", "asn": asn, "as_holder": holder},
                    kaynak_yol=f"$.asn_bilgi.{asn}.holder",
                    iliskiler=(
                        ObservedRelation(
                            tip=RelationType.OWNED_BY,
                            hedef_tip=EntityType.ASN,
                            hedef_deger=asn,
                            yon="gelen",
                        ),
                    ),
                )
            )

        # 3) Duyurulan prefiksler — SINIR BURADA UYGULANIR
        if sinir_asildi:
            return cikti  # sayı niteliklerde, entity üretilmez

        for i, p in enumerate(liste):
            cikti.append(
                Observation(
                    tip=EntityType.NETBLOCK,
                    deger_ham=p,
                    nitelikler={"kaynak": "ripestat", "duyuran_asn": asn},
                    kaynak_yol=f"$.prefixler.{asn}.liste[{i}]",
                    iliskiler=(
                        # Gözlem NETBLOCK: announced_by yönü "giden".
                        ObservedRelation(
                            tip=RelationType.ANNOUNCED_BY,
                            hedef_tip=EntityType.ASN,
                            hedef_deger=asn,
                            yon="giden",
                        ),
                    ),
                )
            )
        return cikti

    @staticmethod
    def _holder_kurum(holder: str) -> str:
        """RIPEstat `holder` alanından kurum adını çıkarır.

        ÖLÇÜM: RIPEstat İKİ BİÇİM kullanıyor, ikisini de gerçek veriden gördük:
            'GITHUB - GitHub, Inc.'            → tire ile ayrılmış
            'HETZNER-AS Hetzner Online GmbH'   → '<HANDLE>-AS ' öneki

        Baştaki handle tescil kısaltmasıdır, kurum adı DEĞİLDİR. Temizlenmezse
        ORG anahtarı 'hetzner as hetzner online' gibi çift kayıtlı bir değere
        düşer ve aynı kurumu başka bir kaynaktan gören tool ile TEKİLLEŞMEZ.

        Hiçbir kalıp tutmazsa değer olduğu gibi bırakılır — uydurmaktansa ham
        hâlini korumak yeğdir; §3.8 normalizasyonu hukuki ekleri zaten temizler.
        """
        h = holder.strip()
        if " - " in h:
            return h.split(" - ", 1)[1].strip() or h
        ilk, ayrac, kalan = h.partition(" ")
        if ayrac and ilk.upper().endswith("-AS") and kalan.strip():
            return kalan.strip()
        return h

    def saglik(self) -> bool:
        """Anahtar gerektirmez."""
        return True
