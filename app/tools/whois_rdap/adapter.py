"""whois-rdap adapter — kayıt otoritesi sorgusu, P0.

Hedefe HİÇ dokunulmaz: sorgulanan taraf tescil kuruluşunun (registry/RIR)
RDAP sunucusudur.

NEDEN RDAP, ESKİ WHOIS DEĞİL
------------------------------------------------------------------
WHOIS **serbest metindir** ve her registrar farklı biçim kullanır: alan adları,
tarih formatları, satır düzeni değişir. Onu ayrıştırmak düzinelerce registrar'a
özel kural yazmak demektir ve `parse()` saf/test edilebilir kalamaz.

RDAP aynı veriyi **JSON** olarak verir (RFC 7483). Ayrıştırma deterministiktir,
tek bir fixture bütün biçimi temsil eder ve biçim değişirse test kırılır.
"""

from __future__ import annotations

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

RDAP_URL = "https://rdap.org"

# rdap.org bir yönlendiricidir: doğru registry/RIR sunucusuna 301/302 atar.
# Sınırsız takip yönlendirme döngüsüne açıktır.
AZAMI_YONLENDIRME = 5

# Bitiş tarihi bu kadar gün içindeyse işaretlenir. Süresi dolan domain
# devralınabilir; Hafta 6 bunu skorlayacak.
BITIS_UYARI_GUN = 90

# Gizlilik korumalı kayıtlarda vcard `fn` alanına konan tipik değerler.
# Bunlar bir KURUM ADI DEĞİLDİR; ORG entity'si üretilirse veri uydurulmuş olur.
_GIZLI_ISARETLERI = (
    "redacted",
    "privacy",
    "private",
    "not disclosed",
    "withheld",
    "data protected",
    "gdpr masked",
    "statutory masking enabled",
)


def _govde_json(icerik: bytes) -> Any:
    """Gövdeyi JSON olarak çöz; çözülemezse ham metni sakla.

    404 sayfaları ve hata gövdeleri JSON olmayabilir; yine de arşivlenir ki
    "bu iş neden boş döndü" sorusu cevaplanabilir kalsın (İlke 2).
    """
    try:
        return json.loads(icerik.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"_ham": icerik.decode("utf-8", errors="replace")[:4000]}


def _gizli_mi(deger: str) -> bool:
    d = deger.strip().lower()
    return not d or any(i in d for i in _GIZLI_ISARETLERI)


class WhoisRdapAdapter:
    cikti_formati = "json"

    spec = ToolSpec(
        name="whois-rdap",
        version="1.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset(
            {EntityType.DOMAIN, EntityType.IP, EntityType.NETBLOCK}
        ),
        uretir=frozenset(
            {EntityType.ORG, EntityType.SUBDOMAIN, EntityType.NETBLOCK, EntityType.ASN}
        ),
        calistirma="api",
        image=None,
        timeout_sn=30,
        # MUHAFAZAKÂR: rdap.org 429'a sık takılır. Retry zaten var ama en iyi
        # retry, hiç gerekmeyendir.
        dakikalik_istek=10,
        # Tescil kuruluşunun kendi kaydı — otoriter kaynak.
        varsayilan_guven=90,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Tek RDAP isteği. Hedef tipine göre `/domain/` ya da `/ip/`.

        404 = KAYIT BULUNAMADI, hata değil: sorgulanan ad tescilli değil ya da
        bu registry'de yok. `cikis_kodu` 0 döner ve gövde arşivlenir; runner
        işi başarılı sayar, `parse()` boş liste verir.
        """
        yol = "ip" if self._ip_gibi(hedef) else "domain"
        try:
            # `max_redirects` Client'in parametresidir, `get()`'in DEĞİL —
            # canlı test yakaladı. Modül düzeyi `httpx.get()` ile yönlendirme
            # sınırı konamaz, bu yüzden Client açılır.
            with httpx.Client(
                timeout=self.spec.timeout_sn,
                follow_redirects=True,
                max_redirects=AZAMI_YONLENDIRME,
                proxy=cfg.proxy,
                headers={
                    "Accept": "application/rdap+json",
                    "User-Agent": "osint-platform/1.0 (+ekip ici arac)",
                },
            ) as istemci:
                y = istemci.get(f"{RDAP_URL}/{yol}/{hedef}")
        except httpx.HTTPError as e:
            # Taşıma katmanı arızası → -1, runner retry'a düşer.
            return RawResult(
                icerik=str(e).encode("utf-8"),
                format="text",
                cikis_kodu=-1,
                meta={"hata": type(e).__name__, "yol": yol},
            )

        # ZARF: RDAP yanıtı SORGUYU GERİ DÖNDÜRMEZ. IP sorgusunda hangi
        # adresin sorulduğunu bilmeden `in_netblock` (ip → netblock) ilişkisi
        # kurulamaz. Hedefi yanıtla birlikte arşivliyoruz ki `parse()` saf
        # kalsın — bilgiyi `RawResult.meta`'dan okumak, ham arşiv dosyasında
        # BULUNMAYAN bir veriye bağımlılık yaratırdı ve arşivden yeniden
        # ayrıştırma imkânsızlaşırdı (İlke 2).
        zarf = {
            "hedef": hedef,
            "yol": yol,
            "http_durum": y.status_code,
            "yanit": _govde_json(y.content),
        }
        return RawResult(
            icerik=json.dumps(zarf, ensure_ascii=False).encode("utf-8"),
            format="json",
            # 404 = KAYIT BULUNAMADI, başarısızlık DEĞİL
            cikis_kodu=0 if y.status_code in (200, 404) else y.status_code,
            meta={"http_durum": y.status_code, "yol": yol},
        )

    @staticmethod
    def _ip_gibi(hedef: str) -> bool:
        """IP/NETBLOCK mı DOMAIN mi? RDAP yolu buna göre seçilir.

        `normalize` çağrılmaz — `calistir()` ağ katmanıdır, tip kararı için
        ucuz bir sözdizimi kontrolü yeterli ve saf fonksiyona bağımlılık
        yaratmaz. NETBLOCK ('10.0.0.0/8') da IP yoluna gider; RDAP prefiks
        sorgusunu kabul eder.
        """
        ilk = hedef.split("/")[0]
        return ":" in ilk or (
            ilk.count(".") == 3 and all(p.isdigit() for p in ilk.split("."))
        )

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """RDAP JSON → gözlemler. SAF FONKSİYON.

        Bozuk/eksik kayıtta istisna fırlatmaz, boş liste döner.
        """
        try:
            d = json.loads(ham.icerik.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(d, dict):
            return []

        # İki biçim de kabul edilir: `calistir()`'in ürettiği zarf, ya da çıplak
        # RDAP nesnesi. İkincisi fixture'ları ve elle kaydedilmiş yanıtları
        # doğrudan kullanılabilir kılar.
        hedef = None
        if isinstance(d.get("yanit"), dict):
            hedef = d.get("hedef") if isinstance(d.get("hedef"), str) else None
            d = d["yanit"]

        sinif = str(d.get("objectClassName") or "").lower()
        if sinif == "domain":
            return self._domain(d)
        if sinif in ("ip network", "ipnetwork"):
            return self._ip_agi(d, hedef)
        # 404 gövdesi ya da tanınmayan nesne — bilgi yok, uydurma da yok.
        return []

    # -- DOMAIN ------------------------------------------------------------- #

    def _domain(self, d: dict) -> list[Observation]:
        ad = str(d.get("ldhName") or d.get("unicodeName") or "").strip().rstrip(".")
        if not ad:
            return []

        cikti: list[Observation] = []
        nitelikler: dict[str, Any] = {"kaynak": "rdap"}

        # Durum kodları: clientTransferProhibited gibi kilitler.
        durumlar = [s for s in (d.get("status") or []) if isinstance(s, str)]
        if durumlar:
            nitelikler["rdap_durum"] = durumlar

        nitelikler.update(self._tarihler(d))

        # Registrar bir KURUM ADIDIR ama hedefin sahibi değildir; ORG entity'si
        # yapılmaz, niteliklerde durur. Sahiplik `registrant` rolündedir.
        registrar = self._entity_adi(d, "registrar")
        if registrar and not _gizli_mi(registrar):
            nitelikler["registrar"] = registrar

        # Kayıt sahibi → ORG entity + owned_by
        sahip = self._entity_adi(d, "registrant")
        if sahip is None:
            nitelikler["kayit_sahibi_yok"] = True
        elif _gizli_mi(sahip):
            # GİZLİLİK KORUMALI. "REDACTED FOR PRIVACY" bir kurum adı değildir;
            # ORG entity'si üretmek veri UYDURMAKTIR. GDPR sonrası gTLD'lerin
            # neredeyse tamamı böyledir — bu yokluk da bir bulgudur.
            nitelikler["kayit_sahibi_gizli"] = True
            nitelikler["kayit_sahibi_ham"] = sahip
        else:
            nitelikler["kayit_sahibi_gizli"] = False
            cikti.append(
                Observation(
                    tip=EntityType.ORG,
                    deger_ham=sahip,
                    nitelikler={"kaynak": "rdap", "rol": "registrant", "domain": ad},
                    kaynak_yol="$.entities[?(@.roles=='registrant')]",
                    iliskiler=(
                        # owned_by = netblock/domain → org. Gözlem ORG olduğu
                        # için yön "gelen"; ingest kaynağı/hedefi takas eder.
                        ObservedRelation(
                            tip=RelationType.OWNED_BY,
                            hedef_tip=EntityType.DOMAIN,
                            hedef_deger=ad,
                            yon="gelen",
                        ),
                    ),
                )
            )

        # Nameserver'lar → SUBDOMAIN + ns_for
        for i, ns in enumerate(d.get("nameservers") or []):
            if not isinstance(ns, dict):
                continue
            ns_ad = str(ns.get("ldhName") or "").strip().rstrip(".")
            if not ns_ad:
                continue
            cikti.append(
                Observation(
                    tip=EntityType.SUBDOMAIN,
                    deger_ham=ns_ad,
                    nitelikler={"kaynak": "rdap", "rol": "nameserver"},
                    kaynak_yol=f"$.nameservers[{i}].ldhName",
                    # ns_for = sub → domain. Gözlem isim sunucusu, hedef alan
                    # adı: yön "giden", ingest takas YAPMAZ.
                    iliskiler=(
                        ObservedRelation(
                            tip=RelationType.NS_FOR,
                            hedef_tip=EntityType.DOMAIN,
                            hedef_deger=ad,
                            yon="giden",
                        ),
                    ),
                )
            )

        # Hedefin kendisi — nitelikleri taşıyan gözlem
        cikti.append(
            Observation(
                tip=EntityType.DOMAIN,
                deger_ham=ad,
                nitelikler=nitelikler,
                kaynak_yol="$",
            )
        )
        return cikti

    @staticmethod
    def _tarihler(d: dict) -> dict[str, Any]:
        """`events` dizisinden tarihler + bitiş yakınlığı işareti.

        SAF KALIR: "bugün" okunmaz. Bitiş tarihi, RDAP'ın kendi verdiği
        `last update of RDAP database` olayına göre değerlendirilir; o da yoksa
        yalnızca tarih kaydedilir, uyarı konmaz. `datetime.now()` çağırmak
        `parse()`'ı saf olmaktan çıkarır ve fixture testini anlamsızlaştırır.
        """
        eslesme = {
            "registration": "olusturma",
            "expiration": "bitis",
            "last changed": "son_degisiklik",
            "last update of rdap database": "rdap_guncelleme",
        }
        sonuc: dict[str, Any] = {}
        for e in d.get("events") or []:
            if not isinstance(e, dict):
                continue
            eylem = str(e.get("eventAction") or "").lower()
            tarih = e.get("eventDate")
            if eylem in eslesme and isinstance(tarih, str):
                sonuc[eslesme[eylem]] = tarih

        bitis, referans = sonuc.get("bitis"), sonuc.get("rdap_guncelleme")
        if bitis and referans:
            kalan = _gun_farki(referans, bitis)
            if kalan is not None:
                sonuc["bitise_kalan_gun"] = kalan
                # Süresi dolan domain devralınabilir — Hafta 6 skorlayacak.
                sonuc["bitis_yakin"] = kalan <= BITIS_UYARI_GUN
        return sonuc

    @staticmethod
    def _entity_adi(d: dict, rol: str) -> str | None:
        """Verilen roldeki entity'nin vcard `fn`/`org` alanı.

        vcardArray biçimi: `["vcard", [["fn", {}, "text", "Ad"], ...]]`
        """
        for e in d.get("entities") or []:
            if not isinstance(e, dict):
                continue
            if rol not in [str(r).lower() for r in (e.get("roles") or [])]:
                continue
            vc = e.get("vcardArray")
            if not (isinstance(vc, list) and len(vc) > 1 and isinstance(vc[1], list)):
                continue
            adaylar: dict[str, str] = {}
            for alan in vc[1]:
                if isinstance(alan, list) and len(alan) >= 4 and alan[0] in ("fn", "org"):
                    deger = alan[3]
                    if isinstance(deger, str) and deger.strip():
                        adaylar[alan[0]] = deger.strip()
            # `org` varsa yeğlenir: `fn` kişi adı olabilir, `org` kurumdur.
            if adaylar:
                return adaylar.get("org") or adaylar.get("fn")
        return None

    # -- IP / NETBLOCK ------------------------------------------------------ #

    def _ip_agi(self, d: dict, hedef: str | None = None) -> list[Observation]:
        cikti: list[Observation] = []
        bloklar = self._cidrler(d)

        nitelikler: dict[str, Any] = {"kaynak": "rdap"}
        for alan in ("name", "country", "type", "handle"):
            if isinstance(d.get(alan), str) and d[alan].strip():
                nitelikler[f"rdap_{alan}"] = d[alan].strip()

        # Sorgulanan adres biliniyorsa `in_netblock` kurulur (ip → netblock).
        # Hedef bir NETBLOCK ise ilişki kurulmaz: bir bloğun kendi içinde
        # olması anlamsızdır ve `ck_rel_self` kısıtına çarpardı.
        ip_iliskisi: tuple[ObservedRelation, ...] = ()
        if hedef and "/" not in hedef and self._ip_gibi(hedef):
            ip_iliskisi = (
                ObservedRelation(
                    tip=RelationType.IN_NETBLOCK,
                    hedef_tip=EntityType.IP,
                    hedef_deger=hedef,
                    # in_netblock = ip → netblock. Gözlem NETBLOCK olduğu için
                    # yön "gelen"; ingest kaynağı/hedefi takas eder.
                    yon="gelen",
                ),
            )

        for i, blok in enumerate(bloklar):
            cikti.append(
                Observation(
                    tip=EntityType.NETBLOCK,
                    deger_ham=blok,
                    nitelikler=dict(nitelikler),
                    kaynak_yol=f"$.cidr0_cidrs[{i}]",
                    iliskiler=ip_iliskisi,
                )
            )

        # Sahip kurum → ORG + owned_by (netblock → org)
        sahip = self._entity_adi(d, "registrant") or self._entity_adi(d, "administrative")
        if sahip and not _gizli_mi(sahip) and bloklar:
            cikti.append(
                Observation(
                    tip=EntityType.ORG,
                    deger_ham=sahip,
                    nitelikler={"kaynak": "rdap", "rol": "ip-registrant"},
                    kaynak_yol="$.entities",
                    iliskiler=(
                        ObservedRelation(
                            tip=RelationType.OWNED_BY,
                            hedef_tip=EntityType.NETBLOCK,
                            hedef_deger=bloklar[0],
                            yon="gelen",
                        ),
                    ),
                )
            )

        # ASN — RDAP IP sorgusunda GENELDE YOKTUR (ölçtük: ARIN'in
        # `arin_originas0_originautnums` alanı boş dönüyor). Varsa alınır;
        # asıl ASN kaynağı `asn-bgp` tool'udur, bu yüzden ayrı bir tool'dur.
        for i, asn in enumerate(self._asnler(d)):
            cikti.append(
                Observation(
                    tip=EntityType.ASN,
                    deger_ham=str(asn),
                    nitelikler={"kaynak": "rdap"},
                    kaynak_yol=f"$.arin_originas0_originautnums[{i}]",
                    iliskiler=(
                        # announced_by = netblock → asn. Gözlem ASN olduğu için
                        # yön "gelen".
                        ObservedRelation(
                            tip=RelationType.ANNOUNCED_BY,
                            hedef_tip=EntityType.NETBLOCK,
                            hedef_deger=bloklar[0],
                            yon="gelen",
                        ),
                    )
                    if bloklar
                    else (),
                )
            )
        return cikti

    @staticmethod
    def _cidrler(d: dict) -> list[str]:
        """`cidr0_cidrs` → ['140.82.112.0/20']. Yoksa start/end'den türetilmez.

        Aralıktan CIDR hesaplamak `parse()`'a ağ matematiği sokar ve tek bir
        aralık birden çok prefikse karşılık gelebilir; RDAP zaten `cidr0_cidrs`
        veriyorsa onu kullanırız, vermiyorsa NETBLOCK üretmeyiz.
        """
        cikti = []
        for c in d.get("cidr0_cidrs") or []:
            if not isinstance(c, dict):
                continue
            uzunluk = c.get("length")
            onek = c.get("v4prefix") or c.get("v6prefix")
            if isinstance(onek, str) and isinstance(uzunluk, int):
                cikti.append(f"{onek}/{uzunluk}")
        return cikti

    @staticmethod
    def _asnler(d: dict) -> list[int]:
        cikti: list[int] = []
        for anahtar, deger in d.items():
            if "autnum" not in anahtar.lower() or not isinstance(deger, list):
                continue
            cikti.extend(a for a in deger if isinstance(a, int))
        return cikti

    def saglik(self) -> bool:
        """Anahtar gerektirmez."""
        return True


def _gun_farki(bas: str, son: str) -> int | None:
    """İki ISO-8601 tarihi arasındaki gün farkı. SAF: saat okumaz.

    Modül seviyesinde çünkü `parse()` zincirinin saflığı buna bağlı; içeride
    `datetime.now()` çağrılmadığı buradan tek bakışta görülür.
    """
    from datetime import datetime

    try:
        a = datetime.fromisoformat(bas.replace("Z", "+00:00"))
        b = datetime.fromisoformat(son.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return (b - a).days
