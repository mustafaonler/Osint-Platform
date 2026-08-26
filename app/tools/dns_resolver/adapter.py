"""dns-resolver adapter — DNS kayıt çözümlemesi, P1.

`docs/kapsam.md` Bölüm 3.3: `dig` ile eşdeğer yetenek. A, AAAA, CNAME, MX, NS,
TXT, SOA, CAA + SPF/DMARC ayrıştırma.

SORUMLULUK SINIRI: `calistir()` ağa çıkar ve HER ŞEYİ serileştirilmiş JSON
olarak döndürür; `parse()` yalnızca o JSON'u okur. Bu ayrım sayesinde `parse()`
saf kalır ve fixture'la ağsız test edilebilir — dnspython nesneleri fixture'a
YAZILMAZ, metin hâlleri yazılır.
"""

from __future__ import annotations

import json
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from app.normalize import EntityType, NormalizeError, kok_domain
from app.tools._base import (
    Observation,
    ObservedRelation,
    Passivity,
    RawResult,
    RelationType,
    ToolConfig,
    ToolSpec,
)

# Sorgulanacak kayıt tipleri. SOA ve CAA entity üretmez, niteliklere yazılır.
KAYIT_TIPLERI = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

# CNAME zinciri döngüye girebilir (a → b → a) ya da absürt uzayabilir.
# Sekiz hop, gerçek dünyada görülenin çok üstünde; sınır olmadan sonsuz döngü.
CNAME_AZAMI_HOP = 8


class DnsResolverAdapter:
    cikti_formati = "json"

    spec = ToolSpec(
        name="dns-resolver",
        version="1.0",
        passivity=Passivity.P1,
        kabul_eder=frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN}),
        uretir=frozenset(
            {EntityType.IP, EntityType.SUBDOMAIN, EntityType.TECH, EntityType.ORG}
        ),
        calistirma="api",
        image=None,
        timeout_sn=30,
        dakikalik_istek=60,
        varsayilan_guven=85,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Bütün kayıt tiplerini sorgular, serileştirilmiş JSON döndürür.

        PASİFLİK SEVİYESİ RESOLVER'A BAĞLIDIR — kod bunu bilir
        ------------------------------------------------------------------
        `cfg.resolver` public bir çözümleyici (varsayılan 1.1.1.1) olduğu sürece
        bu modül **P1**'dir: hedefin sunucusuna tek paket gitmez, ortak altyapı
        sorgulanır. Aynı kod `cfg.resolver` hedefin kendi authoritative NS'ine
        yöneltilirse **P2** olur — o zaman `investigation.yetki_onayi` gerekir
        (`docs/kapsam.md` Bölüm 3.2).

        Bugün seviye manifest'te sabit P1'dir; resolver'ı hedefin NS'ine
        yöneltme özelliği YOKTUR. Eklendiğinde `ToolSpec.passivity` çalışma
        zamanında P2'ye yükseltilmeli ve runner yetkiyi ona göre denetlemelidir.
        Alan bu yüzden `ToolConfig`'te durur, adapter'ın içine gömülmez.
        """
        cozumleyici = dns.resolver.Resolver(configure=False)
        cozumleyici.nameservers = [cfg.resolver]
        # Tek sorgu bütçesi; toplam timeout'u RUNNER uygular.
        cozumleyici.timeout = 5.0
        cozumleyici.lifetime = 5.0

        kayitlar: dict[str, Any] = {}
        for tip in KAYIT_TIPLERI:
            # BİR KAYIT TİPİ PATLARSA DİĞERLERİ YİNE SORGULANIR: kısmi sonuç
            # kayıp değildir. MX'i SERVFAIL veren bir sunucu A kaydını
            # verebilir ve o A kaydı gerçek bir bulgudur.
            kayitlar[tip] = self._sorgu(cozumleyici, hedef, tip)

        cikti: dict[str, Any] = {
            "hedef": hedef,
            "resolver": cfg.resolver,
            "kayitlar": kayitlar,
            # DMARC AYRI BİR İSİMDEDİR: _dmarc.<domain>. Alt çizgili etiket
            # normalize'de korunur (etiket bazlı punycode sayesinde).
            "dmarc": self._sorgu(cozumleyici, f"_dmarc.{hedef}", "TXT"),
            "cname_zinciri": self._cname_zinciri(cozumleyici, hedef),
        }

        return RawResult(
            icerik=json.dumps(cikti, ensure_ascii=False).encode("utf-8"),
            format="json",
            cikis_kodu=self._cikis_kodu(kayitlar),
            meta={"resolver": cfg.resolver},
        )

    @staticmethod
    def _cikis_kodu(kayitlar: dict[str, Any]) -> int:
        """0 = kullanılabilir sonuç var, 503 = geçici arıza (retry'a düşer).

        KISMİ SONUÇ KORUNUR: tek bir kayıt tipi bile geldiyse iş BAŞARILIDIR.
        Aksi hâlde runner turu tekrarlar, ham arşivi üzerine yazar ve elde
        edilmiş gerçek veriyi kaybedebiliriz. Geçici arıza yalnızca HİÇBİR
        kayıt gelmediğinde bildirilir.

        NXDOMAIN ve NODATA hata DEĞİLDİR: "bu isim yok" / "bu tipte kayıt yok"
        da bir bulgudur ve tekrar sorulmakla değişmez.
        """
        durumlar = {k["durum"] for k in kayitlar.values()}
        if "ok" in durumlar:
            return 0
        if "gecici" in durumlar:
            return 503  # GECICI_KODLAR içinde → runner tekrar dener
        return 0

    @staticmethod
    def _sorgu(cozumleyici: Any, ad: str, tip: str) -> dict[str, Any]:
        """Tek kayıt tipi. İSTİSNA FIRLATMAZ, durumu sözlükte bildirir."""
        try:
            yanit = cozumleyici.resolve(ad, tip)
            return {"durum": "ok", "veri": [r.to_text() for r in yanit]}
        except dns.resolver.NXDOMAIN:
            # İsim hiç yok. Hata değil, bilgi.
            return {"durum": "nxdomain", "veri": []}
        except dns.resolver.NoAnswer:
            # İsim var ama bu tipte kayıt yok. Hata değil, bilgi.
            return {"durum": "nodata", "veri": []}
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as e:
            # SERVFAIL / zaman aşımı — geçici, tekrar denemeye değer.
            return {"durum": "gecici", "veri": [], "hata": f"{type(e).__name__}"}
        except dns.exception.DNSException as e:
            return {"durum": "hata", "veri": [], "hata": f"{type(e).__name__}: {e}"}

    def _cname_zinciri(self, cozumleyici: Any, hedef: str) -> list[str]:
        """CNAME zincirini sınırlı adımda takip eder.

        `a → b → a` döngüsü gerçek dünyada olur (yanlış yapılandırma) ve
        sınırsız takip worker'ı kilitler. `gorulen` kümesi döngüyü, hop sayısı
        absürt uzunluğu keser.
        """
        zincir: list[str] = []
        gorulen = {hedef.rstrip(".").lower()}
        ad = hedef
        for _ in range(CNAME_AZAMI_HOP):
            sonuc = self._sorgu(cozumleyici, ad, "CNAME")
            if sonuc["durum"] != "ok" or not sonuc["veri"]:
                break
            ad = sonuc["veri"][0].rstrip(".")
            if ad.lower() in gorulen:
                break  # döngü
            gorulen.add(ad.lower())
            zincir.append(ad)
        return zincir

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """Serileştirilmiş DNS yanıtı → gözlemler.

        SAF FONKSİYON: ağ yok, DB yok, dosya yok, saat okuma yok, rastgelelik
        yok. Bütün ağ işi `calistir()`'de bitmiştir.
        """
        try:
            veri = json.loads(ham.icerik.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(veri, dict):
            return []

        hedef = veri.get("hedef")
        if not isinstance(hedef, str) or not hedef.strip():
            return []
        hedef = hedef.strip().rstrip(".")
        kayitlar = veri.get("kayitlar") or {}
        if not isinstance(kayitlar, dict):
            kayitlar = {}

        cikti: list[Observation] = []
        cikti.extend(self._adresler(hedef, kayitlar))
        cikti.extend(self._cname(hedef, veri.get("cname_zinciri")))
        cikti.extend(self._mx_ns(hedef, kayitlar))
        cikti.extend(self._saglayici(hedef, kayitlar))
        cikti.extend(self._posta_guvenligi(hedef, kayitlar, veri.get("dmarc")))
        return cikti

    @staticmethod
    def _degerler(kayitlar: dict, tip: str) -> list[str]:
        k = kayitlar.get(tip) or {}
        veri = k.get("veri") if isinstance(k, dict) else None
        return [v for v in veri if isinstance(v, str)] if isinstance(veri, list) else []

    def _adresler(self, hedef: str, kayitlar: dict) -> list[Observation]:
        """A / AAAA → IP gözlemi + `resolves_to` ilişkisi."""
        cikti = []
        for tip in ("A", "AAAA"):
            for i, adres in enumerate(self._degerler(kayitlar, tip)):
                cikti.append(
                    Observation(
                        tip=EntityType.IP,
                        deger_ham=adres,
                        nitelikler={"dns_kayit": tip},
                        kaynak_yol=f"$.kayitlar.{tip}.veri[{i}]",
                        # YÖN: resolves_to = domain/sub → ip. Gözlem IP olduğu
                        # için ilişki "gelen"dir; ingest kaynağı/hedefi takas eder.
                        iliskiler=(
                            ObservedRelation(
                                tip=RelationType.RESOLVES_TO,
                                hedef_tip=EntityType.SUBDOMAIN,
                                hedef_deger=hedef,
                                yon="gelen",
                            ),
                        ),
                    )
                )
        return cikti

    def _cname(self, hedef: str, zincir: Any) -> list[Observation]:
        """CNAME zinciri → SUBDOMAIN gözlemleri + `cname_for` ilişkisi."""
        if not isinstance(zincir, list):
            return []
        cikti = []
        onceki = hedef
        for i, ad in enumerate(zincir):
            if not isinstance(ad, str) or not ad.strip():
                continue
            ad = ad.strip().rstrip(".")
            cikti.append(
                Observation(
                    tip=EntityType.SUBDOMAIN,
                    deger_ham=ad,
                    nitelikler={"dns_kayit": "CNAME", "cname_adim": i + 1},
                    kaynak_yol=f"$.cname_zinciri[{i}]",
                    # takma ad → asıl ad. Gözlem asıl ad olduğu için "gelen".
                    iliskiler=(
                        ObservedRelation(
                            tip=RelationType.CNAME_FOR,
                            hedef_tip=EntityType.SUBDOMAIN,
                            hedef_deger=onceki,
                            yon="gelen",
                        ),
                    ),
                )
            )
            onceki = ad
        return cikti

    def _mx_ns(self, hedef: str, kayitlar: dict) -> list[Observation]:
        """MX / NS → SUBDOMAIN gözlemi + `mx_for` / `ns_for` ilişkisi.

        İkisi de "sub → domain" yönündedir; gözlem posta/isim sunucusu, hedef
        sorgulanan alan adıdır. Yön "giden": ingest takas YAPMAZ.
        """
        eslesme = (
            ("MX", RelationType.MX_FOR),
            ("NS", RelationType.NS_FOR),
        )
        cikti = []
        for tip, iliski in eslesme:
            for i, kayit in enumerate(self._degerler(kayitlar, tip)):
                parcalar = kayit.split()
                # MX: "10 mail.firma.com" · NS: "ns1.firma.com."
                sunucu = parcalar[-1].rstrip(".") if parcalar else ""
                if not sunucu:
                    continue
                nitelikler: dict[str, Any] = {"dns_kayit": tip}
                if tip == "MX" and len(parcalar) >= 2 and parcalar[0].isdigit():
                    nitelikler["mx_oncelik"] = int(parcalar[0])
                cikti.append(
                    Observation(
                        tip=EntityType.SUBDOMAIN,
                        deger_ham=sunucu,
                        nitelikler=nitelikler,
                        kaynak_yol=f"$.kayitlar.{tip}.veri[{i}]",
                        iliskiler=(
                            ObservedRelation(
                                tip=iliski,
                                hedef_tip=EntityType.DOMAIN,
                                hedef_deger=hedef,
                                yon="giden",
                            ),
                        ),
                    )
                )
        return cikti

    def _saglayici(self, hedef: str, kayitlar: dict) -> list[Observation]:
        """NS kayıtlarından DNS sağlayıcısını ORG olarak çıkarır.

        `ns1.cloudflare.com` → ORG `cloudflare`. Hedefin kendi kökü altındaki
        NS'ler atlanır (kendi DNS'ini kendi çalıştırıyor demektir, sağlayıcı
        bilgisi yok).

        İLİŞKİ KURULMAZ: `RelationType`'ta "barındırılıyor" karşılığı yok.
        `owned_by` yanlış olurdu — sağlayıcı hedefin sahibi değil. Bağ
        kurmaktansa bağsız ama DOĞRU bir varlık yazmak yeğdir; gerektiğinde
        ilişki tipi bilinçli olarak eklenir.
        """
        try:
            hedef_kok = kok_domain(hedef)
        except NormalizeError:
            hedef_kok = ""

        gorulen: set[str] = set()
        cikti = []
        for i, kayit in enumerate(self._degerler(kayitlar, "NS")):
            ns = kayit.split()[-1].rstrip(".") if kayit.split() else ""
            if not ns:
                continue
            try:
                kok = kok_domain(ns)
            except NormalizeError:
                continue
            if not kok or kok == hedef_kok or kok in gorulen:
                continue
            gorulen.add(kok)
            cikti.append(
                Observation(
                    tip=EntityType.ORG,
                    deger_ham=kok.split(".")[0],
                    nitelikler={"kaynak": "NS", "ns_kok": kok, "ns": ns},
                    kaynak_yol=f"$.kayitlar.NS.veri[{i}]",
                )
            )
        return cikti

    # -- SPF / DMARC -------------------------------------------------------- #

    def _posta_guvenligi(
        self, hedef: str, kayitlar: dict, dmarc: Any
    ) -> list[Observation]:
        """TXT → SPF + DMARC. Hedefin KENDİSİ için bir gözlem üretir.

        E-posta güvenliği bulguları hedefe ait niteliklerdir; ayrı bir varlık
        değildirler. Hafta 6'daki AI skorlaması bu YAPILANDIRILMIŞ alanları
        okuyacak, serbest metni değil.
        """
        nitelikler: dict[str, Any] = {"dns_kayit": "TXT"}
        cikti: list[Observation] = []

        txt = self._degerler(kayitlar, "TXT")
        spf = next((t for t in txt if self._govde(t).lower().startswith("v=spf1")), None)

        if spf is None:
            # KAYIT YOKLUĞU DA BİLGİDİR — sessizce atlanmaz.
            nitelikler["spf_yok"] = True
        else:
            nitelikler.update(self._spf_ayristir(self._govde(spf)))
            for saglayici in nitelikler.get("spf_include", []):
                # include: hangi posta sağlayıcısının yetkilendirildiğini
                # gösterir — TECH olarak yazılır ki korelasyonda kullanılabilsin.
                cikti.append(
                    Observation(
                        tip=EntityType.TECH,
                        deger_ham=f"spf-include:{saglayici}",
                        nitelikler={"kaynak": "SPF", "hedef": hedef},
                        kaynak_yol="$.kayitlar.TXT",
                    )
                )

        nitelikler.update(self._dmarc_ayristir(dmarc))

        caa = self._degerler(kayitlar, "CAA")
        nitelikler["caa_yok"] = not caa
        if caa:
            nitelikler["caa"] = caa
        soa = self._degerler(kayitlar, "SOA")
        if soa:
            nitelikler["soa"] = soa[0]

        cikti.append(
            Observation(
                tip=EntityType.SUBDOMAIN,
                deger_ham=hedef,
                nitelikler=nitelikler,
                kaynak_yol="$.kayitlar",
            )
        )
        return cikti

    @staticmethod
    def _govde(txt: str) -> str:
        """TXT kaydı tırnaklı gelir ve uzun kayıt parçalara bölünür.

        dnspython: '"v=spf1 ..." "...devam"'. Tırnaklar atılır, parçalar
        BOŞLUKSUZ birleştirilir — DNS'te 255 baytlık parçalar bitişiktir.
        """
        parcalar = [p for p in txt.split('" "')]
        return "".join(p.strip().strip('"') for p in parcalar)

    @staticmethod
    def _spf_ayristir(spf: str) -> dict[str, Any]:
        """v=spf1 kaydı → yapılandırılmış alanlar."""
        sonuc: dict[str, Any] = {"spf_yok": False, "spf_ham": spf}
        includes: list[str] = []
        ip4: list[str] = []
        ip6: list[str] = []

        for parca in spf.split():
            dusuk = parca.lower()
            if dusuk.startswith("include:"):
                includes.append(parca.split(":", 1)[1].rstrip("."))
            elif dusuk.startswith("ip4:"):
                ip4.append(parca.split(":", 1)[1])
            elif dusuk.startswith("ip6:"):
                ip6.append(parca.split(":", 1)[1])
            elif dusuk.endswith("all") and len(dusuk) <= 4:
                # ~all softfail · -all fail · ?all neutral · +all herkes
                sonuc["spf_all"] = dusuk
                # ?all ve +all ZAYIF yapılandırmadır: kimlik doğrulaması
                # olmayan gönderici reddedilmez. Hafta 6 bunu skorlayacak.
                sonuc["spf_zayif"] = dusuk in ("?all", "+all")

        sonuc["spf_include"] = includes
        # ip4/ip6 TECH ENTITY YAPILMAZ, nitelik olarak durur: bunlar bir
        # teknoloji değil, SPF kaydının verisidir. TECH'e çevirmek varlık
        # tablosunu teknoloji olmayan satırlarla şişirirdi.
        if ip4:
            sonuc["spf_ip4"] = ip4
        if ip6:
            sonuc["spf_ip6"] = ip6
        if "spf_all" not in sonuc:
            sonuc["spf_all"] = None
            sonuc["spf_zayif"] = True  # 'all' mekanizması hiç yok
        return sonuc

    @classmethod
    def _dmarc_ayristir(cls, dmarc: Any) -> dict[str, Any]:
        """_dmarc.<domain> TXT → politika alanları."""
        veri = (dmarc or {}).get("veri") if isinstance(dmarc, dict) else None
        kayitlar = [v for v in (veri or []) if isinstance(v, str)]
        ham = next(
            (k for k in kayitlar if cls._govde(k).lower().startswith("v=dmarc1")), None
        )
        if ham is None:
            return {"dmarc_yok": True}

        govde = cls._govde(ham)
        sonuc: dict[str, Any] = {"dmarc_yok": False, "dmarc_ham": govde}
        for parca in govde.split(";"):
            parca = parca.strip()
            if "=" not in parca:
                continue
            anahtar, _, deger = parca.partition("=")
            anahtar = anahtar.strip().lower()
            if anahtar in ("p", "sp", "pct", "rua", "ruf", "adkim", "aspf"):
                sonuc[f"dmarc_{anahtar}"] = deger.strip()
        # p=none izleme modudur, koruma sağlamaz.
        sonuc["dmarc_zayif"] = sonuc.get("dmarc_p", "none").lower() == "none"
        return sonuc

    def saglik(self) -> bool:
        """Anahtar gerektirmez; resolver erişimini runner doğrular."""
        return True
