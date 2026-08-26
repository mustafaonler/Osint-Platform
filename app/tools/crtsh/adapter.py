"""crt.sh adapter — Sertifika Şeffaflık Logu (CT) sorgusu, P0.

Hedefe HİÇ dokunulmaz: sorgulanan üçüncü taraf bir veri kaynağıdır. Bir kurum
her yeni sertifika aldığında bu loglara düşer, dolayısıyla CT logları iç ağa
açılmış ama hiçbir yerde ilan edilmemiş alt alan adlarının en verimli pasif
kaynağıdır.

`calistirma: "api"` — container yok. crt.sh sorgusu tek bir HTTP isteğidir;
uğruna imaj inşa etmek anlamsızdır. Timeout, ham çıktı arşivi ve pasiflik
kontrolü yine RUNNER'ın işidir (`app/runner.py` → `ApiRunner`).
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

CRTSH_URL = "https://crt.sh/"


class CrtShAdapter:
    cikti_formati = "json"

    spec = ToolSpec(
        name="crtsh",
        version="1.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.SUBDOMAIN, EntityType.CERT}),
        calistirma="api",
        image=None,
        timeout_sn=45,
        dakikalik_istek=5,
        # CT logları OTORİTER kaynaktır: sertifika gerçekten verilmiştir,
        # tahmin veya scraping değildir (docs/veri-modeli.md 2.3).
        varsayilan_guven=90,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Tek HTTP isteği. Diske YAZMAZ, timeout'u KENDİ dayatmaz.

        `%.hedef` deseni hedefin altındaki tüm adları getirir. Sonuç JSON dizisi
        olarak döner.

        crt.sh SIK DÜŞER (502/504 gayet olağandır). Bu durumda istisna
        fırlatmak yerine gövdeyi olduğu gibi döndürüp `cikis_kodu`'na HTTP
        durumunu yazarız: runner işi `failed` işaretler, ham gövde yine
        arşivlenir ve "neden düştü" sorusu cevaplanabilir kalır (İlke 2).
        """
        try:
            y = httpx.get(
                CRTSH_URL,
                params={"q": f"%.{hedef}", "output": "json"},
                timeout=self.spec.timeout_sn,
                follow_redirects=True,
                proxy=cfg.proxy,
                headers={"User-Agent": "osint-platform/1.0 (+ekip ici arac)"},
            )
        except httpx.HTTPError as e:
            return RawResult(
                icerik=str(e).encode("utf-8"),
                format="text",
                cikis_kodu=-1,
                meta={"hata": type(e).__name__},
            )

        return RawResult(
            icerik=y.content,
            format="json",
            cikis_kodu=0 if y.status_code == 200 else y.status_code,
            meta={"http_durum": y.status_code},
        )

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """crt.sh JSON dizisi → gözlemler.

        SAF FONKSİYON: ağ yok, DB yok, dosya yok, saat okuma yok, rastgelelik yok.

        Kaydın yapısı (gerçek çıktıdan, `fixtures/sample_output.json`):
            {"issuer_name": "...", "common_name": "example.com",
             "name_value": "*.example.com\\nexample.com",
             "serial_number": "0624d0...", "not_before": ..., "not_after": ...}

        `name_value` ÇOK SATIRLIDIR — her satır ayrı bir isimdir. Ölçtük: 77
        kaydın 72'si çok satırlı, 44'ü wildcard içeriyor.

        Bozuk/eksik kayıtta İSTİSNA FIRLATMAZ, o kaydı atlar.
        """
        try:
            kayitlar = json.loads(ham.icerik.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # crt.sh 502 verdiğinde gövde HTML'dir, JSON değil. Turu düşürmeyiz.
            return []
        if not isinstance(kayitlar, list):
            return []

        cikti: list[Observation] = []
        for i, k in enumerate(kayitlar):
            if not isinstance(k, dict):
                continue
            cikti.extend(self._kaydi_ayristir(i, k))
        return cikti

    def _kaydi_ayristir(self, i: int, k: dict[str, Any]) -> list[Observation]:
        cikti: list[Observation] = []

        # 1) Sertifika kimliği. Yoksa CERT üretilmez ama isimler yine toplanır.
        seri = k.get("serial_number")
        seri = seri.strip() if isinstance(seri, str) and seri.strip() else None

        # 2) İsimler — her satır ayrı bir ad
        ham_adlar = k.get("name_value")
        adlar = (
            {a.strip() for a in ham_adlar.split("\n") if a.strip()}
            if isinstance(ham_adlar, str)
            else set()
        )
        ortak = k.get("common_name")
        if isinstance(ortak, str) and ortak.strip():
            adlar.add(ortak.strip())

        for ad in sorted(adlar):
            # HOSTNAME OLMAYAN DEĞERLER ATLANIR.
            # `common_name` her zaman bir DNS adı değildir: ara sertifika
            # otoritelerinde insan tarafından okunabilir bir etikettir. Canlı
            # crt.sh çağrısında ölçtük — gerçek örnek:
            #     'AS207960 Test Intermediate - example.com'
            # DNS etiketi boşluk içeremez, dolayısıyla bu ucuz sözdizimi
            # süzgeci yeterlidir ve normalize'in işini tekrarlamaz.
            #
            # Neden ingest'in WARNING'ine bırakılmıyor: bunlar BEKLENEN
            # kayıtlardır, anomali değil. Her CA sertifikası için uyarı
            # basmak, uyarı kanalını gürültüye boğar ve gerçek bozuklukların
            # görülmemesine yol açar.
            if any(c.isspace() for c in ad):
                continue
            # E-POSTA ATLANIR. crt.sh `name_value` içinde rfc822Name SAN'ları da
            # döner (ölçtük: 'subjectname@example.com'). Bunu SUBDOMAIN sanmak
            # tehlikelidir: normalize `@` öncesini kullanıcı bilgisi sayıp atar
            # ve 'example.com' üretir — yani var olmayan bir alt alan adı
            # gözlemi uydurulur. Bu tipi üretmediğimiz için (manifest: SUBDOMAIN
            # + CERT) kayıt atlanır; EMAIL üretmek istenirse manifest değişmeli.
            if "@" in ad:
                continue

            nitelikler: dict[str, Any] = {}
            if ad.startswith("*."):
                # Bölüm 3.1: wildcard anahtardan temizlenir, bilgisi niteliklerde
                # yaşar. Yoksa '*.firma.com' ile 'firma.com' ayrı entity olurdu.
                nitelikler["wildcard"] = True

            iliskiler: tuple[ObservedRelation, ...] = ()
            if seri:
                # Yön "gelen": ilişki CERT → SUBDOMAIN yönünde kurulur
                # (docs/veri-modeli.md 1: cert_for = cert → domain/sub).
                iliskiler = (
                    ObservedRelation(
                        tip=RelationType.CERT_FOR,
                        hedef_tip=EntityType.CERT,
                        hedef_deger=seri,
                        yon="gelen",
                    ),
                )

            cikti.append(
                Observation(
                    tip=EntityType.SUBDOMAIN,
                    deger_ham=ad,
                    nitelikler=nitelikler,
                    kaynak_yol=f"$[{i}].name_value",
                    iliskiler=iliskiler,
                )
            )

        # 3) Sertifikanın kendisi. Aynı sertifika birden çok kayıtta dönebilir;
        #    tekilleştirme ingest'in işidir (`uq_entity` + ON CONFLICT).
        if seri:
            cikti.append(
                Observation(
                    tip=EntityType.CERT,
                    deger_ham=seri,
                    kaynak_yol=f"$[{i}]",
                    nitelikler={
                        a: k[a]
                        for a in ("issuer_name", "not_before", "not_after", "id")
                        if k.get(a) is not None
                    },
                )
            )
        return cikti

    def saglik(self) -> bool:
        """Anahtar gerektirmez. crt.sh'ın ayakta olup olmadığı runner'ın işi."""
        return True
