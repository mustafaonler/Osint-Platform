"""subfinder adapter — pasif subdomain keşfi (P0).

`docs/kapsam.md` Bölüm 5.2: adapter yalnızca iki şey bilir — komut nasıl
kurulur, çıktı nasıl ayrıştırılır. Timeout, rate limit, retry, kota, diske
yazma ve pasiflik kontrolü RUNNER'ın işidir; burada geçmez.
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


class SubfinderAdapter:
    # Ham arşiv dosyasının uzantısı: subfinder JSONL üretir, tek bir JSON
    # belgesi değil. Yalnızca dosya adını etkiler, yetenek grafiğini değil.
    cikti_formati = "jsonl"

    spec = ToolSpec(
        name="subfinder",
        version="2.14.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.SUBDOMAIN}),
        calistirma="docker",
        image="osint-subfinder:1.0",
        auth_env=("SUBFINDER_API_KEYS",),
        timeout_sn=120,
        dakikalik_istek=5,
        varsayilan_guven=70,
    )

    # -- çalıştırma --------------------------------------------------------- #

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Bu adapter container'da koşar: komutu KURAR, çalıştırmaz.

        Runner `komut()` çıktısını alıp container'ı ayağa kaldırır ve
        `RawResult`'ı kendisi üretir. `calistirma="docker"` olan tool'larda bu
        yöntem doğrudan çağrılmaz; sözleşmeyi tamamlamak için burada durur ve
        yanlışlıkla çağrılırsa sessizce boş dönmek yerine bağırır.
        """
        raise NotImplementedError(
            "subfinder container'da koşar; runner `komut()` kullanır"
        )

    @staticmethod
    def komut(hedef: str) -> list[str]:
        """Container'a geçirilecek argümanlar (ENTRYPOINT zaten `subfinder`).

        `-silent`  : banner ve ilerleme çıktısı stdout'u kirletmesin — stdout
                     saf JSONL olmalı ki `parse()` satır satır okuyabilsin.
        `-json`    : satır başına bir JSON nesnesi (JSONL).
        `-all`/`-brute` KULLANILMAZ: brute-force Seviye A'dır, kapsam dışı.
        """
        return ["-d", hedef, "-silent", "-json"]

    # -- ayrıştırma --------------------------------------------------------- #

    def parse(self, ham: RawResult) -> list[Observation]:
        """JSONL → gözlemler.

        SAF FONKSİYON: ağ yok, DB yok, dosya yok, saat okuma yok, rastgelelik
        yok. Bu yüzden `fixtures/sample_output.jsonl` ile tek başına test
        edilebilir; subfinder'ın çıktı formatı sessizce değişirse test kırılır.

        Bozuk satırda İSTİSNA FIRLATMAZ. Gerekçe: 500 satırlık bir çıktının
        300. satırı yarım kalmışsa (timeout, kesilmiş stdout), o tek satır
        yüzünden diğer 499 bulguyu çöpe atmak veri kaybıdır. Bozuk satır
        atlanır, kalanı ayrıştırılır.
        """
        cikti: list[Observation] = []
        metin = ham.icerik.decode("utf-8", errors="replace")

        for i, satir in enumerate(metin.splitlines()):
            satir = satir.strip()
            if not satir:
                continue
            try:
                kayit = json.loads(satir)
            except json.JSONDecodeError:
                continue  # yarım/bozuk satır — atla, turu düşürme
            if not isinstance(kayit, dict):
                continue

            host = kayit.get("host")
            if not isinstance(host, str) or not host.strip():
                continue

            kok = kayit.get("input")
            nitelikler: dict[str, Any] = {}
            if isinstance(kayit.get("source"), str):
                # Hangi alt kaynaktan geldiği; aramada kullanılmaz, JSONB'de durur.
                nitelikler["subfinder_kaynak"] = kayit["source"]

            # İlişki DEĞERLE ifade edilir, ID ile değil — parser DB'yi tanımaz.
            iliskiler: tuple[ObservedRelation, ...] = ()
            if isinstance(kok, str) and kok.strip() and kok.strip() != host.strip():
                iliskiler = (
                    ObservedRelation(
                        tip=RelationType.SUBDOMAIN_OF,
                        hedef_tip=EntityType.DOMAIN,
                        hedef_deger=kok.strip(),
                    ),
                )

            cikti.append(
                Observation(
                    tip=EntityType.SUBDOMAIN,
                    deger_ham=host.strip(),
                    nitelikler=nitelikler,
                    kaynak_yol=f"$[{i}].host",  # JSONL'de satır numarası
                    iliskiler=iliskiler,
                )
            )

        return cikti

    def saglik(self) -> bool:
        """Anahtar gerektirmez; imajın varlığını runner doğrular."""
        return True
