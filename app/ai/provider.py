"""LLM sağlayıcı soyutlaması. Sağlayıcı değişimi YALNIZCA bu dosyayı etkiler.

`docs/kapsam.md` Bölüm 3.5. Gemini REST doğrudan `httpx` ile çağrılır; SDK
eklenmedi çünkü tek uç nokta kullanılıyor ve `httpx` zaten bağımlılıkta —
yeni bir bağımlılık, kendi sürüm ve hata davranışını da getirirdi.

ANAHTAR SIZINTISI
------------------------------------------------------------------
Anahtar `x-goog-api-key` BAŞLIĞINDA gider, URL'de DEĞİL: URL'ler proxy ve
sunucu loglarına düşer. Hiçbir istisna mesajına, log satırına veya ham arşive
yazılmaz; `HttpHatasi` yalnızca durum kodunu ve gövdenin kısaltılmış,
anahtardan arındırılmış hâlini taşır.
"""

from __future__ import annotations

import json
import os
from typing import Protocol

import httpx

GEMINI_UC = "https://generativelanguage.googleapis.com/v1beta/models"
VARSAYILAN_MODEL = "gemini-2.5-flash"

# Yanıt gövdesinden hata mesajına taşınacak azami karakter.
HATA_GOVDE = 300


class AiHatasi(Exception):
    """Sağlayıcı çağrısı başarısız. Anahtar ASLA mesajda geçmez."""

    def __init__(self, mesaj: str, *, gecici: bool = False):
        super().__init__(mesaj)
        self.gecici = gecici


class AiProvider(Protocol):
    """Skorlama motorunun sağlayıcıdan beklediği tek şey."""

    model: str

    def uret(self, sistem: str, kullanici: str, sema: dict) -> str:
        """JSON metni döndürür. Ayrıştırmaz, doğrulamaz — o `prompt.dogrula`nın işi."""
        ...


# --------------------------------------------------------------------------- #
# Gemini
# --------------------------------------------------------------------------- #


class GeminiProvider:
    def __init__(
        self,
        anahtar: str | None = None,
        model: str | None = None,
        *,
        timeout_sn: float = 120.0,
        proxy: str | None = None,
    ):
        self._anahtar = (anahtar if anahtar is not None else os.getenv("GEMINI_API_KEY", "")).strip()
        self.model = (model or os.getenv("GEMINI_MODEL") or VARSAYILAN_MODEL).strip()
        self.timeout_sn = timeout_sn
        self.proxy = proxy

    @property
    def hazir(self) -> bool:
        """Anahtar yoksa çağrı DENENMEZ; iş `skipped` olur, `failed` değil."""
        return bool(self._anahtar)

    def _temizle(self, metin: str) -> str:
        """Son savunma: anahtar bir şekilde gövdeye yansıdıysa maskele."""
        if self._anahtar and self._anahtar in metin:
            metin = metin.replace(self._anahtar, "***")
        return metin[:HATA_GOVDE]

    def uret(self, sistem: str, kullanici: str, sema: dict) -> str:
        if not self.hazir:
            raise AiHatasi("GEMINI_API_KEY tanımlı değil")

        govde = {
            "systemInstruction": {"parts": [{"text": sistem}]},
            "contents": [{"role": "user", "parts": [{"text": kullanici}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": sema,
                # Skorlama tekrar edilebilir olmalı: aynı girdi aynı çıktı.
                "temperature": 0.0,
            },
        }
        try:
            with httpx.Client(timeout=self.timeout_sn, proxy=self.proxy) as istemci:
                yanit = istemci.post(
                    f"{GEMINI_UC}/{self.model}:generateContent",
                    json=govde,
                    headers={
                        "x-goog-api-key": self._anahtar,
                        "content-type": "application/json",
                    },
                )
        except httpx.HTTPError as e:
            raise AiHatasi(f"taşıma hatası: {type(e).__name__}", gecici=True) from None

        if yanit.status_code != 200:
            gecici = yanit.status_code in (408, 429, 500, 502, 503, 504)
            raise AiHatasi(
                f"HTTP {yanit.status_code}: {self._temizle(yanit.text)}", gecici=gecici
            )

        try:
            veri = yanit.json()
            parcalar = veri["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parcalar)
        except (ValueError, KeyError, IndexError, TypeError):
            # Güvenlik filtresine takılmış ya da boş yanıt da buraya düşer.
            sebep = ""
            try:
                sebep = str(veri["candidates"][0].get("finishReason", ""))
            except Exception:  # noqa: BLE001
                pass
            raise AiHatasi(f"yanıt çözümlenemedi (finishReason={sebep or 'bilinmiyor'})") from None


# --------------------------------------------------------------------------- #
# Test sağlayıcısı
# --------------------------------------------------------------------------- #


class SahteProvider:
    """Testler için: ağa çıkmaz, verilen yanıtları sırayla döndürür.

    `cagrilar` listesi sayesinde test, modele NE GİTTİĞİNİ de doğrulayabilir —
    prompt injection savunmasının sınanması buna bağlıdır.
    """

    def __init__(self, yanitlar: list[str] | str, model: str = "sahte-model"):
        self.yanitlar = [yanitlar] if isinstance(yanitlar, str) else list(yanitlar)
        self.model = model
        self.cagrilar: list[tuple[str, str, dict]] = []

    def uret(self, sistem: str, kullanici: str, sema: dict) -> str:
        self.cagrilar.append((sistem, kullanici, sema))
        if not self.yanitlar:
            raise AiHatasi("sahte sağlayıcıda yanıt kalmadı")
        y = self.yanitlar.pop(0)
        if isinstance(y, Exception):
            raise y
        return y

    @staticmethod
    def yanit(skorlar: list[dict], hipotezler: list[dict] | None = None) -> str:
        return json.dumps(
            {"skorlar": skorlar, "hipotezler": hipotezler or []}, ensure_ascii=False
        )
