"""Gemini sağlayıcısı — ağa ÇIKMAZ, `httpx` taşıyıcısı sahte.

En kritik test: API anahtarı hiçbir yere sızmamalı. URL'ye, log'a, istisna
mesajına, ham arşive. `shodan-lookup`'ta aynı kural uygulanmıştı.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.ai.prompt import SEMA
from app.ai.provider import AiHatasi, GeminiProvider, SahteProvider

ANAHTAR = "AIzaSyTEST-cok-gizli-anahtar-123456"


@pytest.fixture(autouse=True)
def _client_yamasi(monkeypatch):
    """`provider.uret` içindeki `httpx.Client`'ı testin fabrikasına yönlendirir."""
    import app.ai.provider as modul

    gercek = httpx.Client
    kutu = {}

    def sarmalayici(*a, **k):
        if "handler" in kutu:
            k.pop("proxy", None)
            k["transport"] = httpx.MockTransport(kutu["handler"])
        return gercek(*a, **k)

    monkeypatch.setattr(modul.httpx, "Client", sarmalayici)
    return kutu


def _yanit_govdesi(metin: str) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": metin}]}}]}


# --------------------------------------------------------------------------- #
# ANAHTAR SIZINTISI
# --------------------------------------------------------------------------- #


def test_anahtar_url_de_degil_baslikta_gider(_client_yamasi):
    gorulen = {}

    def handler(istek: httpx.Request) -> httpx.Response:
        gorulen["url"] = str(istek.url)
        gorulen["basliklar"] = dict(istek.headers)
        return httpx.Response(200, json=_yanit_govdesi('{"skorlar":[],"hipotezler":[]}'))

    _client_yamasi["handler"] = handler
    GeminiProvider(anahtar=ANAHTAR, model="test-model").uret("s", "k", SEMA)

    assert ANAHTAR not in gorulen["url"], "ANAHTAR URL'DE — proxy loglarına düşer"
    assert gorulen["basliklar"]["x-goog-api-key"] == ANAHTAR


def test_anahtar_hata_mesajinda_maskelenir(_client_yamasi):
    """Sunucu anahtarı yankılasa bile istisnaya taşınmamalı."""
    def handler(istek):
        return httpx.Response(400, text=f"invalid key: {ANAHTAR} rejected")

    _client_yamasi["handler"] = handler
    with pytest.raises(AiHatasi) as hata:
        GeminiProvider(anahtar=ANAHTAR, model="test-model").uret("s", "k", SEMA)

    assert ANAHTAR not in str(hata.value)
    assert "***" in str(hata.value)


def test_tasima_hatasinda_anahtar_gecmez(_client_yamasi):
    def handler(istek):
        raise httpx.ConnectError("bağlanamadı")

    _client_yamasi["handler"] = handler
    with pytest.raises(AiHatasi) as hata:
        GeminiProvider(anahtar=ANAHTAR, model="test-model").uret("s", "k", SEMA)
    assert ANAHTAR not in str(hata.value)
    assert hata.value.gecici is True


# --------------------------------------------------------------------------- #
# Yapılandırma
# --------------------------------------------------------------------------- #


def test_anahtar_yoksa_hazir_degil(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    p = GeminiProvider(anahtar="")
    assert p.hazir is False
    with pytest.raises(AiHatasi):
        p.uret("s", "k", SEMA)


def test_bos_anahtar_ortamdan_da_okunur(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "  ortamdan  ")
    assert GeminiProvider().hazir is True


def test_varsayilan_model(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert GeminiProvider(anahtar="x").model == "gemini-2.5-flash"


# --------------------------------------------------------------------------- #
# İstek gövdesi ve yanıt
# --------------------------------------------------------------------------- #


def test_structured_output_ve_sifir_sicaklik(_client_yamasi):
    gorulen = {}

    def handler(istek):
        gorulen["govde"] = json.loads(istek.content)
        return httpx.Response(200, json=_yanit_govdesi("{}"))

    _client_yamasi["handler"] = handler
    GeminiProvider(anahtar=ANAHTAR, model="test-model").uret("sistem", "kullanici", SEMA)

    cfg = gorulen["govde"]["generationConfig"]
    assert cfg["responseMimeType"] == "application/json"
    assert cfg["responseSchema"] == SEMA
    assert cfg["temperature"] == 0.0  # skorlama tekrar edilebilir olmalı
    assert gorulen["govde"]["systemInstruction"]["parts"][0]["text"] == "sistem"


@pytest.mark.parametrize(
    "kod,gecici",
    [(429, True), (503, True), (500, True), (400, False), (401, False), (403, False)],
)
def test_gecici_kalici_hata_ayrimi(_client_yamasi, kod, gecici):
    _client_yamasi["handler"] = lambda i: httpx.Response(kod, text="hata")
    with pytest.raises(AiHatasi) as h:
        GeminiProvider(anahtar=ANAHTAR, model="t").uret("s", "k", SEMA)
    assert h.value.gecici is gecici


def test_guvenlik_filtresi_bos_yaniti_hata_olur(_client_yamasi):
    """Gemini içeriği bloklarsa `parts` gelmez; sessizce boş dönmemeli."""
    _client_yamasi["handler"] = lambda i: httpx.Response(
        200, json={"candidates": [{"finishReason": "SAFETY"}]}
    )
    with pytest.raises(AiHatasi) as h:
        GeminiProvider(anahtar=ANAHTAR, model="t").uret("s", "k", SEMA)
    assert "SAFETY" in str(h.value)


def test_cok_parcali_yanit_birlestirilir(_client_yamasi):
    _client_yamasi["handler"] = lambda i: httpx.Response(
        200,
        json={"candidates": [{"content": {"parts": [{"text": '{"a":'}, {"text": "1}"}]}}]},
    )
    assert GeminiProvider(anahtar=ANAHTAR, model="t").uret("s", "k", SEMA) == '{"a":1}'


# --------------------------------------------------------------------------- #
# Sahte sağlayıcı
# --------------------------------------------------------------------------- #


def test_sahte_saglayici_cagrilari_kaydeder():
    p = SahteProvider([SahteProvider.yanit([{"id": "v1", "skor": 5, "gerekce": "x"}])])
    p.uret("sistem", "kullanici", SEMA)
    assert p.cagrilar[0][0] == "sistem"
    with pytest.raises(AiHatasi):
        p.uret("s", "k", SEMA)  # yanıt kalmadı
