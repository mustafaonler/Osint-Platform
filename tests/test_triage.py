from types import SimpleNamespace
from uuid import UUID

import pytest

from app.triage import GRUPLAR, ISARETLER, KAYNAK_ESIKLERI, degerlendir
from app.triage_query import VarlikSatiri, sayfala


@pytest.mark.parametrize("tip", KAYNAK_ESIKLERI)
def test_tip_esigi_ve_sifir_kaynak(tip):
    esik = KAYNAK_ESIKLERI[tip]
    assert degerlendir(tip, 0, True).grup == ("sertifika" if tip == "cert" else "incele")
    assert degerlendir(tip, esik, True).grup == ("sertifika" if tip == "cert" else "oncelikli")


def test_tek_kaynak_global_esikle_elenmez():
    assert degerlendir("ip", 1, True).grup == "oncelikli"
    assert degerlendir("subdomain", 1, True).grup == "incele"
    assert degerlendir("netblock", 1, True).grup == "incele"


@pytest.mark.parametrize("isaret", ISARETLER)
def test_saglayici_isaretleri_ve_kok_istisnasi(isaret):
    assert degerlendir("asn", 4, True, frozenset({isaret})).grup == "baglam"
    assert degerlendir("domain", 0, False, frozenset({isaret}), kok=True).grup == "oncelikli"


def test_yetimlik_ve_sertifika_sirasi():
    assert degerlendir("ip", 3, False).grup == "incele"
    assert degerlendir("cert", 20, True).sira > degerlendir("ip", 0, False).sira


def test_sayfalama_ve_gruplar_hicbir_varligi_kaybetmez():
    satirlar = [VarlikSatiri(
        SimpleNamespace(id=UUID(int=i)), (),
        degerlendir("cert" if i % 2 else "ip", 1, True),
    ) for i in range(251)]
    gorulen = []
    for sayfa in range(1, 4):
        sonuc = sayfala(satirlar, "tumu", sayfa)
        assert sum(sonuc["sayim"].values()) == sonuc["toplam"] == 251
        gorulen.extend(s.entity.id for s in sonuc["satirlar"])
    assert len(gorulen) == len(set(gorulen)) == 251
    assert sayfala(satirlar, "tumu", 999)["sayfa"] == 3
    assert sayfala([], "tumu", 1)["sayfa_sayisi"] == 1
    assert sum(sayfala(satirlar, g, 1)["secilen_sayisi"] for g in GRUPLAR) == 251
