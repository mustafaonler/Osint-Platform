"""Retry, geri çekilme ve hız sınırı — HİÇBİRİ AĞA ÇIKMAZ.

Sahte adapter'lar kullanılır: bu testler crt.sh'ın o anki keyfine bağlı
olmamalıdır. Gerçek servise bağlı bir test, servis düştüğünde "kod bozuk mu,
sunucu mu düştü" sorusunu cevaplayamaz hâle gelir.

Süreler ÖLÇÜLÜR, sabit uykuya güvenilmez: `geri_cekilme_sn` küçük değerlere
ayarlanır ve geçen süre gerçekten kronometreyle doğrulanır.
"""

from __future__ import annotations

import time
import uuid

import pytest

from app.models import JobStatus
from app.normalize import EntityType
from app.runner import (
    GECICI_KODLAR,
    KALICI_KODLAR,
    ApiRunner,
    HizSinirlayici,
    RunnerConfig,
    ToolRunner,
    gecici_mi,
)
from app.tools._base import Passivity, RawResult, ToolSpec


def _spec(**kw) -> ToolSpec:
    """Hızlı testler için küçük geri çekilme; jitter ayrı test ediliyor."""
    varsayilan = dict(
        name="sahte",
        version="1.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.SUBDOMAIN}),
        calistirma="api",
        image=None,
        timeout_sn=5,
        max_deneme=3,
        geri_cekilme_sn=0.05,
        dakikalik_istek=None,
    )
    varsayilan.update(kw)
    return ToolSpec(**varsayilan)


class _SahteSunucu:
    """Sırayla verilen cevapları döndüren adapter. Ağ YOK."""

    cikti_formati = "json"

    def __init__(self, cevaplar, spec=None):
        # cevaplar: [(cikis_kodu, govde) | Exception | float(gecikme)]
        self.cevaplar = list(cevaplar)
        self.spec = spec or _spec()
        self.cagrilar: list[float] = []

    def calistir(self, hedef, cfg):
        self.cagrilar.append(time.monotonic())
        c = self.cevaplar[min(len(self.cagrilar) - 1, len(self.cevaplar) - 1)]
        if isinstance(c, Exception):
            raise c
        if isinstance(c, float):  # yavaş cevap — timeout tetiklesin
            time.sleep(c)
            return RawResult(icerik=b"gec", format="json", cikis_kodu=0)
        kod, govde = c
        return RawResult(icerik=govde, format="json", cikis_kodu=kod)

    def parse(self, ham):
        return []


@pytest.fixture
def kosucu(tmp_path):
    # jitter_orani=0.0 → süreler ölçülebilir olsun
    return ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))


# --------------------------------------------------------------------------- #
# Sınıflandırma
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("kod", sorted(GECICI_KODLAR))
def test_gecici_kodlar_tekrar_denenir(kod):
    assert gecici_mi(kod, JobStatus.FAILED) is True


@pytest.mark.parametrize("kod", sorted(KALICI_KODLAR))
def test_kalici_kodlar_tekrar_denenmez(kod):
    assert gecici_mi(kod, JobStatus.FAILED) is False


def test_bilinmeyen_kod_kalici_sayilir():
    """Şüphede kalınca hammering YAPILMAZ — pasiflik ilkesiyle tutarlı."""
    assert gecici_mi(418, JobStatus.FAILED) is False
    assert gecici_mi(999, JobStatus.FAILED) is False


def test_timeout_gecici_basari_degil():
    assert gecici_mi(None, JobStatus.TIMEOUT) is True
    assert gecici_mi(0, JobStatus.SUCCESS) is False


# --------------------------------------------------------------------------- #
# Retry davranışı
# --------------------------------------------------------------------------- #


def test_502_uc_kez_denenir(kosucu):
    a = _SahteSunucu([(502, b"<html>502</html>")])
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())

    assert len(a.cagrilar) == 3, "3 deneme yapılmadı"
    assert s.durum is JobStatus.FAILED
    assert s.deneme == 3
    assert s.cikis_kodu == 502


def test_404_tek_deneme(kosucu):
    """Kalıcı hatada boşuna uğraşılmaz."""
    a = _SahteSunucu([(404, b"yok")])
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())

    assert len(a.cagrilar) == 1, "kalıcı hatada tekrar denendi"
    assert s.deneme == 1
    assert s.cikis_kodu == 404


def test_ikinci_denemede_duzelen_servis(kosucu):
    """crt.sh'ın gerçek davranışı: 502 sonra 200."""
    a = _SahteSunucu([(502, b"kotu"), (0, b'[{"ok":1}]')])
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())

    assert len(a.cagrilar) == 2
    assert s.durum is JobStatus.SUCCESS
    assert s.deneme == 2
    assert s.ham.icerik == b'[{"ok":1}]'


def test_basarili_denemede_gereksiz_bekleme_yok(kosucu):
    """İlk deneme tutarsa hiç uyunmamalı."""
    a = _SahteSunucu([(0, b"tamam")], spec=_spec(geri_cekilme_sn=5.0))
    basla = time.monotonic()
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())
    gecen = time.monotonic() - basla

    assert s.durum is JobStatus.SUCCESS
    assert s.deneme == 1
    assert gecen < 0.5, f"başarılı çağrıda {gecen:.2f} sn beklendi"


def test_istisna_da_tekrar_denenir(kosucu):
    """Adapter patlarsa taşıma hatası sayılır (cikis_kodu=-1 muadili)."""
    a = _SahteSunucu([ConnectionError("baglanti koptu")])
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())

    assert len(a.cagrilar) == 3
    assert s.durum is JobStatus.FAILED


def test_yetki_engelinde_hic_denenmez(tmp_path):
    """SKIPPED tekrar denenmez; sayaç da artmaz çünkü hiç denenmedi."""
    a = _SahteSunucu(
        [(0, b"x")], spec=_spec(passivity=Passivity.P2, calistirma="api", image=None)
    )
    s = ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0)).calistir(
        a, "firma.com", uuid.uuid4(), yetki_onayi=False
    )

    assert s.durum is JobStatus.SKIPPED
    assert a.cagrilar == []
    assert s.deneme == 1  # varsayılan; hiç deneme yapılmadı


def test_max_deneme_bire_dusurulebilir(kosucu):
    a = _SahteSunucu([(503, b"x")], spec=_spec(max_deneme=1))
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())
    assert len(a.cagrilar) == 1
    assert s.deneme == 1


# --------------------------------------------------------------------------- #
# Geri çekilme süreleri — ÖLÇÜLÜR
# --------------------------------------------------------------------------- #


def test_ustel_geri_cekilme_hesabi():
    """Saf hesap: 2, 4, 8."""
    s = _spec(geri_cekilme_sn=2.0)
    assert [s.geri_cekilme(d) for d in (1, 2, 3)] == [2.0, 4.0, 8.0]


def test_geri_cekilme_gercekten_bekletiyor(kosucu):
    """Denemeler ARASINDAKİ süreler ölçülür, sabit uykuya güvenilmez."""
    a = _SahteSunucu([(502, b"x")], spec=_spec(geri_cekilme_sn=0.2, max_deneme=3))
    kosucu.calistir(a, "firma.com", uuid.uuid4())

    assert len(a.cagrilar) == 3
    ara1 = a.cagrilar[1] - a.cagrilar[0]
    ara2 = a.cagrilar[2] - a.cagrilar[1]

    assert ara1 >= 0.2, f"1. bekleme kısa: {ara1:.3f}"
    assert ara2 >= 0.4, f"2. bekleme kısa: {ara2:.3f}"
    # Üstel: ikinci bekleme birincinin ~2 katı
    assert ara2 > ara1 * 1.5, f"üstel değil: {ara1:.3f} -> {ara2:.3f}"


def test_jitter_sureyi_dagitiyor(tmp_path):
    """Aynı anda kuyruğa giren işler senkronize vurmasın."""
    kosucu = ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.5))
    s = _spec(geri_cekilme_sn=4.0)
    gecikmeler = {round(kosucu._gecikme(s, 1), 4) for _ in range(30)}

    assert len(gecikmeler) > 20, "jitter uygulanmıyor, süreler aynı"
    assert all(2.0 <= g <= 6.0 for g in gecikmeler), f"aralık dışı: {gecikmeler}"


def test_jitter_kapatilinca_deterministik(tmp_path):
    kosucu = ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))
    s = _spec(geri_cekilme_sn=3.0)
    assert {kosucu._gecikme(s, 2) for _ in range(10)} == {6.0}


# --------------------------------------------------------------------------- #
# Toplam bütçe — retry ile timeout etkileşimi
# --------------------------------------------------------------------------- #


def test_toplam_butce_hesabi():
    """`timeout_sn` TEK DENEME içindir; bütçe tüm denemelerin tavanıdır."""
    s = _spec(timeout_sn=45, max_deneme=3, geri_cekilme_sn=2.0)
    # 3 x 45 + (2 + 4) = 141
    assert s.toplam_butce_sn() == 141.0
    # max_deneme=1 → yalnızca tek timeout, bekleme yok
    assert _spec(timeout_sn=45, max_deneme=1).toplam_butce_sn() == 45.0


def test_timeout_tek_deneme_icin_gecerli(kosucu):
    """Retry açıkken de her çağrı TAM `timeout_sn` kadar süre alır.

    Toplam sayılsaydı etkin süre 5/3 = 1.6 sn'ye düşerdi ve 2 sn süren meşru
    bir sorgu retry yüzünden kırılmaya başlardı — sessiz tuzak tam olarak budur.
    """
    a = _SahteSunucu([1.0], spec=_spec(timeout_sn=3, max_deneme=2))
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())

    # 1 sn süren çağrı, 3 sn'lik timeout içinde rahat bitmeli
    assert s.durum is JobStatus.SUCCESS
    assert s.deneme == 1


def test_butce_dolunca_retry_durur(kosucu):
    """Kalan bütçe bir denemeyi daha almıyorsa yeniden denenmez.

    Kuyrukta bekleyen işler, düşmüş bir servis yüzünden süresiz beklemez.
    """
    # timeout 1 sn, her çağrı 1 sn sürüp TIMEOUT olacak, bütçe 2 deneme alır
    a = _SahteSunucu([5.0], spec=_spec(timeout_sn=1, max_deneme=5, geri_cekilme_sn=0.1))
    basla = time.monotonic()
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())
    gecen = time.monotonic() - basla

    butce = a.spec.toplam_butce_sn()
    assert s.durum is JobStatus.TIMEOUT
    assert len(a.cagrilar) <= 5
    assert gecen <= butce + 1.5, f"bütçe {butce:.1f} sn aşıldı: {gecen:.1f} sn"


def test_timeout_da_tekrar_denenir(kosucu):
    """Yavaş sunucu hızlanabilir; TIMEOUT geçici sayılır."""
    a = _SahteSunucu([2.0], spec=_spec(timeout_sn=1, max_deneme=2, geri_cekilme_sn=0.05))
    s = kosucu.calistir(a, "firma.com", uuid.uuid4())
    assert len(a.cagrilar) == 2
    assert s.durum is JobStatus.TIMEOUT
    assert s.deneme == 2


# --------------------------------------------------------------------------- #
# Hız sınırı
# --------------------------------------------------------------------------- #


def test_hiz_sinirlayici_bekletiyor():
    """5/dk → istekler arasında en az 12 sn."""
    h = HizSinirlayici()
    assert h.bekleme_suresi("crtsh", 5) == 0.0  # ilk istek beklemez
    ikinci = h.bekleme_suresi("crtsh", 5)
    assert 11.0 < ikinci <= 12.0, f"beklenen ~12 sn, gelen {ikinci}"
    ucuncu = h.bekleme_suresi("crtsh", 5)
    assert ucuncu > ikinci, "sıra rezerve edilmiyor, istekler üst üste biner"


def test_hiz_siniri_tool_basina():
    """Bir tool'un beklemesi diğerini bloklamaz."""
    h = HizSinirlayici()
    h.bekleme_suresi("crtsh", 5)
    h.bekleme_suresi("crtsh", 5)
    assert h.bekleme_suresi("subfinder", 5) == 0.0


def test_hiz_siniri_yoksa_beklenmez():
    h = HizSinirlayici()
    for _ in range(5):
        assert h.bekleme_suresi("sinirsiz", None) == 0.0
    assert h.bekleme_suresi("sinirsiz", 0) == 0.0


def test_hiz_siniri_gercekten_uyutuyor(tmp_path):
    """Runner içinde ölçülür: 60/dk → 1 sn ara."""
    kosucu = ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))
    a = _SahteSunucu([(0, b"x")], spec=_spec(dakikalik_istek=60, max_deneme=1))

    kosucu.calistir(a, "firma.com", uuid.uuid4())  # ilk: beklemesiz
    basla = time.monotonic()
    kosucu.calistir(a, "firma.com", uuid.uuid4())  # ikinci: ~1 sn beklemeli
    gecen = time.monotonic() - basla

    assert gecen >= 0.9, f"hız sınırı uygulanmadı: {gecen:.2f} sn"


def test_retry_de_hiz_sinirina_tabi(tmp_path):
    """Retry'ın kendisi de bir istektir: 429 yiyip hemen vurmak yasak."""
    kosucu = ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))
    a = _SahteSunucu(
        [(429, b"cok istek")],
        spec=_spec(dakikalik_istek=60, max_deneme=2, geri_cekilme_sn=0.05),
    )
    kosucu.calistir(a, "firma.com", uuid.uuid4())

    assert len(a.cagrilar) == 2
    ara = a.cagrilar[1] - a.cagrilar[0]
    assert ara >= 0.9, f"retry hız sınırını atladı: {ara:.2f} sn"


# --------------------------------------------------------------------------- #
# Docker yolunda retry YOK
# --------------------------------------------------------------------------- #


def test_docker_yolunda_retry_yok(tmp_path, monkeypatch):
    """Container çıkış kodları sınıflandırılamaz — kör tekrar pahalıdır."""
    from app.runner import ContainerRunner

    cagri = {"n": 0}

    def _sahte_container(self, spec, hedef, job_id, komut, cikti_formati):
        cagri["n"] += 1
        return __import__("app.runner", fromlist=["RunSonucu"]).RunSonucu(
            durum=JobStatus.FAILED, cikis_kodu=502, deneme=1
        )

    monkeypatch.setattr(ContainerRunner, "_container_calistir", _sahte_container)

    class _DockerAdapter:
        spec = _spec(calistirma="docker", image="sahte:1")

        def parse(self, ham):
            return []

    r = ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))
    s = r.calistir(_DockerAdapter(), "firma.com", uuid.uuid4())

    assert cagri["n"] == 1, "docker yolunda tekrar denendi"
    assert s.durum is JobStatus.FAILED


def test_docker_yolunda_hiz_siniri_var(tmp_path, monkeypatch):
    """Nazik davranma borcu çalıştırma biçimine göre değişmez."""
    from app.runner import ContainerRunner, RunSonucu

    monkeypatch.setattr(
        ContainerRunner,
        "_container_calistir",
        lambda self, spec, hedef, job_id, komut, bicim: RunSonucu(
            durum=JobStatus.SUCCESS, cikis_kodu=0
        ),
    )

    class _DockerAdapter:
        spec = _spec(calistirma="docker", image="sahte:1", dakikalik_istek=60)

        def parse(self, ham):
            return []

    r = ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw", jitter_orani=0.0))
    a = _DockerAdapter()
    r.calistir(a, "firma.com", uuid.uuid4())
    basla = time.monotonic()
    r.calistir(a, "firma.com", uuid.uuid4())
    assert time.monotonic() - basla >= 0.9


def test_iki_yol_ayni_hiz_sinirlayiciyi_paylasir(tmp_path):
    r = ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw"))
    assert r.api._hiz is r.container._hiz is r.hiz


# --------------------------------------------------------------------------- #
# Manifest ile spec tutarlılığı
# --------------------------------------------------------------------------- #


def test_manifest_retry_yazmak_zorunda_degil(tmp_path):
    """Varsayılanlar makul; her manifest retry ayarı yazmaz."""
    from app.tools._base import ToolRegistry

    d = tmp_path / "sade"
    (d / "fixtures").mkdir(parents=True)
    (d / "fixtures" / "x.json").write_text("{}")
    (d / "manifest.yaml").write_text(
        "name: sade\nversion: '1.0'\npassivity: P0\n"
        "kabul_eder: [DOMAIN]\nuretir: [SUBDOMAIN]\ncalistirma: api\n",
        encoding="utf-8",
    )
    (d / "adapter.py").write_text(
        "from app.normalize import EntityType\n"
        "from app.tools._base import Passivity, ToolSpec\n"
        "class A:\n"
        "    spec = ToolSpec(name='sade', version='1.0', passivity=Passivity.P0,\n"
        "        kabul_eder=frozenset({EntityType.DOMAIN}),\n"
        "        uretir=frozenset({EntityType.SUBDOMAIN}), calistirma='api')\n"
        "    def parse(self, ham): return []\n",
        encoding="utf-8",
    )
    a = ToolRegistry(tmp_path).get("sade")
    assert a is not None
    assert a.spec.max_deneme == 3
    assert a.spec.geri_cekilme_sn == 2.0


def test_manifest_retry_kaymasi_hata_verir(tmp_path):
    """Yazılmışsa tutmalı — sessiz kayma iki doğruluk kaynağının tuzağıdır."""
    from app.tools._base import ToolRegistry, ToolYuklemeHatasi

    d = tmp_path / "kayan"
    (d / "fixtures").mkdir(parents=True)
    (d / "fixtures" / "x.json").write_text("{}")
    (d / "manifest.yaml").write_text(
        "name: kayan\nversion: '1.0'\npassivity: P0\n"
        "kabul_eder: [DOMAIN]\nuretir: [SUBDOMAIN]\ncalistirma: api\n"
        "limitler:\n  max_deneme: 9\n",
        encoding="utf-8",
    )
    (d / "adapter.py").write_text(
        "from app.normalize import EntityType\n"
        "from app.tools._base import Passivity, ToolSpec\n"
        "class A:\n"
        "    spec = ToolSpec(name='kayan', version='1.0', passivity=Passivity.P0,\n"
        "        kabul_eder=frozenset({EntityType.DOMAIN}),\n"
        "        uretir=frozenset({EntityType.SUBDOMAIN}), calistirma='api')\n"
        "    def parse(self, ham): return []\n",
        encoding="utf-8",
    )
    with pytest.raises(ToolYuklemeHatasi, match="max_deneme"):
        ToolRegistry(tmp_path)
