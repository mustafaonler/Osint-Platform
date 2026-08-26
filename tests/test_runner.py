"""`ContainerRunner` — GERÇEK Docker'a karşı, mock YOK.

Bu testlerin konusu güvenlik sınırının kendisi: read_only, root olmama, ağ
izolasyonu, timeout'ta container'ın gerçekten ölmesi. Bunların hiçbiri mock'la
doğrulanamaz — mock yalnızca "doğru bayrağı geçirdim" der, "bayrak işe yaradı"
demez. Aradaki fark bu dosyanın var olma sebebidir.

Docker Desktop ayakta olmalı. Değilse tüm dosya atlanır.
"""

from __future__ import annotations

import uuid

import docker
import pytest
from docker.errors import DockerException

from app.models import JobStatus
from app.runner import GUVENLIK_BAYRAKLARI, ContainerRunner, RunnerConfig
from app.tools._base import Passivity, RawResult, ToolSpec
from app.normalize import EntityType

ALPINE = "alpine:3.20"


# --------------------------------------------------------------------------- #
# Fixture'lar
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def client():
    try:
        c = docker.from_env()
        c.ping()
    except DockerException as e:
        pytest.skip(f"Docker'a baglanilamadi (Docker Desktop kapali olabilir): {e}")
    try:
        c.images.get(ALPINE)
    except docker.errors.ImageNotFound:
        c.images.pull(ALPINE)
    return c


@pytest.fixture
def runner(client, tmp_path):
    """Her test kendi ham çıktı klasörüne yazar; repo kirletilmez."""
    return ContainerRunner(RunnerConfig(raw_kok=tmp_path / "raw"), client=client)


def _spec(
    *,
    ad: str = "test-tool",
    passivity: Passivity = Passivity.P0,
    timeout_sn: int = 60,
    image: str | None = ALPINE,
    etkin: bool = True,
    calistirma: str = "docker",
    auth_env: tuple[str, ...] = (),
) -> ToolSpec:
    return ToolSpec(
        name=ad,
        version="1.0",
        passivity=passivity,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.SUBDOMAIN}),
        calistirma=calistirma,
        image=image,
        auth_env=auth_env,
        timeout_sn=timeout_sn,
        etkin=etkin,
    )


def _container_sayisi(client) -> int:
    return len(client.containers.list(all=True))


# --------------------------------------------------------------------------- #
# Temel çalıştırma
# --------------------------------------------------------------------------- #


def test_basit_calistirma_cikti_yakalanir(runner):
    job_id = uuid.uuid4()
    s = runner.calistir(
        _spec(), "firma.com", job_id, komut=["echo", "merhaba-dunya"]
    )

    assert s.durum is JobStatus.SUCCESS
    assert s.cikis_kodu == 0
    assert b"merhaba-dunya" in s.ham.icerik
    assert s.sure_ms > 0


def test_ham_cikti_diske_yazilir(runner, tmp_path):
    """İlke 2: her bulgu ham çıktısına kadar izlenebilir olmalı."""
    job_id = uuid.uuid4()
    s = runner.calistir(_spec(), "firma.com", job_id, komut=["echo", "kanit"])

    beklenen = tmp_path / "raw" / str(job_id) / "output.json"
    assert s.ham_cikti_ref == str(beklenen)
    assert beklenen.is_file()
    assert b"kanit" in beklenen.read_bytes()


def test_basarisiz_cikis_kodu_failed(runner):
    s = runner.calistir(
        _spec(), "firma.com", uuid.uuid4(), komut=["sh", "-c", "exit 3"]
    )
    assert s.durum is JobStatus.FAILED
    assert s.cikis_kodu == 3


def test_stderr_hata_mesajina_gecer(runner):
    s = runner.calistir(
        _spec(),
        "firma.com",
        uuid.uuid4(),
        komut=["sh", "-c", "echo bozuk-cikti >&2; exit 1"],
    )
    assert s.durum is JobStatus.FAILED
    assert "bozuk-cikti" in (s.hata_mesaji or "")


def test_olmayan_imaj_failed(runner):
    s = runner.calistir(
        _spec(image="yok-boyle-bir-imaj:0"), "firma.com", uuid.uuid4()
    )
    assert s.durum is JobStatus.FAILED
    assert "imaj" in (s.hata_mesaji or "").lower()


# --------------------------------------------------------------------------- #
# Timeout
# --------------------------------------------------------------------------- #


def test_timeout_containeri_gercekten_oldurur(runner, client):
    """`sleep 30` + `timeout_sn=2` -> TIMEOUT, container host'ta KALMAZ."""
    onceki = _container_sayisi(client)

    s = runner.calistir(
        _spec(timeout_sn=2), "firma.com", uuid.uuid4(), komut=["sleep", "30"]
    )

    assert s.durum is JobStatus.TIMEOUT
    assert s.sure_ms < 30_000, "30 sn beklenmiş: timeout hiç uygulanmamış"
    assert "timeout" in (s.hata_mesaji or "").lower()

    # Zombi container kalmamalı — `docker ps -a` karşılığı.
    assert _container_sayisi(client) == onceki
    ayakta = [
        c.name
        for c in client.containers.list()
        if c.attrs.get("Config", {}).get("Image") == ALPINE
    ]
    assert not ayakta, f"öldürülmemiş container: {ayakta}"


def test_timeoutta_da_ham_cikti_yazilir(runner, tmp_path):
    """Kısmi çıktı bile 'bu iş neden düştü' sorusunun kanıtıdır."""
    job_id = uuid.uuid4()
    s = runner.calistir(
        _spec(timeout_sn=2),
        "firma.com",
        job_id,
        komut=["sh", "-c", "echo yarim-is; sleep 30"],
    )
    assert s.durum is JobStatus.TIMEOUT
    yol = tmp_path / "raw" / str(job_id) / "output.json"
    assert yol.is_file()
    assert b"yarim-is" in yol.read_bytes()


# --------------------------------------------------------------------------- #
# Pasiflik / yetki kontrolü
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("seviye", [Passivity.P2, Passivity.A])
def test_yetki_isteyen_tool_onaysiz_calismaz(runner, client, seviye):
    """Container HİÇ oluşturulmamalı — kontrol çalıştırmadan ÖNCE."""
    onceki = _container_sayisi(client)

    s = runner.calistir(
        _spec(passivity=seviye),
        "firma.com",
        uuid.uuid4(),
        yetki_onayi=False,
        komut=["echo", "bu-calismamali"],
    )

    assert s.durum is JobStatus.SKIPPED
    assert s.ham is None
    assert s.ham_cikti_ref is None
    assert _container_sayisi(client) == onceki, "container oluşturulmuş!"


@pytest.mark.parametrize("seviye", [Passivity.P0, Passivity.P1])
def test_pasif_tool_onay_istemez(runner, seviye):
    s = runner.calistir(
        _spec(passivity=seviye), "firma.com", uuid.uuid4(), komut=["echo", "ok"]
    )
    assert s.durum is JobStatus.SUCCESS


def test_yetki_onayi_verilince_p2_calisir(runner):
    s = runner.calistir(
        _spec(passivity=Passivity.P2),
        "firma.com",
        uuid.uuid4(),
        yetki_onayi=True,
        komut=["echo", "onayli"],
    )
    assert s.durum is JobStatus.SUCCESS
    assert b"onayli" in s.ham.icerik


def test_etkin_olmayan_tool_skipped(runner, client):
    onceki = _container_sayisi(client)
    s = runner.calistir(_spec(etkin=False), "firma.com", uuid.uuid4())
    assert s.durum is JobStatus.SKIPPED
    assert _container_sayisi(client) == onceki


# --------------------------------------------------------------------------- #
# Güvenlik bayrakları — bayrağın geçtiği değil, İŞE YARADIĞI doğrulanır
# --------------------------------------------------------------------------- #


def test_kok_dosya_sistemi_salt_okunur(runner):
    s = runner.calistir(
        _spec(),
        "firma.com",
        uuid.uuid4(),
        komut=["sh", "-c", "touch /kok-deneme.txt"],
    )
    assert s.durum is JobStatus.FAILED
    assert s.cikis_kodu != 0
    assert "read-only" in (s.hata_mesaji or "").lower()


def test_tmpfs_yazilabilir(runner):
    """read_only altında tool'un geçici dosya yazabileceği tek yer."""
    s = runner.calistir(
        _spec(),
        "firma.com",
        uuid.uuid4(),
        komut=["sh", "-c", "echo x > /tmp/gecici && cat /tmp/gecici"],
    )
    assert s.durum is JobStatus.SUCCESS
    assert b"x" in s.ham.icerik


def test_root_olarak_calismiyor(runner):
    s = runner.calistir(_spec(), "firma.com", uuid.uuid4(), komut=["id", "-u"])
    assert s.durum is JobStatus.SUCCESS
    assert s.ham.icerik.strip() == b"1000", "container root olarak koşuyor"


def test_guvenlik_bayraklari_eksiksiz():
    """Bayraklardan biri sessizce düşerse burada yakalanır."""
    assert GUVENLIK_BAYRAKLARI["read_only"] is True
    assert GUVENLIK_BAYRAKLARI["user"] == "1000:1000"
    assert GUVENLIK_BAYRAKLARI["cap_drop"] == ["ALL"]
    assert GUVENLIK_BAYRAKLARI["security_opt"] == ["no-new-privileges"]
    assert GUVENLIK_BAYRAKLARI["mem_limit"] == "512m"
    assert GUVENLIK_BAYRAKLARI["nano_cpus"] == 1_000_000_000
    assert "/tmp" in GUVENLIK_BAYRAKLARI["tmpfs"]


# --------------------------------------------------------------------------- #
# Ağ izolasyonu — kararın kendisi
# --------------------------------------------------------------------------- #


def _servis_ip(client, sonek: str) -> str | None:
    """Çalışan compose servisinin bridge IP'si (DNS'i atlayarak test için)."""
    for c in client.containers.list():
        if c.name.endswith(sonek):
            for ag in c.attrs["NetworkSettings"]["Networks"].values():
                if ag.get("IPAddress"):
                    return ag["IPAddress"]
    return None


def test_tool_containeri_db_ye_ulasamaz(runner, client):
    """Ağ kararının asıl testi: db AYRI ağda, tool oraya erişemez.

    DNS'e güvenilmez — `db` adı zaten çözülmez. Doğrudan IP denenir ki
    'sadece isim çözümlenmiyor' ile 'trafik gerçekten kesiliyor' ayrılsın.
    """
    ip = _servis_ip(client, "-db-1")
    if not ip:
        pytest.skip("db container'ı ayakta değil (docker compose up -d db redis)")

    s = runner.calistir(
        _spec(timeout_sn=30),
        "firma.com",
        uuid.uuid4(),
        komut=["nc", "-z", "-w", "3", ip, "5432"],
    )
    assert s.durum is not JobStatus.SUCCESS, f"tool db'ye ULAŞTI ({ip}:5432)"


def test_tool_containeri_db_adini_cozemez(runner, client):
    ip = _servis_ip(client, "-db-1")
    if not ip:
        pytest.skip("db container'ı ayakta değil")
    s = runner.calistir(
        _spec(timeout_sn=30),
        "firma.com",
        uuid.uuid4(),
        komut=["nc", "-z", "-w", "3", "db", "5432"],
    )
    assert s.durum is not JobStatus.SUCCESS


def test_tool_containerlari_birbirini_goremez(runner, client):
    """`enable_icc=false` doğrulaması: aynı ağdaki iki tool birbirine kapalı."""
    dinleyici = client.containers.run(
        ALPINE,
        command=["nc", "-l", "-p", "9999"],
        detach=True,
        network=runner._ag_hazirla().name,
        **GUVENLIK_BAYRAKLARI,
    )
    try:
        dinleyici.reload()
        ip = next(
            a["IPAddress"]
            for a in dinleyici.attrs["NetworkSettings"]["Networks"].values()
            if a.get("IPAddress")
        )
        s = runner.calistir(
            _spec(timeout_sn=30),
            "firma.com",
            uuid.uuid4(),
            komut=["nc", "-z", "-w", "3", ip, "9999"],
        )
        assert s.durum is not JobStatus.SUCCESS, "iki tool birbirini görüyor"
    finally:
        dinleyici.remove(force=True)


def test_tool_containeri_internete_cikabilir(runner):
    """İzolasyonun yönü İÇERİYE doğrudur: dış çıkış açık kalmalı.

    Bu test olmadan ağ kararı yarım doğrulanmış olur — her şeyi kesmek kolay,
    marifet db'yi keserken crt.sh'ı açık bırakmakta.
    """
    s = runner.calistir(
        _spec(timeout_sn=30),
        "firma.com",
        uuid.uuid4(),
        komut=["nc", "-z", "-w", "8", "1.1.1.1", "443"],
    )
    if s.durum is not JobStatus.SUCCESS:
        pytest.skip(f"dış ağ erişimi yok, ortam kaynaklı olabilir: {s.hata_mesaji}")
    assert s.cikis_kodu == 0


def test_ag_izole_bayragiyla_kuruldu(runner):
    ag = runner._ag_hazirla()
    ag.reload()
    assert ag.attrs["Driver"] == "bridge"
    assert ag.attrs["Options"].get("com.docker.network.bridge.enable_icc") == "false"
    # `internal` olmamalı: o bayrak dış çıkışı da keserdi.
    assert ag.attrs.get("Internal") is False


# --------------------------------------------------------------------------- #
# ApiRunner ve ToolRunner — `calistirma: "api"` yolu
#
# Bu testler Docker İSTEMEZ: API tool'u container açmaz. Sahte adapter'larla
# koşarlar, dolayısıyla crt.sh ayakta olmasa da anlamlıdırlar.
# --------------------------------------------------------------------------- #

import time as _time

from app.runner import ApiRunner, ToolRunner


class _SahteApiAdapter:
    """calistirma='api' olan asgari adapter."""

    cikti_formati = "json"

    def __init__(self, *, gecikme=0.0, patlat=None, govde=b'{"ok":1}', kod=0, spec=None):
        self.spec = spec or _spec(ad="sahte-api", calistirma="api", image=None)
        self._gecikme = gecikme
        self._patlat = patlat
        self._govde = govde
        self._kod = kod
        self.cagrildi = 0
        self.gecen_cfg = None

    def calistir(self, hedef, cfg):
        self.cagrildi += 1
        self.gecen_cfg = cfg
        if self._gecikme:
            _time.sleep(self._gecikme)
        if self._patlat is not None:
            raise self._patlat
        return RawResult(icerik=self._govde, format="json", cikis_kodu=self._kod)

    def parse(self, ham):
        return []


def _api_runner(tmp_path) -> ApiRunner:
    return ApiRunner(RunnerConfig(raw_kok=tmp_path / "raw"))


def test_api_basarili_calisma(tmp_path):
    a = _SahteApiAdapter(govde=b'[{"host":"a.firma.com"}]')
    s = _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4())

    assert s.durum is JobStatus.SUCCESS
    assert s.cikis_kodu == 0
    assert s.ham.icerik == b'[{"host":"a.firma.com"}]'
    assert a.cagrildi == 1


def test_api_ham_cikti_diske_yazilir(tmp_path):
    """İlke 2, çalıştırma biçiminden bağımsızdır."""
    job_id = uuid.uuid4()
    a = _SahteApiAdapter(govde=b'{"kanit":true}')
    s = _api_runner(tmp_path).calistir(a, "firma.com", job_id)

    yol = tmp_path / "raw" / str(job_id) / "output.json"
    assert s.ham_cikti_ref == str(yol)
    assert yol.is_file() and yol.read_bytes() == b'{"kanit":true}'


def test_api_http_hatasi_failed(tmp_path):
    """Adapter HTTP durumunu çıkış kodu olarak bildirir (crt.sh 502 gibi)."""
    a = _SahteApiAdapter(govde=b"<html>502</html>", kod=502)
    s = _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4())

    assert s.durum is JobStatus.FAILED
    assert s.cikis_kodu == 502
    assert "502" in (s.hata_mesaji or "")


def test_api_hatali_govde_bile_arsivlenir(tmp_path):
    """'Neden düştü' sorusunun kanıtı 502 gövdesidir."""
    job_id = uuid.uuid4()
    a = _SahteApiAdapter(govde=b"<html>502 Bad Gateway</html>", kod=502)
    s = _api_runner(tmp_path).calistir(a, "firma.com", job_id)

    yol = tmp_path / "raw" / str(job_id) / "output.json"
    assert s.durum is JobStatus.FAILED
    assert yol.is_file()
    assert b"502" in yol.read_bytes()


def test_api_adapter_patlarsa_worker_cokmez(tmp_path):
    a = _SahteApiAdapter(patlat=RuntimeError("baglanti koptu"))
    s = _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4())

    assert s.durum is JobStatus.FAILED
    assert "RuntimeError" in (s.hata_mesaji or "")
    assert "baglanti koptu" in (s.hata_mesaji or "")


def test_api_timeout_runner_tarafindan_uygulanir(tmp_path):
    """Adapter kendi timeout'unu unutsa bile iş burada kesilir."""
    a = _SahteApiAdapter(
        gecikme=30, spec=_spec(ad="yavas", calistirma="api", image=None, timeout_sn=1)
    )
    basla = _time.monotonic()
    s = _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4())
    gecen = _time.monotonic() - basla

    assert s.durum is JobStatus.TIMEOUT
    assert gecen < 25, "timeout uygulanmadı"
    assert "timeout" in (s.hata_mesaji or "").lower()


@pytest.mark.parametrize("seviye", [Passivity.P2, Passivity.A])
def test_api_yetki_isteyen_tool_cagrilmaz(tmp_path, seviye):
    """Pasiflik kontrolü çalıştırma biçiminden BAĞIMSIZDIR."""
    a = _SahteApiAdapter(
        spec=_spec(ad="p2-api", passivity=seviye, calistirma="api", image=None)
    )
    s = _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4(), yetki_onayi=False)

    assert s.durum is JobStatus.SKIPPED
    assert a.cagrildi == 0, "adapter yetkisiz çağrıldı"
    assert s.ham_cikti_ref is None


def test_api_yetki_onayi_varsa_calisir(tmp_path):
    a = _SahteApiAdapter(
        spec=_spec(ad="p2-api", passivity=Passivity.P2, calistirma="api", image=None)
    )
    s = _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4(), yetki_onayi=True)
    assert s.durum is JobStatus.SUCCESS
    assert a.cagrildi == 1


def test_api_env_yalnizca_istenen_anahtarlari_gecirir(tmp_path, monkeypatch):
    """Bir tool başka bir tool'un anahtarını görmemeli."""
    monkeypatch.setenv("BENIM_ANAHTARIM", "gizli")
    monkeypatch.setenv("BASKASININ_ANAHTARI", "dokunma")
    a = _SahteApiAdapter(
        spec=_spec(
            ad="anahtarli",
            calistirma="api",
            image=None,
            auth_env=("BENIM_ANAHTARIM",),
        )
    )
    _api_runner(tmp_path).calistir(a, "firma.com", uuid.uuid4())

    assert a.gecen_cfg.env == {"BENIM_ANAHTARIM": "gizli"}
    assert "BASKASININ_ANAHTARI" not in a.gecen_cfg.env


# --- dağıtıcı --------------------------------------------------------------- #


def test_dagitici_api_yolunu_secer(tmp_path):
    a = _SahteApiAdapter(govde=b"api-yolu")
    s = ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw")).calistir(
        a, "firma.com", uuid.uuid4()
    )
    assert s.durum is JobStatus.SUCCESS
    assert s.ham.icerik == b"api-yolu"


def test_dagitici_docker_yolunu_secer(tmp_path, client):
    """Aynı dağıtıcı, container tool'unu ContainerRunner'a yollar."""

    class _DockerAdapter:
        spec = _spec(ad="docker-tool")

        def parse(self, ham):
            return []

    r = ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw"), client=client)
    s = r.calistir(
        _DockerAdapter(), "firma.com", uuid.uuid4(), komut=["echo", "container-yolu"]
    )
    assert s.durum is JobStatus.SUCCESS
    assert b"container-yolu" in s.ham.icerik


def test_dagitici_bilinmeyen_bicimde_net_hata(tmp_path):
    class _Garip:
        spec = _spec(ad="garip", calistirma="karga", image=None)

        def parse(self, ham):
            return []

    s = ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw")).calistir(
        _Garip(), "firma.com", uuid.uuid4()
    )
    assert s.durum is JobStatus.FAILED
    assert "calistirma" in (s.hata_mesaji or "")
    assert "karga" in (s.hata_mesaji or "")


def test_dagitici_cikti_formatini_adapterdan_alir(tmp_path):
    class _Jsonl(_SahteApiAdapter):
        cikti_formati = "jsonl"

    job_id = uuid.uuid4()
    ToolRunner(RunnerConfig(raw_kok=tmp_path / "raw")).calistir(
        _Jsonl(), "firma.com", job_id
    )
    assert (tmp_path / "raw" / str(job_id) / "output.jsonl").is_file()
