"""Container runner — bir tool'u izole container'da çalıştırır.

`docs/kapsam.md` Bölüm 5.2 sorumluluk sınırı: **adapter bunların hiçbirini
bilmez.** Timeout uygulama, rate limit, retry/backoff, kota takibi, hata
izolasyonu, ham çıktıyı diske yazma ve pasiflik seviyesi kontrolü runner'ın
işidir. Adapter yalnızca "çalıştır" ve "ayrıştır" der.

İlke 5: her tool kendi container'ında izole çalışır — bozuk bir tool sistemi
düşürmez. Bu dosyadaki güvenlik bayrakları o izolasyonun kendisidir, isteğe
bağlı ayar değildir: bu container'lar HEDEFİN KONTROL ETTİĞİ veriyi işler.
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import docker
import requests
from docker.errors import APIError, DockerException, ImageNotFound, NotFound

from app.models import JobStatus
from app.tools._base import RawResult, ToolSpec

__all__ = [
    "TOOL_AGI",
    "GUVENLIK_BAYRAKLARI",
    "RunnerConfig",
    "RunSonucu",
    "ContainerRunner",
    "varsayilan_raw_kok",
]

_KOK = Path(__file__).resolve().parents[1]

# Tool container'larının bağlandığı ağ. compose'un varsayılan ağından AYRIDIR.
TOOL_AGI = "osint-tools"

# stderr'den hata mesajına alınacak azami karakter — hedefin kontrolündeki
# metin olabileceği için sınırsız log DB'ye taşınmaz.
_HATA_SINIRI = 2000


# --------------------------------------------------------------------------- #
# Güvenlik bayrakları
# --------------------------------------------------------------------------- #

# Her biri ayrı bir saldırı yüzeyini kapatır. Tek sözlükte toplanmalarının
# sebebi, yeni bir çalıştırma yolu eklendiğinde birinin unutulmasını
# zorlaştırmaktır — bayraklar çağrı yerinde tek tek yazılmaz.
GUVENLIK_BAYRAKLARI: dict[str, Any] = {
    # Kök dosya sistemi salt okunur: tool kendini veya imajı değiştiremez,
    # indirdiği bir yükü diske kalıcı yazamaz.
    "read_only": True,
    # Bellek ve CPU tavanı: bozuk ya da kötü niyetli bir çıktı host'u tüketip
    # diğer işleri durduramaz (hata izolasyonu).
    "mem_limit": "512m",
    "nano_cpus": 1_000_000_000,  # 1 CPU
    # ROOT DEĞİL. Container escape zincirlerinin çoğu uid 0 ile başlar.
    "user": "1000:1000",
    # Bütün Linux capability'leri düşürülür; hiçbir pasif tool'un
    # CAP_NET_RAW veya CAP_SYS_ADMIN'e ihtiyacı yoktur.
    "cap_drop": ["ALL"],
    # setuid ikililerle ayrıcalık yükseltme yolunu kapatır.
    "security_opt": ["no-new-privileges"],
    # read_only=True altında yazılabilir TEK yer. Bellekte durur, container
    # ölünce yok olur, 64 MB ile sınırlıdır.
    "tmpfs": {"/tmp": "size=64m"},
}


def varsayilan_raw_kok() -> Path:
    """Ham çıktı arşivinin kökü.

    Container içinde `/data/raw` (compose ile mount edilir), host'ta ise repo
    altındaki `data/raw`. `ALEMBIC_DATABASE_URL` ile aynı gerekçe: aynı dizinin
    nerede durduğunuza göre iki farklı yolu var.
    """
    ham = os.getenv("RAW_DIR_HOST") or os.getenv("RAW_DIR") or "data/raw"
    yol = Path(ham)
    return yol if yol.is_absolute() else _KOK / yol


@dataclass(frozen=True)
class RunnerConfig:
    raw_kok: Path = field(default_factory=varsayilan_raw_kok)
    tool_agi: str = TOOL_AGI


@dataclass(frozen=True)
class RunSonucu:
    """Runner'ın job'a yazacağı her şey. Adapter bunu görmez."""

    durum: JobStatus
    ham: RawResult | None = None
    ham_cikti_ref: str | None = None  # /data/raw/{job_id}/output.json
    cikis_kodu: int | None = None
    sure_ms: int = 0
    hata_mesaji: str | None = None


class ContainerRunner:
    """Tool'u izole container'da çalıştırır ve ham çıktıyı arşivler."""

    def __init__(self, cfg: RunnerConfig | None = None, client: Any = None) -> None:
        self.cfg = cfg or RunnerConfig()
        self._client = client
        self._ag: Any = None

    # -- docker istemcisi --------------------------------------------------- #

    @property
    def client(self) -> Any:
        """Docker istemcisi, ilk kullanımda açılır.

        WINDOWS: `docker.from_env()` burada da çalışır. Docker Desktop, UNIX
        soketi yerine named pipe (`npipe:////./pipe/dockerDesktopLinuxEngine`)
        yayınlar; docker-py bunu kendisi seçer, ayrı yapılandırma gerekmez.
        Buna karşılık compose'daki `worker` servisi Linux container'ı olduğu
        için orada `/var/run/docker.sock` mount'u geçerlidir — ikisi aynı anda
        doğrudur, ortam belirler.
        """
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # -- ağ ----------------------------------------------------------------- #

    def _ag_hazirla(self) -> Any:
        """Tool container'ları için ayrı, izole bir bridge ağı kurar.

        AĞ KARARI VE GEREKÇESİ
        ------------------------------------------------------------------
        Gerilim şu: tool'ların internete çıkması ŞART (crt.sh, Shodan, RDAP),
        ama db ve redis'i GÖRMEMELERİ de şart — bu container'lar hedefin
        kontrol ettiği veriyi işliyor.

        Bu ağ o korumanın YALNIZCA BİR YARISIDIR. İki bileşen var:

        1) ICC KAPALI (`enable_icc=false`) — BURADA. Aynı bridge üzerindeki
           container'lar arası trafiği yasaklar, yani paralel koşan iki tool
           birbirinin portuna erişemez. Dış çıkış etkilenmez.

        2) VERİ KATMANI `internal: true` — `docker-compose.yml`'de. db ve redis
           `osint-data` internal ağındadır; tool'ların oraya erişimini asıl
           kesen budur.

        İKİNCİ MADDE NEDEN GEREKLİ (ölçüm)
        ------------------------------------------------------------------
        İlk tasarım yalnızca "ayrı bridge ağı" idi: tool'lar `osint-tools`,
        db compose'un varsayılan ağında. Varsayım, Docker'ın DOCKER-ISOLATION
        zincirleriyle çapraz bridge trafiğini düşüreceğiydi. YANLIŞ ÇIKTI —
        Docker Desktop 29.7.2'de tool container'ı 172.19 ağından 172.18.0.3:5432
        adresine DOĞRUDAN IP ile ulaştı. Ayrı ağ, isim çözümlemesini engeller
        ama yönlendirmeyi engellemez.

        Ölçülen davranışlar:
            internal ağa başka bir bridge'den giriş  -> ENGELLENİYOR
            internal ağda yayınlanan port (-p)       -> ÇALIŞMIYOR

        Kısıt VERİ katmanına konuldu, tool katmanına değil. Gerekçe: db ve
        redis'in zaten hiç internet erişimine ihtiyacı yok, tool'ların ise var.
        Tool ağını `internal` yapmak çıkışı da keserdi ve tool'ları bir egress
        proxy'ye bağımlı kılardı; üstelik yukarıdaki (1) numaralı madde
        tool→proxy trafiğini de kestiği için her iş kendi ağını açıp kapatmak
        zorunda kalırdı. Kısıt, ona en az ihtiyaç duyan katmanda durur.

        Bedeli `docker-compose.yml`'de yazılı: db host'tan TCP ile erişilemez,
        migration ve DB testleri container içinden koşar.

        `tests/test_runner.py` bu iddiaların üçünü de gerçek Docker'a karşı
        doğrular: db'ye ulaşılamıyor, tool'lar birbirini görmüyor, internet açık.
        """
        if self._ag is not None:
            return self._ag
        try:
            ag = self.client.networks.get(self.cfg.tool_agi)
        except NotFound:
            try:
                ag = self.client.networks.create(
                    self.cfg.tool_agi,
                    driver="bridge",
                    options={"com.docker.network.bridge.enable_icc": "false"},
                    labels={"com.osint-platform.rol": "tool-agi"},
                )
            except APIError:
                # Paralel worker aynı anda kurmuş olabilir — yarışı kaybettik.
                ag = self.client.networks.get(self.cfg.tool_agi)
        self._ag = ag
        return ag

    # -- ham çıktı arşivi --------------------------------------------------- #

    def _ham_yaz(self, job_id: uuid.UUID | str, icerik: bytes, bicim: str) -> str:
        """`RAW_DIR/{job_id}/output.{bicim}`.

        İlke 2'nin (her bulgu ham çıktısına kadar izlenebilir) altyapısı:
        `observation.ham_cikti_ref` bu yolu gösterir. Diske yazmak ADAPTER'IN
        DEĞİL runner'ın işidir; adapter ham baytları döndürmekle yetinir.
        """
        klasor = Path(self.cfg.raw_kok) / str(job_id)
        klasor.mkdir(parents=True, exist_ok=True)
        yol = klasor / f"output.{bicim}"
        yol.write_bytes(icerik)
        return str(yol)

    # -- ana giriş ---------------------------------------------------------- #

    def calistir(
        self,
        spec: ToolSpec,
        hedef: str,
        job_id: uuid.UUID | str,
        *,
        yetki_onayi: bool = False,
        komut: list[str] | None = None,
        cikti_formati: str = "json",
    ) -> RunSonucu:
        """Tool'u container'da çalıştırır, ham çıktıyı arşivler, sonucu döner.

        İstisna FIRLATMAZ: her hata bir `JobStatus` ve `hata_mesaji` olarak
        döner. Bozuk bir tool turu düşürmemelidir.
        """
        # 1) PASİFLİK KONTROLÜ — container HİÇ oluşturulmadan önce.
        #    Bu kontrolün arayüzde değil BURADA olmasının sebebi: arayüz
        #    atlanabilir (API doğrudan çağrılabilir, iş kuyruğa elle
        #    eklenebilir). Kontrol, işi gerçekten başlatan tek noktada durur.
        if spec.yetki_ister() and not yetki_onayi:
            return RunSonucu(
                durum=JobStatus.SKIPPED,
                hata_mesaji=(
                    f"{spec.name} seviyesi {spec.passivity.value}; "
                    "investigation.yetki_onayi isaretli degil"
                ),
            )

        if not spec.etkin:
            return RunSonucu(
                durum=JobStatus.SKIPPED, hata_mesaji=f"{spec.name} etkin degil"
            )

        if not spec.image:
            return RunSonucu(
                durum=JobStatus.FAILED,
                hata_mesaji=f"{spec.name} icin spec.image tanimsiz",
            )

        # BURAYA GELECEK — rate limit ve retry (bu parçada YAZILMADI):
        #   * `spec.dakikalik_istek` -> Redis'te tool başına token bucket;
        #     kota dolmuşsa beklenir, beklemek işi geciktirecekse
        #     JobStatus.SKIPPED dönülür.
        #   * `spec.aylik_kota` -> aylık sayaç; aşıldıysa çalıştırmadan SKIPPED.
        #   * retry/backoff -> yalnızca GEÇİCİ hatalar (ağ, 5xx, TIMEOUT) için,
        #     üstel bekleme ile. Kalıcı hatalar (ImageNotFound, kimlik
        #     doğrulama) tekrarlanmaz.
        # Üçü de runner'ın sorumluluğudur; adapter'a sızmamalıdır.

        return self._container_calistir(spec, hedef, job_id, komut, cikti_formati)

    # -- container yaşam döngüsü -------------------------------------------- #

    def _container_calistir(
        self,
        spec: ToolSpec,
        hedef: str,
        job_id: uuid.UUID | str,
        komut: list[str] | None,
        cikti_formati: str,
    ) -> RunSonucu:
        try:
            ag = self._ag_hazirla()
        except DockerException as e:
            return RunSonucu(durum=JobStatus.FAILED, hata_mesaji=f"ag kurulamadi: {e}")

        baslangic = time.monotonic()
        try:
            container = self.client.containers.run(
                image=spec.image,
                command=komut if komut is not None else [hedef],
                detach=True,
                network=ag.name,
                **GUVENLIK_BAYRAKLARI,
            )
        except ImageNotFound:
            return RunSonucu(
                durum=JobStatus.FAILED, hata_mesaji=f"imaj bulunamadi: {spec.image}"
            )
        except (APIError, DockerException) as e:
            return RunSonucu(
                durum=JobStatus.FAILED, hata_mesaji=f"container baslatilamadi: {e}"
            )

        zaman_asimi = False
        cikis_kodu: int | None = None
        try:
            sonuc = container.wait(timeout=spec.timeout_sn)
            cikis_kodu = int(sonuc.get("StatusCode", -1))
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        ):
            # TIMEOUT: container'ı ÖLDÜR. Aksi halde zombi container host'ta
            # kalır ve `mem_limit` başına 512 MB'ı süresiz tutar.
            zaman_asimi = True
            try:
                container.kill()
            except (NotFound, APIError):
                pass  # bu arada kendiliğinden bitmiş olabilir
        except (APIError, DockerException) as e:
            try:
                container.kill()
            except (NotFound, APIError):
                pass
            return self._topla(
                container,
                job_id,
                cikti_formati,
                baslangic,
                durum=JobStatus.FAILED,
                cikis_kodu=None,
                ek_hata=f"container beklenirken hata: {e}",
            )

        if zaman_asimi:
            durum = JobStatus.TIMEOUT
        elif cikis_kodu == 0:
            durum = JobStatus.SUCCESS
        else:
            durum = JobStatus.FAILED

        return self._topla(
            container,
            job_id,
            cikti_formati,
            baslangic,
            durum=durum,
            cikis_kodu=cikis_kodu,
            ek_hata=(
                f"timeout: {spec.timeout_sn} sn asildi, container olduruldu"
                if zaman_asimi
                else None
            ),
        )

    def _topla(
        self,
        container: Any,
        job_id: uuid.UUID | str,
        cikti_formati: str,
        baslangic: float,
        *,
        durum: JobStatus,
        cikis_kodu: int | None,
        ek_hata: str | None,
    ) -> RunSonucu:
        """Log'ları alır, ham çıktıyı arşivler, container'ı temizler."""
        stdout = b""
        stderr = b""
        try:
            stdout = container.logs(stdout=True, stderr=False)
            stderr = container.logs(stdout=False, stderr=True)
        except (APIError, DockerException):
            pass
        finally:
            # Container HER durumda silinir — timeout ve hata dahil.
            try:
                container.remove(force=True)
            except (NotFound, APIError):
                pass

        sure_ms = int((time.monotonic() - baslangic) * 1000)

        # Ham çıktı TIMEOUT ve FAILED durumunda da yazılır: kısmi çıktı bile
        # "bu iş neden başarısız oldu" sorusunun kanıtıdır (İlke 2).
        ham_ref: str | None = None
        try:
            ham_ref = self._ham_yaz(job_id, stdout, cikti_formati)
        except OSError as e:
            ek_hata = f"{ek_hata or ''} | ham cikti yazilamadi: {e}".strip(" |")

        hata = ek_hata
        if stderr:
            metin = stderr.decode("utf-8", errors="replace").strip()[:_HATA_SINIRI]
            hata = f"{hata} | {metin}" if hata else metin

        return RunSonucu(
            durum=durum,
            ham=RawResult(
                icerik=stdout,
                format=cikti_formati,
                cikis_kodu=cikis_kodu if cikis_kodu is not None else -1,
                sure_ms=sure_ms,
                meta={"ham_cikti_ref": ham_ref},
            ),
            ham_cikti_ref=ham_ref,
            cikis_kodu=cikis_kodu,
            sure_ms=sure_ms,
            hata_mesaji=hata,
        )
