"""Tool koşucuları — bir tool'u çalıştırıp ham çıktısını arşivler.

İki çalıştırma biçimi vardır ve `ToolRunner` aralarında seçim yapar:
  `docker` → `ContainerRunner`, izole container (subfinder gibi ikililer)
  `api`    → `ApiRunner`, doğrudan HTTP çağrısı (crt.sh, RDAP, BGP gibi)

`docs/kapsam.md` Bölüm 5.2 sorumluluk sınırı: **adapter bunların hiçbirini
bilmez.** Timeout uygulama, rate limit, retry/backoff, kota takibi, hata
izolasyonu, ham çıktıyı diske yazma ve pasiflik seviyesi kontrolü runner'ın
işidir. Adapter yalnızca "çalıştır" ve "ayrıştır" der.

İlke 5: her tool kendi container'ında izole çalışır — bozuk bir tool sistemi
düşürmez. Bu dosyadaki güvenlik bayrakları o izolasyonun kendisidir, isteğe
bağlı ayar değildir: bu container'lar HEDEFİN KONTROL ETTİĞİ veriyi işler.
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import docker
import requests
from docker.errors import APIError, DockerException, ImageNotFound, NotFound

from app.models import JobStatus
from app.tools._base import RawResult, ToolConfig, ToolSpec

__all__ = [
    "TOOL_AGI",
    "GUVENLIK_BAYRAKLARI",
    "RunnerConfig",
    "RunSonucu",
    "ContainerRunner",
    "ApiRunner",
    "ToolRunner",
    "ham_yaz",
    "yetki_engeli",
    "anahtar_engeli",
    "gecici_mi",
    "GECICI_KODLAR",
    "KALICI_KODLAR",
    "HizSinirlayici",
    "varsayilan_raw_kok",
]

log = logging.getLogger(__name__)

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
    # Geri çekilme süresine eklenen rastgelelik oranı. Aynı anda kuyruğa giren
    # işler senkronize retry yapıp sunucuyu dalga dalga dövmesin diye vardır
    # ("thundering herd"). Testlerde 0.0 verilir ki süreler ölçülebilsin.
    jitter_orani: float = 0.25


def ham_yaz(
    raw_kok: Path | str, job_id: uuid.UUID | str, icerik: bytes, bicim: str
) -> str:
    """`RAW_DIR/{job_id}/output.{bicim}`.

    İlke 2'nin (her bulgu ham çıktısına kadar izlenebilir) altyapısı:
    `observation.ham_cikti_ref` bu yolu gösterir. Diske yazmak ADAPTER'IN DEĞİL
    runner'ın işidir; adapter ham baytları döndürmekle yetinir.

    Modül seviyesindedir çünkü hem container hem API koşucusu kullanır —
    ham çıktı arşivi çalıştırma biçiminden bağımsızdır.
    """
    klasor = Path(raw_kok) / str(job_id)
    klasor.mkdir(parents=True, exist_ok=True)
    yol = klasor / f"output.{bicim}"
    yol.write_bytes(icerik)
    return str(yol)


def anahtar_engeli(spec: ToolSpec) -> RunSonucu | None:
    """Zorunlu API anahtarı eksikse çalıştırma. Engel yoksa `None`.

    NEDEN SESSİZCE GİZLEMİYORUZ
    ------------------------------------------------------------------
    Anahtarsız tool'u registry'den düşürmek ya da arayüzde hiç göstermemek,
    analiste "bu tool neden çalışmadı" sorusunu CEVAPSIZ bırakır. Tool listede
    kalır, seçilebilir ve seçilince EKSİĞİN ADIYLA birlikte SKIPPED döner —
    "SHODAN_API_KEY tanımlı değil" mesajı, sessiz bir yokluktan çok daha
    kullanışlıdır.

    SKIPPED doğru durumdur: `JobStatus.SKIPPED` zaten "kota/limit/yetki
    nedeniyle atlandı" demektir. FAILED demek olmaz — ortada bir arıza yok,
    eksik bir yapılandırma var ve retry onu düzeltmez.

    ANAHTARIN KENDİSİ ASLA MESAJA GİRMEZ; yalnızca DEĞİŞKEN ADI yazılır.
    """
    if not spec.auth_gerekli:
        return None
    eksik = [ad for ad in spec.auth_env if not os.environ.get(ad)]
    if not eksik:
        return None
    return RunSonucu(
        durum=JobStatus.SKIPPED,
        hata_mesaji=(
            f"{spec.name} API anahtari gerektiriyor; "
            f"tanimli olmayan degisken(ler): {', '.join(eksik)}"
        ),
    )


def yetki_engeli(spec: ToolSpec, yetki_onayi: bool) -> RunSonucu | None:
    """P2/A seviyesi onaysız, zorunlu anahtarı eksik tool çalışmaz.

    Container ve API koşucularının PAYLAŞTIĞI kontrol. Pasiflik, çalıştırma
    biçiminin değil tool'un özelliğidir; API üzerinden koşan bir P2 tool da
    aynı onayı ister.
    """
    anahtar = anahtar_engeli(spec)
    if anahtar is not None:
        return anahtar
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
    return None


# --------------------------------------------------------------------------- #
# Retry sınıflandırması
# --------------------------------------------------------------------------- #

# GEÇİCİ — tekrar denemeye DEĞER. Ortak özellikleri: hata sunucunun o anki
# yükünden/sağlığından kaynaklanıyor ve saniyeler içinde kendiliğinden
# düzelebilir. crt.sh bu oturumda 200 ve 502 arasında dakikalar içinde gidip
# geldi; tek atışlık istek böyle bir serviste sık boşa düşer.
GECICI_KODLAR = frozenset(
    {
        408,  # Request Timeout — sunucu okumayı bekleyemedi
        429,  # Too Many Requests — rate limit, beklersek geçer
        502,  # Bad Gateway
        503,  # Service Unavailable
        504,  # Gateway Timeout
        -1,  # taşıma katmanı: bağlantı kurulamadı / okuma zaman aşımı
    }
)

# KALICI — tekrar denemek BOŞUNA ve kabalıktır. Aynı istek aynı cevabı verir.
#   400 isteğimiz bozuk, 401/403 kimlik/yetki, 404 kaynak yok,
#   405 yanlış metot, 410 kalıcı olarak gitmiş, 422 içerik reddedildi.
# 500 BİLİNÇLİ OLARAK LİSTEDE YOK ve geçici SAYILMAZ: sunucu tarafındaki bir
# hata iki saniyede düzelmez, tekrarlamak yalnızca yükü artırır. Bilinmeyen
# kodlar da kalıcı kabul edilir — şüphede kalınca hammering yapmamak
# (pasiflik ilkesiyle tutarlı) doğru varsayılandır.
KALICI_KODLAR = frozenset({400, 401, 403, 404, 405, 410, 422, 500})


def gecici_mi(cikis_kodu: int | None, durum: JobStatus) -> bool:
    """Bu sonuç tekrar denemeye değer mi?

    TEKRAR DENENMEYENLER (buraya hiç gelmezler, sınır burada çizilir):
      * SKIPPED — yetki engeli. Onay yokken beş kez denemek de yetki vermez.
      * parse hatası — `parse()` runner'dan SONRA, worker'da çalışır; bozuk
        ayrıştırma tool'u tekrar çalıştırmakla düzelmez, adapter düzelmelidir.
      * kalıcı HTTP kodları — yukarıdaki liste.
    """
    if durum is JobStatus.TIMEOUT:
        # Süre dolduğu için biz kestik: sunucu yavaştı, yine hızlanabilir.
        return True
    if durum is JobStatus.SUCCESS:
        return False
    if cikis_kodu is None:
        return False
    return cikis_kodu in GECICI_KODLAR


# --------------------------------------------------------------------------- #
# Rate limit
# --------------------------------------------------------------------------- #


class HizSinirlayici:
    """Aynı tool için ardışık istekler arasında asgari bekleme.

    `spec.dakikalik_istek` manifest'ten gelir; 5/dk → istekler arasında en az
    12 saniye. Token bucket değil, basit aralık koruması: tek worker'da yeterli
    ve okunması kolay.

    TEK WORKER VARSAYIMI NEREDE KIRILIR
    ------------------------------------------------------------------
    Durum SÜREÇ İÇİDİR (`_son` sözlüğü). Şu üç durumda etkin hız, manifest'te
    yazandan KAT KAT yüksek olur:

      1) `celery worker --concurrency=N` — prefork havuzunda her çocuk süreç
         kendi sözlüğünü taşır, gerçek hız N × limit olur.
      2) Birden fazla worker container'ı (`docker compose up --scale worker=N`).
      3) Worker yeniden başladığında sözlük sıfırlanır; hemen ardından gelen
         ilk istek beklemeden çıkar.

    Bugün compose'da tek worker ve varsayılan havuz var, o yüzden yeterli.
    Kalıcı çözüm Redis'te tool başına token bucket'tır (`INCR` + `EXPIRE` ya da
    kayan pencere) — kota takibiyle (`aylik_kota`) birlikte yazılmalıdır,
    çünkü ikisi de aynı paylaşılan sayaç altyapısını ister.
    """

    def __init__(self) -> None:
        self._son: dict[str, float] = {}
        self._kilit = threading.Lock()

    def bekleme_suresi(self, tool: str, dakikalik_istek: int | None) -> float:
        """Kaç saniye beklenmeli? Yeri de rezerve eder (uyku çağırana ait).

        Uykuyu kilidin İÇİNDE tutmayız: bir tool'un beklemesi, başka bir
        tool'un isteğini bloklamamalı.
        """
        if not dakikalik_istek or dakikalik_istek <= 0:
            return 0.0
        asgari = 60.0 / dakikalik_istek
        with self._kilit:
            simdi = time.monotonic()
            son = self._son.get(tool)
            bekleme = 0.0 if son is None else max(0.0, asgari - (simdi - son))
            # Sıradaki çağıran bu isteğin BİTECEĞİ ana göre beklesin.
            self._son[tool] = simdi + bekleme
        return bekleme

    def sifirla(self) -> None:
        with self._kilit:
            self._son.clear()


@dataclass(frozen=True)
class RunSonucu:
    """Runner'ın job'a yazacağı her şey. Adapter bunu görmez."""

    durum: JobStatus
    ham: RawResult | None = None
    ham_cikti_ref: str | None = None  # /data/raw/{job_id}/output.json
    cikis_kodu: int | None = None
    sure_ms: int = 0
    hata_mesaji: str | None = None
    # Kaç kez denendi. 1 = ilk denemede oldu. Analist bir işin 3 kez denenip
    # düştüğünü görmelidir; job satırına ve arayüze yansır.
    deneme: int = 1


class ContainerRunner:
    """Tool'u izole container'da çalıştırır ve ham çıktıyı arşivler."""

    def __init__(
        self,
        cfg: RunnerConfig | None = None,
        client: Any = None,
        hiz: HizSinirlayici | None = None,
    ) -> None:
        self.cfg = cfg or RunnerConfig()
        self._client = client
        self._ag: Any = None
        self._hiz = hiz or HizSinirlayici()

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
        return ham_yaz(self.cfg.raw_kok, job_id, icerik, bicim)

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
        engel = yetki_engeli(spec, yetki_onayi)
        if engel is not None:
            return engel

        if not spec.image:
            return RunSonucu(
                durum=JobStatus.FAILED,
                hata_mesaji=f"{spec.name} icin spec.image tanimsiz",
            )

        # RATE LIMIT container yolunda DA uygulanır: subfinder de üçüncü taraf
        # kaynakları sorgular, nazik davranma borcu çalıştırma biçimine göre
        # değişmez.
        bekleme = self._hiz.bekleme_suresi(spec.name, spec.dakikalik_istek)
        if bekleme > 0:
            log.info("%s: hız sınırı, %.1f sn bekleniyor", spec.name, bekleme)
            time.sleep(bekleme)

        # RETRY BURADA YOK — BİLİNÇLİ KARAR
        # ------------------------------------------------------------------
        # Retry, hatayı GEÇİCİ ve KALICI diye ayırabildiğimiz yerde işe yarar.
        # Container yolunda bu ayrım yapılamaz:
        #
        #   1) Çıkış kodu tool'a özgüdür. subfinder'ın `exit 1`'i "sonuç yok"
        #      da olabilir "DNS çözülemedi" de. Kör tekrar, dakikalar süren bir
        #      taramayı boşuna ikinci kez koşturur.
        #   2) TIMEOUT'ta tekrar denemek maliyeti katlar, başarı olasılığı
        #      düşüktür: tool kendi bütçesinde bitiremediyse ikinci seferde de
        #      bitiremez.
        #   3) Retry'ın gerçekten yardımcı olduğu hatalar (429, 502, 503, 504,
        #      kopan bağlantı) HTTP kavramlarıdır ve yalnızca API yolunda vardır.
        #
        # `ImageNotFound` gibi kalıcı hatalar zaten tekrarlanmamalı. Container
        # tarafında tekrar denemeye değecek tek şey daemon'ın anlık meşguliyeti
        # olurdu; ölçülmüş bir sorun değil, spekülatif karmaşıklık eklemiyoruz.
        #
        # `spec.aylik_kota` hâlâ uygulanmıyor: paylaşılan sayaç ister, Redis
        # tabanlı token bucket ile birlikte yazılacak.

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


# --------------------------------------------------------------------------- #
# API koşucusu — `calistirma: "api"`
# --------------------------------------------------------------------------- #


class ApiRunner:
    """Üçüncü taraf HTTP API'sini sorgulayan tool'ları çalıştırır.

    NEDEN AYRI BİR KOŞUCU
    ------------------------------------------------------------------
    `calistirma: "api"` olan tool'un container'ı yoktur: crt.sh, RDAP ve BGP
    sorguları yalnızca bir HTTP isteğidir, uğruna imaj inşa etmek anlamsızdır.
    Ama RUNNER SORUMLULUKLARI aynen geçerlidir — timeout, ham çıktı arşivi,
    pasiflik kontrolü, hata izolasyonu. Bu sınıf onları container yerine
    adapter'ın `calistir()` çağrısı etrafında uygular.

    Container koşucusundan tek FARKI izolasyon derecesidir ve bu bilinçlidir:
    API tool'u worker sürecinde koşar, ayrı bir çekirdek ad alanında değil.
    Karşılığında hedefe hiç dokunmaz (P0) ve işlediği veri kendi ürettiği HTTP
    yanıtıdır. Ham yanıtın modele gitmesi hâlâ yasaktır — `parse()` onu
    gözlemlere indirger, `<untrusted_data>` sınırı AI katmanında uygulanır.
    """

    def __init__(
        self, cfg: RunnerConfig | None = None, hiz: HizSinirlayici | None = None
    ) -> None:
        self.cfg = cfg or RunnerConfig()
        # Süreç ömrü boyunca paylaşılır; sınırları HizSinirlayici docstring'inde.
        self._hiz = hiz or HizSinirlayici()

    def _cfg_kur(self, spec: ToolSpec) -> ToolConfig:
        """Adapter `os.environ`'a bakmaz; anahtarları runner seçip verir.

        Yalnızca `spec.auth_env`'de İSTENEN değişkenler geçirilir — bir tool
        başka bir tool'un anahtarını göremez.
        """
        return ToolConfig(
            env={ad: os.environ[ad] for ad in spec.auth_env if ad in os.environ},
            proxy=os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY"),
        )

    def calistir(
        self,
        adapter: Any,
        hedef: str,
        job_id: uuid.UUID | str,
        *,
        yetki_onayi: bool = False,
        cikti_formati: str = "json",
    ) -> RunSonucu:
        """Adapter'ı rate limit + retry ile çalıştırır, çıktıyı arşivler.

        İSTİSNA FIRLATMAZ: bozuk bir API yanıtı ya da düşmüş bir servis turu
        değil yalnızca bu işi düşürür.
        """
        spec: ToolSpec = adapter.spec
        engel = yetki_engeli(spec, yetki_onayi)
        if engel is not None:
            # Yetki engeli tekrar DENENMEZ: onay yokken beş kez denemek de
            # onay üretmez. Deneme sayacı da artmaz, çünkü hiç denenmedi.
            return engel

        basla = time.monotonic()
        butce = spec.toplam_butce_sn()
        sonuc: RunSonucu | None = None

        for deneme in range(1, max(1, spec.max_deneme) + 1):
            # RATE LIMIT — her denemeden önce. Retry'ın kendisi de bir istektir;
            # 429 yiyip hemen tekrar vurmak sorunu büyütür.
            bekleme = self._hiz.bekleme_suresi(spec.name, spec.dakikalik_istek)
            if bekleme > 0:
                log.info("%s: hız sınırı, %.1f sn bekleniyor", spec.name, bekleme)
                time.sleep(bekleme)

            sonuc = self._tek_deneme(adapter, hedef, job_id, cikti_formati, deneme)

            if not gecici_mi(sonuc.cikis_kodu, sonuc.durum):
                return sonuc  # başarılı ya da kalıcı hata — bitti
            if deneme >= spec.max_deneme:
                break

            # TOPLAM BÜTÇE KONTROLÜ. `timeout_sn` tek deneme içindir; kuyrukta
            # bekleyen işleri koruyan tavan budur. Bir sonraki deneme + bekleme
            # bütçeye sığmıyorsa retry'dan VAZGEÇİLİR — yarım kalacağı belli
            # olan bir denemeyi başlatmak yalnızca zaman yakar.
            gecen = time.monotonic() - basla
            gecikme = self._gecikme(spec, deneme)
            # Bütçe bir SON TARİHTİR: geçtiyse YENİ deneme başlatılmaz.
            # Bir sonraki deneme için tam `timeout_sn` kadar yer aramayız —
            # öyle yapılırsa en kötü hâl bütçeye tıpatıp eşit olduğu için son
            # deneme HER ZAMAN iptal edilir ve `max_deneme` bir eksik çalışır.
            # Bedeli: başlamış bir deneme bitene kadar sürebildiği için gerçek
            # süre bütçeyi en fazla bir `timeout_sn` kadar aşabilir.
            if gecen + gecikme >= butce:
                log.warning(
                    "%s: toplam bütçe (%.0f sn) doldu, %d. denemeden sonra durdu",
                    spec.name,
                    butce,
                    deneme,
                )
                break

            log.info(
                "%s: geçici hata (kod=%s), %.1f sn sonra %d. deneme",
                spec.name,
                sonuc.cikis_kodu,
                gecikme,
                deneme + 1,
            )
            time.sleep(gecikme)

        return sonuc if sonuc is not None else RunSonucu(durum=JobStatus.FAILED)

    def _gecikme(self, spec: ToolSpec, deneme: int) -> float:
        """Üstel geri çekilme + jitter.

        JITTER NEDEN ŞART: aynı anda kuyruğa giren on iş, aynı anda 502 yiyip
        aynı anda 2 saniye bekler ve aynı anda tekrar vurur. Sunucu dalga dalga
        dövülür ("thundering herd") ve iyileşmesi zorlaşır. Rastgelelik
        denemeleri zamana yayar.
        """
        taban = spec.geri_cekilme(deneme)
        oran = max(0.0, self.cfg.jitter_orani)
        if oran == 0.0:
            return taban
        return taban * (1.0 + random.uniform(-oran, oran))

    def _tek_deneme(
        self,
        adapter: Any,
        hedef: str,
        job_id: uuid.UUID | str,
        cikti_formati: str,
        deneme: int,
    ) -> RunSonucu:
        """Tek çağrı: süreli çalıştır, çıktıyı arşivle, sonucu sınıflandır."""
        spec: ToolSpec = adapter.spec
        baslangic = time.monotonic()
        ham: RawResult | None = None
        hata: str | None = None
        durum = JobStatus.SUCCESS
        tasima_hatasi = False

        # TIMEOUT'U RUNNER UYGULAR, adapter'a güvenilmez. Adapter kendi
        # httpx timeout'unu unutsa ya da yanlış verse bile iş burada kesilir.
        # SINIRI: Python thread'i dışarıdan öldürülemez; süre dolduğunda iş
        # TIMEOUT sayılır ve sonucu atılır, arkadaki istek kendi hâlinde biter.
        # Container yolundaki `kill()` kadar kesin değildir — API tool'unun
        # bırakabileceği tek iz açık bir soket olduğu için kabul edilebilir.
        havuz = ThreadPoolExecutor(max_workers=1)
        try:
            gorev = havuz.submit(adapter.calistir, hedef, self._cfg_kur(spec))
            try:
                ham = gorev.result(timeout=spec.timeout_sn)
            except FuturesTimeout:
                durum = JobStatus.TIMEOUT
                hata = f"timeout: {spec.timeout_sn} sn asildi"
                gorev.cancel()
            except OSError as e:
                # ConnectionError, TimeoutError ve soket hataları OSError
                # altındadır: bunlar TAŞIMA katmanı arızasıdır, geçicidir.
                # RawResult sözleşmesindeki -1 ile aynı anlama gelir.
                # (Adapter'ın tercih edilen davranışı zaten istisna fırlatmak
                # değil -1 döndürmektir; bu dal onu unutan adapter'ı kurtarır.)
                durum = JobStatus.FAILED
                tasima_hatasi = True
                hata = f"{type(e).__name__}: {e}"[:_HATA_SINIRI]
            except Exception as e:  # noqa: BLE001 — hata izolasyonu
                # Taşıma dışı istisna = adapter hatası. Tekrar denemek düzeltmez.
                durum = JobStatus.FAILED
                hata = f"{type(e).__name__}: {e}"[:_HATA_SINIRI]
        finally:
            havuz.shutdown(wait=False)

        sure_ms = int((time.monotonic() - baslangic) * 1000)

        if ham is not None and ham.cikis_kodu != 0:
            # Adapter HTTP hatasını çıkış kodu olarak bildirdi (ör. crt.sh 502).
            durum = JobStatus.FAILED
            hata = hata or f"tool cikis kodu {ham.cikis_kodu}"

        # Ham çıktı BAŞARISIZ durumda da yazılır: 502 gövdesi bile
        # "bu iş neden düştü" sorusunun kanıtıdır (İlke 2). Son deneme neyse
        # arşivde o kalır; her deneme bir öncekinin üzerine yazar.
        ham_ref: str | None = None
        icerik = ham.icerik if ham is not None else b""
        try:
            ham_ref = ham_yaz(self.cfg.raw_kok, job_id, icerik, cikti_formati)
        except OSError as e:
            hata = f"{hata or ''} | ham cikti yazilamadi: {e}".strip(" |")

        if deneme > 1 and hata:
            hata = f"{deneme}. deneme: {hata}"

        return RunSonucu(
            durum=durum,
            ham=RawResult(
                icerik=icerik,
                format=(ham.format if ham is not None else cikti_formati),
                cikis_kodu=(ham.cikis_kodu if ham is not None else -1),
                sure_ms=sure_ms,
                meta={"ham_cikti_ref": ham_ref},
            ),
            ham_cikti_ref=ham_ref,
            cikis_kodu=(
                ham.cikis_kodu
                if ham is not None
                else (-1 if tasima_hatasi else None)
            ),
            sure_ms=sure_ms,
            hata_mesaji=hata,
            deneme=deneme,
        )


# --------------------------------------------------------------------------- #
# Dağıtıcı
# --------------------------------------------------------------------------- #


class ToolRunner:
    """`spec.calistirma` alanına bakıp doğru koşucuyu seçer.

    Çağıran (worker) hangi tool'un container'da hangisinin API üzerinden
    koştuğunu BİLMEZ. Yeni bir çalıştırma biçimi eklendiğinde değişecek tek
    yer burasıdır; worker ve arayüz dokunulmadan kalır.
    """

    def __init__(
        self,
        cfg: RunnerConfig | None = None,
        client: Any = None,
        hiz: HizSinirlayici | None = None,
    ) -> None:
        self.cfg = cfg or RunnerConfig()
        # TEK sınırlayıcı: aynı tool iki yoldan da koşsa hız sınırı ortak kalır.
        self.hiz = hiz or HizSinirlayici()
        self.container = ContainerRunner(self.cfg, client=client, hiz=self.hiz)
        self.api = ApiRunner(self.cfg, hiz=self.hiz)

    def calistir(
        self,
        adapter: Any,
        hedef: str,
        job_id: uuid.UUID | str,
        *,
        yetki_onayi: bool = False,
        komut: list[str] | None = None,
        cikti_formati: str = "json",
    ) -> RunSonucu:
        bicim = getattr(adapter, "cikti_formati", cikti_formati)
        calistirma = adapter.spec.calistirma

        if calistirma == "docker":
            return self.container.calistir(
                adapter.spec,
                hedef,
                job_id,
                yetki_onayi=yetki_onayi,
                komut=komut,
                cikti_formati=bicim,
            )
        if calistirma == "api":
            return self.api.calistir(
                adapter,
                hedef,
                job_id,
                yetki_onayi=yetki_onayi,
                cikti_formati=bicim,
            )
        return RunSonucu(
            durum=JobStatus.FAILED,
            hata_mesaji=(
                f"{adapter.spec.name}: bilinmeyen calistirma bicimi "
                f"{calistirma!r} (beklenen: docker | api)"
            ),
        )
