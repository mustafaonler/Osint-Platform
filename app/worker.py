"""Celery worker — bir job'ı uçtan uca çalıştırır.

Zincir: job 'running' → runner.calistir() → adapter.parse() → ingest()
        → job 'success' / 'failed' / 'timeout' / 'skipped'

Bu modül, mimarinin bütün katmanlarını birbirine bağlayan tek yerdir. Kendisi
iş mantığı taşımaz; sıralamayı kurar ve `job` satırını güncel tutar.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from celery import Celery
from dotenv import load_dotenv
from sqlalchemy import func, select

from app.db import SessionLocal
from app.ingest import ingest
from app.models import Investigation, Job, JobStatus
from app.runner import RunSonucu, ToolRunner
from app.limits import RedisLimitleri
from app.tools._base import RawResult, ToolAdapter, ToolRegistry

load_dotenv()

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
TOOL_KOK = Path(__file__).resolve().parent / "tools"

celery_app = Celery("osint", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    # Bir tool ne kadar uzun koşarsa koşsun timeout'u RUNNER uygular
    # (spec.timeout_sn). Buradaki tavan yalnızca son çare emniyet supabıdır.
    task_time_limit=1800,
)

_registry: ToolRegistry | None = None
_runner: ToolRunner | None = None


def registry() -> ToolRegistry:
    """Tool keşfi bir kez yapılır, worker ömrü boyunca yaşar."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry(TOOL_KOK)
    return _registry


def runner() -> ToolRunner:
    """`spec.calistirma` alanına bakıp container ya da API yolunu seçen dağıtıcı.

    Worker hangi tool'un nasıl koştuğunu BİLMEZ; yeni bir çalıştırma biçimi
    eklendiğinde burası değil `ToolRunner` değişir.
    """
    global _runner
    if _runner is None:
        _runner = ToolRunner(hiz=RedisLimitleri.from_url(REDIS_URL))
    return _runner


def kuyruga_gonder(job_id) -> bool:
    """Celery'ye görev gönderir. Broker yoksa iş `queued` kalır, istisna yok.

    `ingest()` yalnızca `job` satırını yazar; görevi dağıtan burasıdır. İkisi
    ayrı olduğu için satır yazılıp görev gönderilmemesi MÜMKÜNDÜR ve tam olarak
    bu hata Hafta 4 ölçümünde yakalandı: 154 zincirleme iş sonsuza kadar
    `queued` durumunda bekledi çünkü `send_task` yalnızca arayüzde vardı.
    """
    try:
        celery_app.send_task("osint.job_calistir", args=[str(job_id)])
        return True
    except Exception:  # noqa: BLE001 — broker yoksa tur düşmez
        log.warning("job %s kuyruğa gönderilemedi, 'queued' bekliyor", job_id)
        return False


@celery_app.task(name="osint.ai_skorla", bind=True)
def ai_skorla(self, inv_id: str) -> dict:  # noqa: ANN001
    """Bir araştırmayı AI ile skorlar. ASLA İSTİSNA SIZDIRMAZ.

    Tool işlerinden AYRI tutulur ve `job` satırı yazmaz: skorlama bir keşif
    adımı değil, mevcut veri üzerinde bir görünüm hesabıdır. Zincirleme
    tetiklemez, `uq_job_tekrar` kısıtına da girmez.
    """
    from app.ai.provider import GeminiProvider
    from app.ai.skorla import skorla

    try:
        saglayici = GeminiProvider()
        if not saglayici.hazir:
            # Eksik yapılandırma arıza değildir (kapsam.md Bölüm 5.3).
            log.warning("GEMINI_API_KEY tanımlı değil; skorlama atlandı")
            return {"investigation_id": inv_id, "durum": "skipped"}

        with SessionLocal() as session:
            ozet = skorla(session, uuid.UUID(str(inv_id)), saglayici)
            session.commit()
        log.info(
            "skorlama: %d skor, %d hipotez, %d önbellek, %d halüsinasyon",
            ozet.skor_yazilan, ozet.hipotez_yazilan,
            ozet.atlanan_onbellek, ozet.halusinasyon,
        )
        return {
            "investigation_id": inv_id,
            "durum": "success" if ozet.basarili or not ozet.hatalar else "failed",
            "skor": ozet.skor_yazilan,
            "hipotez": ozet.hipotez_yazilan,
            "halusinasyon": ozet.halusinasyon,
            "hatalar": ozet.hatalar[:5],
        }
    except Exception as e:  # noqa: BLE001 — worker çökmemeli
        log.exception("skorlama %s beklenmedik hata", inv_id)
        return {"investigation_id": inv_id, "durum": "failed", "hata": str(e)}


def skorlamayi_gonder(inv_id) -> bool:
    """Celery'ye skorlama görevi gönderir. Broker yoksa istisna fırlatmaz."""
    try:
        celery_app.send_task("osint.ai_skorla", args=[str(inv_id)])
        return True
    except Exception:  # noqa: BLE001
        log.warning("araştırma %s skorlamaya gönderilemedi", inv_id)
        return False


def _simdi() -> datetime:
    return datetime.now(timezone.utc)


def _komut(adapter: ToolAdapter, hedef: str) -> list[str] | None:
    """Adapter kendi argümanlarını kurar; runner yalnızca çalıştırır."""
    kurucu = getattr(adapter, "komut", None)
    return kurucu(hedef) if callable(kurucu) else None


def _cikti_formati(adapter: ToolAdapter) -> str:
    """Ham çıktı dosyasının uzantısı. Adapter bildirmezse 'json'.

    `ToolSpec`'e alan eklemek yerine hafif bir sınıf değişkeni yeterli:
    yalnızca arşiv dosyasının adını etkiler, yetenek grafiğini değil.
    """
    return getattr(adapter, "cikti_formati", "json")


@celery_app.task(name="osint.job_calistir", bind=True)
def job_calistir(self, job_id: str) -> dict:  # noqa: ANN001
    """Bir job'ı çalıştırır. ASLA İSTİSNA SIZDIRMAZ.

    Bozuk bir tool ya da beklenmedik bir hata worker'ı düşürmemelidir (İlke 5:
    hata izolasyonu). Her çıkış yolu `job` satırını bir son duruma yazar;
    'running' durumunda asılı kalan job bırakılmaz.
    """
    try:
        return _job_calistir(uuid.UUID(str(job_id)))
    except Exception as e:  # noqa: BLE001 — worker çökmemeli
        log.exception("job %s beklenmedik hata", job_id)
        _durumu_isaretle(job_id, JobStatus.FAILED, f"beklenmedik hata: {e}")
        return {"job_id": str(job_id), "durum": JobStatus.FAILED.value, "hata": str(e)}


def _durumu_isaretle(job_id, durum: JobStatus, hata: str | None) -> None:
    """Son çare: ana akış çöktüyse bile job'u son duruma yaz."""
    try:
        with SessionLocal() as s:
            job = s.get(Job, uuid.UUID(str(job_id)))
            if job is None:
                return
            job.durum = durum.value
            job.hata_mesaji = (hata or "")[:2000]
            job.bitis = _simdi()
            s.commit()
    except Exception:  # noqa: BLE001
        log.exception("job %s durumu yazılamadı", job_id)


def _job_calistir(job_id: uuid.UUID) -> dict:
    with SessionLocal() as session:
        job = session.get(Job, job_id)
        if job is None:
            log.error("job %s bulunamadı", job_id)
            return {"job_id": str(job_id), "durum": "bulunamadi"}

        inv = session.get(Investigation, job.investigation_id)
        adapter = registry().get(job.tool)

        # 1) Çalıştırılabilir mi?
        if adapter is None:
            return _bitir(
                session, job, JobStatus.FAILED, hata=f"tool kayıtlı değil: {job.tool}"
            )
        if inv is None:
            return _bitir(session, job, JobStatus.FAILED, hata="araştırma bulunamadı")

        # 2) running
        job.durum = JobStatus.RUNNING.value
        job.baslangic = _simdi()
        job.tool_version = adapter.spec.version
        session.commit()

        # 3) Container'da çalıştır. Yetki kontrolü RUNNER'da yapılır —
        #    arayüz atlanabilir, runner atlanamaz.
        sonuc: RunSonucu = runner().calistir(
            adapter,
            job.hedef_deger,
            job.id,
            yetki_onayi=bool(inv.yetki_onayi),
            komut=_komut(adapter, job.hedef_deger),
            cikti_formati=_cikti_formati(adapter),
        )

        # 4) Ayrıştır + ingest.
        #    TIMEOUT'ta da ingest edilir: kesilmiş çıktıdaki bulgular gerçek
        #    bulgulardır, onları atmak veri kaybı olurdu. Job yine 'timeout'
        #    kalır, yani turun eksik olduğu görünür.
        ozet = None
        if sonuc.durum in (JobStatus.SUCCESS, JobStatus.TIMEOUT) and sonuc.ham:
            ozet = _ayristir_ve_yaz(
                session, job, adapter, sonuc, list(inv.secili_toollar or ())
            )

        return _bitir(
            session,
            job,
            sonuc.durum,
            hata=sonuc.hata_mesaji,
            cikis_kodu=sonuc.cikis_kodu,
            sure_ms=sonuc.sure_ms,
            deneme=sonuc.deneme,
            ozet=ozet,
        )


def _ayristir_ve_yaz(session, job: Job, adapter: ToolAdapter, sonuc: RunSonucu,
                     secili_toollar: list[str] | None = None):
    """parse() + ingest(). Ayrıştırma hatası turu düşürmez, job'u failed yapmaz.

    `parse()` sözleşme gereği istisna fırlatmaz; yine de bozuk bir adapter
    yüzünden container'ın gerçekten koştuğu bilgisini kaybetmeyelim.
    """
    try:
        gozlemler = adapter.parse(sonuc.ham or RawResult(icerik=b"", format="json"))
    except Exception:  # noqa: BLE001
        log.exception("%s: parse() patladı, gözlem yazılmadı", job.tool)
        return None

    ozet = ingest(
        session,
        job,
        gozlemler,
        spec=adapter.spec,
        ham_cikti_ref=sonuc.ham_cikti_ref or "",
        registry=registry(),
        secili_toollar=secili_toollar,
    )
    session.commit()

    # GÖNDERİM COMMIT'TEN SONRA. Önce gönderilirse yarış oluşur: Celery
    # görevi, `job` satırı henüz görünür olmadan başka bir worker tarafından
    # alınabilir ve "job bulunamadı" ile düşer.
    for jid in ozet.kuyruk_idleri:
        kuyruga_gonder(jid)

    log.info(
        "%s: %d gözlem, %d ilişki, %d yeni iş (atlanan %d)",
        job.tool,
        ozet.observation_sayisi,
        ozet.relationship_sayisi,
        ozet.kuyruga_alinan,
        ozet.atlanan,
    )
    return ozet


def _bitir(
    session,
    job: Job,
    durum: JobStatus,
    *,
    hata: str | None = None,
    cikis_kodu: int | None = None,
    sure_ms: int | None = None,
    deneme: int = 0,
    ozet=None,
) -> dict:
    job.durum = durum.value
    job.bitis = _simdi()
    job.hata_mesaji = (hata or None) and hata[:2000]
    job.cikis_kodu = cikis_kodu
    job.sure_ms = sure_ms
    job.deneme_sayisi = deneme
    session.commit()

    skorlama = _tur_bittiyse_skorla(session, job.investigation_id)
    return {
        "job_id": str(job.id),
        "tool": job.tool,
        "hedef": job.hedef_deger,
        "durum": durum.value,
        "deneme": job.deneme_sayisi,
        "gozlem": ozet.observation_sayisi if ozet else 0,
        "kuyruga_alinan": ozet.kuyruga_alinan if ozet else 0,
        "skorlama_tetiklendi": skorlama,
    }


def _tur_bittiyse_skorla(session, inv_id) -> bool:
    """Araştırmada bekleyen iş kalmadıysa AI skorlamasını tetikler.

    Analist elle düğmeye basmak zorunda kalmasın diye: toplama biter bitmez
    önceliklendirme de hazır olmalı. Sayım COMMIT SONRASI yapılır — bu işin
    kendi son durumu da görünsün.

    YARIŞ: iki iş neredeyse aynı anda bitip ikisi de "sıfır kaldı" görebilir,
    yani skorlama iki kez kuyruğa girebilir. Kilit KOYULMADI çünkü bedeli yok:
    `assessment.girdi_hash` sayesinde ikinci koşu aynı girdiyi önbellekte bulur
    ve modele HİÇ gitmez. Kilit, kazandırdığından fazla karmaşıklık getirirdi.
    """
    kalan = session.execute(
        select(func.count())
        .select_from(Job)
        .where(
            Job.investigation_id == inv_id,
            Job.durum.in_([JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
        )
    ).scalar_one()
    if kalan:
        return False
    log.info("araştırma %s: tur bitti, skorlama tetikleniyor", inv_id)
    return skorlamayi_gonder(inv_id)
