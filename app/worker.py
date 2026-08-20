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

from app.db import SessionLocal
from app.ingest import ingest
from app.models import Investigation, Job, JobStatus
from app.runner import ContainerRunner, RunSonucu
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
_runner: ContainerRunner | None = None


def registry() -> ToolRegistry:
    """Tool keşfi bir kez yapılır, worker ömrü boyunca yaşar."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry(TOOL_KOK)
    return _registry


def runner() -> ContainerRunner:
    global _runner
    if _runner is None:
        _runner = ContainerRunner()
    return _runner


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
            adapter.spec,
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
            ozet = _ayristir_ve_yaz(session, job, adapter, sonuc)

        return _bitir(
            session,
            job,
            sonuc.durum,
            hata=sonuc.hata_mesaji,
            cikis_kodu=sonuc.cikis_kodu,
            sure_ms=sonuc.sure_ms,
            ozet=ozet,
        )


def _ayristir_ve_yaz(session, job: Job, adapter: ToolAdapter, sonuc: RunSonucu):
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
    )
    session.commit()
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
    ozet=None,
) -> dict:
    job.durum = durum.value
    job.bitis = _simdi()
    job.hata_mesaji = (hata or None) and hata[:2000]
    job.cikis_kodu = cikis_kodu
    job.sure_ms = sure_ms
    session.commit()
    return {
        "job_id": str(job.id),
        "tool": job.tool,
        "hedef": job.hedef_deger,
        "durum": durum.value,
        "gozlem": ozet.observation_sayisi if ozet else 0,
        "kuyruga_alinan": ozet.kuyruga_alinan if ozet else 0,
    }
