"""UÇTAN UCA — Hafta 2'nin bitiş çizgisi.

Mimarinin tamamının tek akışta çalıştığını kanıtlar:
    API (investigation + job) -> worker -> runner -> container ->
    parse() -> ingest() -> veritabanı -> arayüz

Mock YOK. subfinder gerçekten koşar, gerçek subdomain'ler veritabanına düşer.
Hedef `example.com` — IANA'nın ayrılmış dokümantasyon domain'i; gerçek bir
hedef/müşteri değildir (docs/kapsam.md Bölüm 9).

Bu testler YAVAŞTIR (container + ağ). Atlamak için:
    pytest -m "not slow"

Nerede koşar: `osint-data` ağına bağlı VE docker soketi olan bir container.
    docker compose run --rm worker python -m pytest tests/test_e2e.py -v
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.models import Entity, Investigation, Job, JobStatus
from app.models import Observation as ObservationRow

load_dotenv()

_URL = os.getenv("ALEMBIC_DATABASE_URL") or os.getenv("DATABASE_URL")

HEDEF = "example.com"

pytestmark = pytest.mark.slow


# --------------------------------------------------------------------------- #
# Fixture'lar
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def engine():
    if not _URL:
        pytest.skip("DATABASE_URL tanımlı değil")
    eng = create_engine(_URL, poolclass=NullPool, future=True)
    try:
        with eng.connect() as c:
            c.execute(select(1))
    except SQLAlchemyError as e:
        pytest.skip(f"PostgreSQL'e bağlanılamadı: {e}")
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def docker_var():
    """Runner gerçek Docker'a ihtiyaç duyar; worker container'ında soket mount'lu."""
    import docker
    from docker.errors import DockerException

    try:
        c = docker.from_env()
        c.ping()
    except DockerException as e:
        pytest.skip(f"Docker soketine erişilemedi: {e}")
    try:
        c.images.get("osint-subfinder:1.0")
    except docker.errors.ImageNotFound:
        pytest.skip(
            "osint-subfinder:1.0 imajı yok — "
            "docker build -t osint-subfinder:1.0 tools-images/subfinder/"
        )
    return c


@pytest.fixture
def inv_id(engine):
    """Her test kendi araştırmasında; sonunda CASCADE ile temizlenir."""
    with Session(engine) as s:
        inv = Investigation(
            ad=f"e2e-{uuid.uuid4()}",
            kok_hedef=HEDEF,
            olusturan="pytest-e2e",
            yetki_onayi=False,  # subfinder P0, onay istemez
        )
        s.add(inv)
        s.commit()
        iid = inv.id
    yield iid
    with Session(engine) as s:
        s.query(Investigation).filter_by(id=iid).delete()
        s.commit()


# --------------------------------------------------------------------------- #
# Asıl akış
# --------------------------------------------------------------------------- #


def test_ucdan_uca_subfinder(engine, docker_var, inv_id):
    """domain gir -> job kuyruğa -> worker -> container -> entity'ler DB'de."""
    from app.ingest import upsert_entity
    from app.main import registry
    from app.normalize import EntityType
    from app.worker import job_calistir

    adapter = registry().get("subfinder")
    assert adapter is not None, "subfinder registry'de yok"

    # 1) Kök hedefi varlık yap ve işi kuyruğa al (POST /run'ın yaptığı)
    with Session(engine) as s:
        kok = upsert_entity(s, inv_id, EntityType.DOMAIN, HEDEF, HEDEF)
        job = Job(
            investigation_id=inv_id,
            tool="subfinder",
            tool_version=adapter.spec.version,
            hedef_entity_id=kok.id,
            hedef_deger=HEDEF,
            durum=JobStatus.QUEUED.value,
            derinlik=0,
        )
        s.add(job)
        s.commit()
        job_id = job.id

    # 2) Worker görevini SENKRON çağır (broker'a ihtiyaç duymadan aynı kod yolu)
    sonuc = job_calistir(str(job_id))

    # 3) job son durumu
    with Session(engine) as s:
        job = s.get(Job, job_id)
        assert job.durum == JobStatus.SUCCESS.value, (
            f"job başarısız: durum={job.durum} hata={job.hata_mesaji}"
        )
        assert job.cikis_kodu == 0
        assert job.baslangic is not None and job.bitis is not None
        assert job.sure_ms and job.sure_ms > 0

        # 4) En az bir SUBDOMAIN entity'si oluşmuş olmalı
        subler = (
            s.execute(
                select(Entity).where(
                    Entity.investigation_id == inv_id, Entity.tip == "subdomain"
                )
            )
            .scalars()
            .all()
        )
        assert len(subler) >= 1, "hiç subdomain bulunamadı"
        assert all(e.deger_norm.endswith(f".{HEDEF}") for e in subler)

        # 5) İlke 2: gözlemde ham çıktı referansı DOLU ve dosya DİSKTE VAR
        obs = (
            s.execute(
                select(ObservationRow).where(ObservationRow.entity_id == subler[0].id)
            )
            .scalars()
            .all()
        )
        assert obs, "subdomain'in gözlemi yok"
        o = obs[0]
        assert o.tool == "subfinder"
        assert o.guven == adapter.spec.varsayilan_guven
        assert o.ham_cikti_ref, "ham_cikti_ref boş"
        assert o.ham_cikti_yol, "ham_cikti_yol boş"

        ham_yol = Path(o.ham_cikti_ref)
        assert ham_yol.is_file(), f"ham çıktı diskte yok: {ham_yol}"
        assert ham_yol.stat().st_size > 0
        assert str(job_id) in str(ham_yol), "ham çıktı job_id klasöründe değil"
        # Arşiv gerçekten tool'un çıktısı mı
        assert b'"host"' in ham_yol.read_bytes()

    assert sonuc["durum"] == JobStatus.SUCCESS.value
    assert sonuc["gozlem"] >= 1


def test_ucdan_uca_iliskiler_ve_kok_domain(engine, docker_var, inv_id):
    """subdomain_of ilişkileri kurulmuş ve kök hedef DOMAIN olarak durmalı."""
    from app.ingest import upsert_entity
    from app.models import Relationship
    from app.normalize import EntityType
    from app.worker import job_calistir

    with Session(engine) as s:
        kok = upsert_entity(s, inv_id, EntityType.DOMAIN, HEDEF, HEDEF)
        job = Job(
            investigation_id=inv_id,
            tool="subfinder",
            tool_version="2.14.0",
            hedef_entity_id=kok.id,
            hedef_deger=HEDEF,
            durum=JobStatus.QUEUED.value,
        )
        s.add(job)
        s.commit()
        job_id = job.id

    job_calistir(str(job_id))

    with Session(engine) as s:
        # Kök hedef DOMAIN olarak duruyor (parser SUBDOMAIN etiketlese de)
        kok_ent = s.execute(
            select(Entity).where(
                Entity.investigation_id == inv_id,
                Entity.tip == "domain",
                Entity.deger_norm == HEDEF,
            )
        ).scalar_one()

        rel_sayisi = s.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(
                Relationship.investigation_id == inv_id,
                Relationship.hedef_entity_id == kok_ent.id,
                Relationship.tip == "subdomain_of",
            )
        )
        assert rel_sayisi >= 1, "subdomain_of ilişkisi kurulmamış"


def test_worker_bilinmeyen_toolda_cokmez(engine, inv_id):
    """Bozuk iş worker'ı düşürmemeli — job 'failed' olmalı (İlke 5)."""
    from app.worker import job_calistir

    with Session(engine) as s:
        job = Job(
            investigation_id=inv_id,
            tool="yok-boyle-bir-tool",
            tool_version="0",
            hedef_deger=HEDEF,
            durum=JobStatus.QUEUED.value,
        )
        s.add(job)
        s.commit()
        job_id = job.id

    sonuc = job_calistir(str(job_id))  # istisna FIRLATMAMALI
    assert sonuc["durum"] == JobStatus.FAILED.value

    with Session(engine) as s:
        job = s.get(Job, job_id)
        assert job.durum == JobStatus.FAILED.value
        assert "kayıtlı değil" in (job.hata_mesaji or "")


def test_olmayan_job_cokmez():
    from app.worker import job_calistir

    sonuc = job_calistir(str(uuid.uuid4()))
    assert sonuc["durum"] == "bulunamadi"


# --------------------------------------------------------------------------- #
# Arayüz — aynı akış HTTP üzerinden
# --------------------------------------------------------------------------- #


@pytest.fixture
def istemci():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


def test_arayuz_acilyor(istemci):
    r = istemci.get("/")
    assert r.status_code == 200
    # ZORUNLU UYARI kaldırılmamış olmalı
    assert "Yalnızca yetkili olduğunuz hedeflerde kullanın" in r.text


def test_arayuz_arastirma_olustur_ve_calistir(engine, istemci):
    r = istemci.post(
        "/investigations",
        data={
            "ad": f"ui-{uuid.uuid4()}",
            "kok_hedef": "https://WWW.Example.COM/yol",  # normalize edilmeli
            "olusturan": "pytest",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    inv_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])

    try:
        with Session(engine) as s:
            inv = s.get(Investigation, inv_id)
            # www.example.com girildi ama kök domain'e indirildi
            assert inv.kok_hedef == "example.com"
            assert inv.yetki_onayi is False

        sayfa = istemci.get(f"/investigations/{inv_id}")
        assert sayfa.status_code == 200
        assert "subfinder" in sayfa.text

        # HTMX parçası 2 saniyede bir yenileniyor
        assert 'hx-trigger="load, every 2s"' in sayfa.text

        parca = istemci.get(f"/investigations/{inv_id}/entities")
        assert parca.status_code == 200

        # İşi kuyruğa at (broker yoksa bile job satırı oluşmalı)
        r = istemci.post(
            f"/investigations/{inv_id}/run",
            data={"tool": "subfinder"},
            follow_redirects=False,
        )
        assert r.status_code == 303

        with Session(engine) as s:
            job = s.execute(
                select(Job).where(Job.investigation_id == inv_id)
            ).scalar_one()
            assert job.tool == "subfinder"
            assert job.hedef_deger == "example.com"
            assert job.derinlik == 0
    finally:
        with Session(engine) as s:
            s.query(Investigation).filter_by(id=inv_id).delete()
            s.commit()


def test_arayuz_gecersiz_kok_hedef_reddedilir(istemci):
    r = istemci.post(
        "/investigations",
        data={"ad": "kotu", "kok_hedef": "localhost"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_arayuz_bilinmeyen_tool_reddedilir(engine, istemci, inv_id):
    r = istemci.post(
        f"/investigations/{inv_id}/run",
        data={"tool": "yok-boyle"},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_varlik_sayfasi_ham_cikti_yolunu_gosterir(engine, istemci, inv_id):
    """İlke 2: arayüzde ham çıktı referansı GÖRÜNMELİ."""
    from app.ingest import upsert_entity
    from app.normalize import EntityType

    with Session(engine) as s:
        e = upsert_entity(s, inv_id, EntityType.SUBDOMAIN, "a.example.com", "a.example.com")
        job = Job(
            investigation_id=inv_id,
            tool="subfinder",
            tool_version="2.14.0",
            hedef_deger="example.com",
            durum=JobStatus.SUCCESS.value,
        )
        s.add(job)
        s.commit()
        s.add(
            ObservationRow(
                entity_id=e.id,
                job_id=job.id,
                tool="subfinder",
                tool_version="2.14.0",
                ham_cikti_ref="/data/raw/deneme/output.jsonl",
                ham_cikti_yol="$[7].host",
                guven=70,
            )
        )
        s.commit()
        eid = e.id

    r = istemci.get(f"/entities/{eid}")
    assert r.status_code == 200
    assert "/data/raw/deneme/output.jsonl" in r.text
    assert "$[7].host" in r.text
