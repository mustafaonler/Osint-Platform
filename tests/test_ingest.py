"""`upsert_entity` / `upsert_relationship` — GERÇEK PostgreSQL'e karşı.

SQLite KULLANILMAZ: `ON CONFLICT DO UPDATE` davranışı, kısıt adıyla hedefleme
(`constraint="uq_entity"`) ve satır kilitleme semantiği farklıdır. Bu testlerin
tek amacı zaten paralel worker'lardaki yarış koşulunun çözüldüğünü göstermek —
onu ancak gerçek sunucu doğrulayabilir.

Bağlantı: `ALEMBIC_DATABASE_URL` (host tarafı, localhost:5432).
Veritabanı şemalı olmalı: `python -m alembic upgrade head`
"""

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from app.ingest import upsert_entity, upsert_relationship
from app.models import Entity, Investigation, Relationship
from app.normalize import EntityType

load_dotenv()

_URL = os.getenv("ALEMBIC_DATABASE_URL") or os.getenv("DATABASE_URL")

PARALEL = 10


# --------------------------------------------------------------------------- #
# Fixture'lar — veritabanı KİRLETİLMEZ
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def engine():
    if not _URL:
        pytest.skip("ALEMBIC_DATABASE_URL/DATABASE_URL tanımlı değil")
    # NullPool: eşzamanlılık testinde 10 thread'in havuz sırasında beklemesini
    # değil, gerçekten 10 ayrı bağlantı açmasını istiyoruz.
    eng = create_engine(_URL, poolclass=NullPool, future=True)
    try:
        with eng.connect() as c:
            c.execute(select(1))
    except SQLAlchemyError as e:
        pytest.skip(f"PostgreSQL'e bağlanılamadı: {e}")
    yield eng
    eng.dispose()


def _investigation_olustur(session: Session, ad: str) -> uuid.UUID:
    inv = Investigation(
        ad=ad,
        kok_hedef="firma.com",
        olusturan="pytest",
    )
    session.add(inv)
    session.commit()
    return inv.id


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture
def inv_id(engine):
    """Her test kendi araştırmasında çalışır; sonunda CASCADE ile silinir."""
    with Session(engine) as s:
        iid = _investigation_olustur(s, f"test-{uuid.uuid4()}")
    yield iid
    with Session(engine) as s:
        # investigation silinince entity/relationship ON DELETE CASCADE ile gider
        s.query(Investigation).filter_by(id=iid).delete()
        s.commit()


def _sayim(session: Session, iid: uuid.UUID) -> int:
    return session.scalar(
        select(func.count()).select_from(Entity).where(Entity.investigation_id == iid)
    )


# --------------------------------------------------------------------------- #
# upsert_entity
# --------------------------------------------------------------------------- #


def test_ilk_upsert_tek_satir_gozlem_1(session, inv_id):
    e = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "a.firma.com", "A.Firma.com")
    session.commit()
    assert e.gozlem_sayisi == 1
    assert e.deger_norm == "a.firma.com"
    assert _sayim(session, inv_id) == 1


def test_ayni_varlik_iki_kez_tek_satir(session, inv_id):
    """Dedup'ın kalbi: aynı anahtar → tek satır, sayaç artar."""
    e1 = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "a.firma.com", "A.Firma.com")
    session.commit()
    e2 = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "a.firma.com", "a.firma.com")
    session.commit()

    assert e1.id == e2.id
    assert e2.gozlem_sayisi == 2
    assert _sayim(session, inv_id) == 1


def test_deger_ham_ilk_hali_korunur(session, inv_id):
    """Bölüm 2.2: `deger_ham` ilk görülen orijinal halidir, ezilmez."""
    upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "www.firma.com", "WWW.Firma.COM.")
    session.commit()
    e = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "www.firma.com", "www.firma.com")
    session.commit()

    assert e.deger_ham == "WWW.Firma.COM."
    assert e.gozlem_sayisi == 2


def test_son_gorulme_tazelenir_ilk_gorulme_sabit(session, inv_id):
    e1 = upsert_entity(session, inv_id, EntityType.IP, "1.2.3.4", "1.2.3.4")
    session.commit()
    ilk_gorulme, ilk_son = e1.ilk_gorulme, e1.son_gorulme

    e2 = upsert_entity(session, inv_id, EntityType.IP, "1.2.3.4", "1.2.3.4")
    session.commit()

    assert e2.ilk_gorulme == ilk_gorulme
    assert e2.son_gorulme >= ilk_son


def test_farkli_tip_ayri_satir(session, inv_id):
    """`uq_entity` tipi de kapsar: aynı değer farklı tipte ayrı varlıktır."""
    a = upsert_entity(session, inv_id, EntityType.DOMAIN, "firma.com", "firma.com")
    b = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "firma.com", "firma.com")
    session.commit()

    assert a.id != b.id
    assert _sayim(session, inv_id) == 2


def test_farkli_investigation_ayri_satir(engine, session, inv_id):
    """Araştırmalar birbirinden yalıtıktır — aynı değer ayrı satıra düşer."""
    with Session(engine) as s2:
        iid2 = _investigation_olustur(s2, f"test-ikinci-{uuid.uuid4()}")
    try:
        a = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "a.firma.com", "a.firma.com")
        b = upsert_entity(session, iid2, EntityType.SUBDOMAIN, "a.firma.com", "a.firma.com")
        session.commit()

        assert a.id != b.id
        assert _sayim(session, inv_id) == 1
        assert _sayim(session, iid2) == 1
    finally:
        with Session(engine) as s:
            s.query(Investigation).filter_by(id=iid2).delete()
            s.commit()


# --------------------------------------------------------------------------- #
# upsert_relationship
# --------------------------------------------------------------------------- #


@pytest.fixture
def iki_varlik(session, inv_id):
    a = upsert_entity(session, inv_id, EntityType.SUBDOMAIN, "a.firma.com", "a.firma.com")
    b = upsert_entity(session, inv_id, EntityType.IP, "1.2.3.4", "1.2.3.4")
    session.commit()
    return a, b


def test_upsert_relationship_idempotent(session, inv_id, iki_varlik):
    a, b = iki_varlik
    r1 = upsert_relationship(session, inv_id, a, b, "resolves_to")
    session.commit()
    r2 = upsert_relationship(session, inv_id, a, b, "resolves_to")
    session.commit()

    assert r1.id == r2.id
    assert r2.son_gorulme >= r1.ilk_gorulme
    sayi = session.scalar(
        select(func.count())
        .select_from(Relationship)
        .where(Relationship.investigation_id == inv_id)
    )
    assert sayi == 1


def test_upsert_relationship_uuid_ile_de_calisir(session, inv_id, iki_varlik):
    a, b = iki_varlik
    r1 = upsert_relationship(session, inv_id, a, b, "resolves_to")
    session.commit()
    r2 = upsert_relationship(session, inv_id, a.id, b.id, "resolves_to")
    session.commit()
    assert r1.id == r2.id


def test_farkli_tip_ayri_iliski(session, inv_id, iki_varlik):
    a, b = iki_varlik
    r1 = upsert_relationship(session, inv_id, a, b, "resolves_to")
    r2 = upsert_relationship(session, inv_id, a, b, "runs_on")
    session.commit()
    assert r1.id != r2.id


def test_kendine_iliski_sessizce_atlanir(session, inv_id, iki_varlik):
    """`ck_rel_self`'e çarpmak yerine elenir — tek bozuk gözlem turu düşürmez."""
    a, _ = iki_varlik
    assert upsert_relationship(session, inv_id, a, a, "subdomain_of") is None
    assert upsert_relationship(session, inv_id, a.id, a.id, "subdomain_of") is None
    session.commit()

    sayi = session.scalar(
        select(func.count())
        .select_from(Relationship)
        .where(Relationship.investigation_id == inv_id)
    )
    assert sayi == 0


# --------------------------------------------------------------------------- #
# EŞZAMANLILIK — en kritik test
# --------------------------------------------------------------------------- #


def test_paralel_upsert_tek_satir(engine, inv_id):
    """10 thread, 10 AYRI bağlantı, aynı anahtar → TEK satır, sayaç 10.

    `SELECT` + `INSERT` deseni bu testte ya `IntegrityError` verir ya da
    mükerrer satır üretir. `ON CONFLICT DO UPDATE` ikisini de yapmaz.
    """
    engel = threading.Barrier(PARALEL, timeout=30)
    hatalar: list[BaseException] = []
    kilit = threading.Lock()

    def gorev(i: int) -> None:
        try:
            with Session(engine) as s:
                # Bağlantıyı barrier'dan ÖNCE aç: aksi halde thread'ler
                # bağlantı kurmayı sıraya sokar ve çakışma hiç yaşanmaz.
                s.execute(select(1))
                engel.wait()
                upsert_entity(
                    s, inv_id, EntityType.SUBDOMAIN, "yaris.firma.com", f"ham-{i}"
                )
                s.commit()
        except BaseException as e:  # IntegrityError dahil her şey yakalanır
            with kilit:
                hatalar.append(e)

    with ThreadPoolExecutor(max_workers=PARALEL) as ex:
        list(ex.map(gorev, range(PARALEL)))

    assert not hatalar, f"paralel upsert hata verdi: {hatalar!r}"
    assert not any(isinstance(e, IntegrityError) for e in hatalar)

    with Session(engine) as s:
        satirlar = (
            s.execute(
                select(Entity).where(
                    Entity.investigation_id == inv_id,
                    Entity.deger_norm == "yaris.firma.com",
                )
            )
            .scalars()
            .all()
        )

    assert len(satirlar) == 1, f"dedup kırık: {len(satirlar)} satır"
    assert satirlar[0].gozlem_sayisi == PARALEL
    # Kazanan hangi thread olursa olsun `deger_ham` ilk yazanın hâlinde kalır
    assert satirlar[0].deger_ham.startswith("ham-")


def test_paralel_upsert_relationship_tek_satir(engine, inv_id):
    """Aynı yarış `uq_rel` için de çözülmüş olmalı."""
    with Session(engine) as s:
        a = upsert_entity(s, inv_id, EntityType.SUBDOMAIN, "a.firma.com", "a.firma.com")
        b = upsert_entity(s, inv_id, EntityType.IP, "1.2.3.4", "1.2.3.4")
        s.commit()
        a_id, b_id = a.id, b.id

    engel = threading.Barrier(PARALEL, timeout=30)
    hatalar: list[BaseException] = []
    kilit = threading.Lock()

    def gorev(_: int) -> None:
        try:
            with Session(engine) as s:
                s.execute(select(1))
                engel.wait()
                upsert_relationship(s, inv_id, a_id, b_id, "resolves_to")
                s.commit()
        except BaseException as e:
            with kilit:
                hatalar.append(e)

    with ThreadPoolExecutor(max_workers=PARALEL) as ex:
        list(ex.map(gorev, range(PARALEL)))

    assert not hatalar, f"paralel upsert_relationship hata verdi: {hatalar!r}"
    with Session(engine) as s:
        sayi = s.scalar(
            select(func.count())
            .select_from(Relationship)
            .where(Relationship.investigation_id == inv_id)
        )
    assert sayi == 1
