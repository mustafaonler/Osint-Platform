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


# --------------------------------------------------------------------------- #
# INGEST HATTI — docs/veri-modeli.md Bölüm 4.5
# --------------------------------------------------------------------------- #

import logging
import pathlib

from app.ingest import ingest
from app.models import MAX_DERINLIK, Job
from app.models import Observation as ObservationRow
from app.tools._base import (
    Observation,
    ObservedRelation,
    Passivity,
    RelationType,
    ToolRegistry,
    ToolSpec,
)

TOOL_KOK = pathlib.Path(__file__).resolve().parents[1] / "app" / "tools"

SAHTE_SPEC = ToolSpec(
    name="sahte",
    version="1.0",
    passivity=Passivity.P0,
    kabul_eder=frozenset({EntityType.DOMAIN}),
    uretir=frozenset({EntityType.SUBDOMAIN}),
    calistirma="docker",
    varsayilan_guven=70,
)


@pytest.fixture
def job(session, inv_id):
    j = Job(
        investigation_id=inv_id,
        tool="sahte",
        tool_version="1.0",
        hedef_deger="firma.com",
        durum="running",
        derinlik=0,
    )
    session.add(j)
    session.commit()
    return j


@pytest.fixture
def registry():
    return ToolRegistry(TOOL_KOK)


def _domain_tuketen_sayisi(registry) -> int:
    """DOMAIN'i tüketen etkin tool sayısı.

    SABİT YAZILMAZ: yeni bir DOMAIN tool'u eklendiğinde zincirleme sayısı
    kendiliğinden artar — yetenek grafiğinin işi budur. Sayıyı teste gömmek,
    her tool eklemede çekirdek testleri kırardı ve "tool eklemek ucuz" iddiası
    yalan olurdu.
    """
    return len(registry.tuketenler(EntityType.DOMAIN))


def _obs(deger_ham, tip=EntityType.SUBDOMAIN, **kw):
    return Observation(tip=tip, deger_ham=deger_ham, **kw)


def _entityler(session, iid):
    return {
        (e.tip, e.deger_norm): e
        for e in session.execute(
            select(Entity).where(Entity.investigation_id == iid)
        ).scalars()
    }


def test_ingest_entity_observation_yazar(session, inv_id, job):
    gozlemler = [
        _obs("API.Firma.com", kaynak_yol="$[0].host", nitelikler={"kaynak": "crtsh"}),
        _obs("mail.firma.com", kaynak_yol="$[1].host"),
    ]
    s = ingest(
        session, job, gozlemler, spec=SAHTE_SPEC, ham_cikti_ref="/data/raw/x/o.json"
    )
    session.commit()

    assert s.entity_sayisi == 2
    assert s.observation_sayisi == 2
    assert s.atlanan == 0

    ent = _entityler(session, inv_id)
    assert ("subdomain", "api.firma.com") in ent
    assert ("subdomain", "mail.firma.com") in ent
    # deger_ham ilk görülen hâli
    assert ent[("subdomain", "api.firma.com")].deger_ham == "API.Firma.com"

    obs = (
        session.execute(
            select(ObservationRow).where(
                ObservationRow.entity_id == ent[("subdomain", "api.firma.com")].id
            )
        )
        .scalars()
        .all()
    )
    assert len(obs) == 1
    # İlke 2: ham çıktıya kadar izlenebilirlik
    assert obs[0].ham_cikti_ref == "/data/raw/x/o.json"
    assert obs[0].ham_cikti_yol == "$[0].host"
    assert obs[0].guven == 70  # spec.varsayilan_guven
    assert obs[0].veri == {"kaynak": "crtsh"}


def test_ingest_guven_gozlemden_gelirse_onu_kullanir(session, inv_id, job):
    ingest(
        session, job, [_obs("a.firma.com", guven=95)], spec=SAHTE_SPEC, ham_cikti_ref="r"
    )
    session.commit()
    # FİLTRE ŞART: veritabanında başka araştırmalar olabilir (gerçek kullanım,
    # paralel test). Filtresiz sorgu onların satırlarını da toplar.
    obs = (
        session.execute(
            select(ObservationRow)
            .join(Entity, Entity.id == ObservationRow.entity_id)
            .where(Entity.investigation_id == inv_id)
        )
        .scalars()
        .all()
    )
    assert [o.guven for o in obs] == [95]


def test_ingest_iliskileri_cozer(session, inv_id, job):
    """Hedef varlık yoksa oluşturulur; ilişki değerlerle çözülür."""
    g = _obs(
        "api.firma.com",
        iliskiler=(
            ObservedRelation(
                tip=RelationType.SUBDOMAIN_OF,
                hedef_tip=EntityType.DOMAIN,
                hedef_deger="firma.com",
            ),
        ),
    )
    s = ingest(session, job, [g], spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    assert s.relationship_sayisi == 1
    ent = _entityler(session, inv_id)
    assert ("domain", "firma.com") in ent  # ilişkiden türedi

    rel = (
        session.execute(
            select(Relationship).where(Relationship.investigation_id == inv_id)
        )
        .scalars()
        .one()
    )
    assert rel.kaynak_entity_id == ent[("subdomain", "api.firma.com")].id
    assert rel.hedef_entity_id == ent[("domain", "firma.com")].id
    assert rel.tip == "subdomain_of"


def test_ingest_gelen_yon_kaynak_hedefi_takas_eder(session, inv_id, job):
    g = _obs(
        "api.firma.com",
        iliskiler=(
            ObservedRelation(
                tip=RelationType.CERT_FOR,
                hedef_tip=EntityType.CERT,
                hedef_deger="ab" * 32,
                yon="gelen",
            ),
        ),
    )
    ingest(session, job, [g], spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    ent = _entityler(session, inv_id)
    rel = (
        session.execute(
            select(Relationship).where(Relationship.investigation_id == inv_id)
        )
        .scalars()
        .one()
    )
    assert rel.kaynak_entity_id == ent[("cert", "ab" * 32)].id
    assert rel.hedef_entity_id == ent[("subdomain", "api.firma.com")].id


def test_ingest_tipi_psl_ile_duzeltir(session, inv_id, job):
    """crt.sh her şeyi SUBDOMAIN etiketler; kök hedef DOMAIN olmalı."""
    gozlemler = [
        _obs("firma.com", tip=EntityType.SUBDOMAIN),  # aslında DOMAIN
        _obs("firma.com.tr", tip=EntityType.SUBDOMAIN),  # PSL: com.tr son ek
        _obs("mail.firma.com.tr", tip=EntityType.SUBDOMAIN),
        _obs("api.firma.com", tip=EntityType.DOMAIN),  # aslında SUBDOMAIN
    ]
    ingest(session, job, gozlemler, spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    ent = _entityler(session, inv_id)
    assert ("domain", "firma.com") in ent
    assert ("domain", "firma.com.tr") in ent
    assert ("subdomain", "mail.firma.com.tr") in ent
    assert ("subdomain", "api.firma.com") in ent
    assert ("subdomain", "firma.com") not in ent


def test_ingest_ayni_varlik_tekillesir(session, inv_id, job):
    gozlemler = [_obs("API.Firma.com"), _obs("api.firma.com."), _obs("api.firma.com")]
    s = ingest(session, job, gozlemler, spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    assert s.observation_sayisi == 3
    ent = _entityler(session, inv_id)
    assert len(ent) == 1  # 1 entity
    assert list(ent.values())[0].gozlem_sayisi == 3  # 3 observation


# --- geçersiz kayıt: atlanır AMA sessizce yutulmaz ------------------------- #


def test_gecersiz_kayit_warning_logluyor(session, inv_id, job, caplog):
    """İlke: veri sessizce kaybolmaz. Atlanan kayıt iz bırakır."""
    gozlemler = [
        _obs("gecerli.firma.com"),
        _obs("localhost"),  # PSL'de yok
        _obs("fir ma.com"),  # boşluk
        _obs(""),  # boş
    ]
    with caplog.at_level(logging.WARNING, logger="app.ingest"):
        s = ingest(session, job, gozlemler, spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    assert s.observation_sayisi == 1
    assert s.atlanan == 3
    uyarilar = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(uyarilar) >= 3
    metin = " ".join(r.getMessage() for r in uyarilar)
    assert "localhost" in metin
    assert len(s.atlanan_ayrinti) == 3


def test_gecersiz_iliski_hedefi_de_loglanir(session, inv_id, job, caplog):
    g = _obs(
        "api.firma.com",
        iliskiler=(
            ObservedRelation(
                tip=RelationType.RESOLVES_TO,
                hedef_tip=EntityType.IP,
                hedef_deger="999.999.999.999",
            ),
        ),
    )
    with caplog.at_level(logging.WARNING, logger="app.ingest"):
        s = ingest(session, job, [g], spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    assert s.observation_sayisi == 1  # gözlem yazıldı
    assert s.relationship_sayisi == 0  # ilişki atlandı
    assert "ilişki" in " ".join(r.getMessage() for r in caplog.records)


# --- zincirleme ------------------------------------------------------------ #


def test_zincirleme_is_kuyruga_girer(session, inv_id, job, registry):
    """DOMAIN oluşunca DOMAIN tüketen tool (subfinder) kuyruğa girer."""
    g = _obs("firma.com", tip=EntityType.DOMAIN)
    s = ingest(session, job, [g], spec=SAHTE_SPEC, ham_cikti_ref="r", registry=registry)
    session.commit()

    assert s.kuyruga_alinan == _domain_tuketen_sayisi(registry)
    yeni = (
        session.execute(
            select(Job).where(Job.investigation_id == inv_id, Job.tool == "subfinder")
        )
        .scalars()
        .one()
    )
    assert yeni.durum == "queued"
    assert yeni.hedef_deger == "firma.com"
    assert yeni.derinlik == job.derinlik + 1
    assert yeni.parent_job_id == job.id


def test_subdomain_zincirleme_ikinci_katman(session, inv_id, job, registry):
    """İKİ KATMANLI ZİNCİR: SUBDOMAIN oluşunca onu tüketen tool'lar kuyruğa girer.

    dns-resolver eklenene kadar SUBDOMAIN tüketen tool yoktu ve bu sayı 0'dı.
    Sayı yine SABİT YAZILMIYOR, registry'den türetiliyor.
    """
    s = ingest(
        session,
        job,
        [_obs("api.firma.com")],
        spec=SAHTE_SPEC,
        ham_cikti_ref="r",
        registry=registry,
    )
    session.commit()
    beklenen = len(registry.tuketenler(EntityType.SUBDOMAIN))
    assert s.kuyruga_alinan == beklenen
    assert beklenen >= 1, "SUBDOMAIN tüketen tool yok — zincir tek katmanlı"


def test_uq_job_tekrar_ikinci_kez_engelliyor(session, inv_id, job, registry):
    """SONSUZ DÖNGÜ KORUMASI: aynı tool + aynı hedef ikinci kez kuyruğa girmez."""
    g = _obs("firma.com", tip=EntityType.DOMAIN)

    bir = ingest(
        session, job, [g], spec=SAHTE_SPEC, ham_cikti_ref="r", registry=registry
    )
    session.commit()
    iki = ingest(
        session, job, [g], spec=SAHTE_SPEC, ham_cikti_ref="r", registry=registry
    )
    session.commit()

    assert bir.kuyruga_alinan == _domain_tuketen_sayisi(registry)
    assert iki.kuyruga_alinan == 0  # ikinci turda HİÇBİRİ yeniden girmez
    sayi = session.scalar(
        select(func.count())
        .select_from(Job)
        .where(Job.investigation_id == inv_id, Job.tool == "subfinder")
    )
    assert sayi == 1


def test_ayni_turda_tekrarlanan_varlik_tek_is_uretir(session, inv_id, job, registry):
    gozlemler = [_obs("firma.com", tip=EntityType.DOMAIN)] * 5
    s = ingest(
        session, job, gozlemler, spec=SAHTE_SPEC, ham_cikti_ref="r", registry=registry
    )
    session.commit()
    # 5 kez tekrarlanan varlık, tool başına TEK iş üretir
    assert s.kuyruga_alinan == _domain_tuketen_sayisi(registry)


def test_max_derinlik_zincirlemeyi_durdurur(session, inv_id, registry):
    """`derinlik` ikinci güvenliktir: tarama patlamasını durdurur."""
    derin = Job(
        investigation_id=inv_id,
        tool="sahte",
        tool_version="1.0",
        hedef_deger="derin.firma.com",
        durum="running",
        derinlik=MAX_DERINLIK,
    )
    session.add(derin)
    session.commit()

    s = ingest(
        session,
        derin,
        [_obs("firma.com", tip=EntityType.DOMAIN)],
        spec=SAHTE_SPEC,
        ham_cikti_ref="r",
        registry=registry,
    )
    session.commit()

    assert s.entity_sayisi == 1  # varlık yine yazıldı
    assert s.kuyruga_alinan == 0  # ama zincirleme durdu


def test_registry_yoksa_zincirleme_yok(session, inv_id, job):
    s = ingest(
        session,
        job,
        [_obs("firma.com", tip=EntityType.DOMAIN)],
        spec=SAHTE_SPEC,
        ham_cikti_ref="r",
    )
    session.commit()
    assert s.kuyruga_alinan == 0


# --- gerçek subfinder fixture'ı uçtan uca ---------------------------------- #


def test_subfinder_fixture_ucdan_uca(session, inv_id, job, registry):
    """parse() -> ingest(): gerçek çıktı veritabanına düşüyor mu."""
    from app.tools._base import RawResult
    from app.tools.subfinder.adapter import SubfinderAdapter

    adapter = SubfinderAdapter()
    fixture = TOOL_KOK / "subfinder" / "fixtures" / "sample_output.jsonl"
    gozlemler = adapter.parse(RawResult(icerik=fixture.read_bytes(), format="json"))

    s = ingest(
        session,
        job,
        gozlemler,
        spec=adapter.spec,
        ham_cikti_ref=f"/data/raw/{job.id}/output.json",
        registry=registry,
    )
    session.commit()

    assert s.atlanan == 0
    assert s.observation_sayisi == len(gozlemler)
    ent = _entityler(session, inv_id)
    # Kök domain ilişkiden türedi ve DOMAIN olarak yazıldı
    assert ("domain", "example.com") in ent
    assert s.relationship_sayisi == len(gozlemler)
    # entity_sayisi upsert SAYISIDIR: 24 gözlem + 24 ilişki hedefi (hepsi
    # aynı example.com varlığı). Tekil varlık sayısı 24 subdomain + 1 domain.
    assert s.entity_sayisi == 2 * len(gozlemler)
    assert len(ent) == len(gozlemler) + 1

    # Gözlemlerin tamamı SUBDOMAIN. Fixture'daki 24 satır normalize sonrası
    # yalnızca birkaç TEKİL ada düşer; her tekil ad için SUBDOMAIN tüketen her
    # tool bir kez kuyruğa girer.
    #
    # example.com DOMAIN olarak yazıldı ama İLİŞKİ HEDEFİ olarak türedi;
    # ilişki hedefleri zincirlenmez (kök hedef sonsuz yeniden kuyruğa girerdi).
    # Bkz. app/ingest.py adım 5.
    tekil_sub = len({e for (tip, _), e in ent.items() if tip == "subdomain"})
    assert s.kuyruga_alinan == tekil_sub * len(
        registry.tuketenler(EntityType.SUBDOMAIN)
    )


def test_gozlem_sayisi_observation_satirlariyla_hizali(session, inv_id, job):
    """Sayaç yalan söylememeli: 'Gözlem: N' diyen satırın N kanıtı olmalı.

    İlişki hedefleri ve arayüzden girilen kök hedef observation satırı
    yazmadan oluşur; sayacı artırmamalıdırlar (İlke 2).
    """
    gozlemler = [
        _obs(
            f"s{i}.firma.com",
            iliskiler=(
                ObservedRelation(
                    tip=RelationType.SUBDOMAIN_OF,
                    hedef_tip=EntityType.DOMAIN,
                    hedef_deger="firma.com",
                ),
            ),
        )
        for i in range(5)
    ]
    ingest(session, job, gozlemler, spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    for (tip, norm), e in _entityler(session, inv_id).items():
        gercek = session.scalar(
            select(func.count())
            .select_from(ObservationRow)
            .where(ObservationRow.entity_id == e.id)
        )
        assert e.gozlem_sayisi == gercek, f"{tip}/{norm}: sayaç {e.gozlem_sayisi}, kanıt {gercek}"

    # Kök domain 5 kez ilişki hedefi oldu ama hiç gözlemlenmedi
    kok = _entityler(session, inv_id)[("domain", "firma.com")]
    assert kok.gozlem_sayisi == 0


def test_gozlem_false_mevcut_sayaci_bozmaz(session, inv_id, job):
    """Önce gözlemlenmiş bir varlık, sonra ilişki hedefi olursa sayaç düşmez."""
    from app.ingest import upsert_entity as _ue

    ingest(session, job, [_obs("api.firma.com")], spec=SAHTE_SPEC, ham_cikti_ref="r")
    session.commit()

    e = _ue(session, inv_id, EntityType.SUBDOMAIN, "api.firma.com", "api.firma.com",
            gozlem=False)
    session.commit()
    assert e.gozlem_sayisi == 1
