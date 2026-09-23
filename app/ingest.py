"""Ingest hattı — `docs/veri-modeli.md` Bölüm 4.5.

Parser çıktısını veritabanına yazan TEK yer; tüm tool'lar bu hattı paylaşır.

Ortak ilke: **dedup uygulama katmanında değil, veritabanı kısıtında çözülür.**
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import MAX_DERINLIK, Entity, Job, Relationship
from app.models import Observation as ObservationRow
from app.normalize import EntityType, NormalizeError, domain_mi, gecerli_mi, normalize
from app.tools._base import Observation, ObservedRelation, ToolRegistry, ToolSpec

__all__ = [
    "upsert_entity",
    "upsert_relationship",
    "kuyruga_al",
    "ingest",
    "IngestSonucu",
]

log = logging.getLogger(__name__)


def _id(x: Entity | Relationship | uuid.UUID) -> uuid.UUID:
    """Entity nesnesi de UUID de kabul edilir — çağıranın elinde hangisi varsa."""
    return x if isinstance(x, uuid.UUID) else x.id


# --------------------------------------------------------------------------- #
# Upsert yapı taşları
# --------------------------------------------------------------------------- #


def upsert_entity(
    session: Session,
    investigation_id: uuid.UUID,
    tip: EntityType | str,
    deger_norm: str,
    deger_ham: str,
    *,
    gozlem: bool = True,
) -> Entity:
    """Varlığı ekler veya görülme sayacını artırır. TEK SORGUDA.

    NEDEN `ON CONFLICT`, NEDEN `SELECT` + `INSERT` DEĞİL
    ------------------------------------------------------------------
    `if exists` deseni (önce SELECT, yoksa INSERT) tek worker'da doğru görünür
    ama paralel worker'larda BOZUKTUR: iki worker aynı anda SELECT çalıştırıp
    ikisi de "yok" cevabını alır, ikisi de INSERT dener ve biri `uq_entity`
    kısıtına çarpar — ya `IntegrityError` ile iş düşer ya da elle retry yazmak
    gerekir. Aradaki pencere ne kadar dar olursa olsun kapanmaz; `crtsh` ile
    `subfinder` aynı subdomain'i milisaniyeler arayla bulduğunda bu gerçekleşir.

    `INSERT ... ON CONFLICT DO UPDATE` bunu atomik hâle getirir: çakışma
    kontrolü ile yazma aynı ifadenin içindedir, PostgreSQL satır kilidini
    kendisi yönetir. Yarış koşulu ortadan kalkar, retry döngüsü gerekmez.
    `uq_entity (investigation_id, tip, deger_norm)` bu yüzden şemanın kalbidir.

    `deger_ham` ÇAKIŞMADA GÜNCELLENMEZ
    ------------------------------------------------------------------
    Bölüm 2.2: `deger_ham` "ilk görülen orijinal hali"dir. Aynı varlığı ikinci
    kez gören tool farklı bir yazımla gelebilir ('WWW.Firma.COM.' vs
    'www.firma.com'); ilk kayıt korunur, sonrakiler `observation.veri` içinde
    yaşar. `deger_norm` zaten ikisini de aynı anahtara indirger.

    `gozlem_sayisi` 1'den başlar: ilk upsert de bir gözlemdir. (Bölüm 4.5'teki
    SQL taslağı `VALUES` listesinde bu alanı atladığı için sayaç bir eksik
    kalıyordu; N upsert sonrası N-1 gösteriyordu.)

    `gozlem=False` SAYACI ARTIRMAZ
    ------------------------------------------------------------------
    Her varlık bir gözlemden doğmaz: ilişki hedefleri ve arayüzden girilen kök
    hedef, karşılığında bir `observation` satırı OLMADAN oluşur. Onları da
    saydırmak sayacı yalana çevirir — arayüzde "Gözlem: 17058" yazan bir
    satırın kanıt zinciri bomboş çıkar. Sayaç `observation` satırlarıyla
    hizalı kalmalıdır; İlke 2 bunu gerektirir.
    """
    artis = 1 if gozlem else 0
    stmt = (
        pg_insert(Entity)
        .values(
            investigation_id=investigation_id,
            tip=str(tip),
            deger_norm=deger_norm,
            deger_ham=deger_ham,
            gozlem_sayisi=artis,
        )
        .on_conflict_do_update(
            constraint="uq_entity",
            set_={
                "son_gorulme": func.now(),
                # Sağ taraftaki kolon referansı MEVCUT satırın değeridir
                # (SQL karşılığı: `entity.gozlem_sayisi + 1`).
                "gozlem_sayisi": Entity.__table__.c.gozlem_sayisi + artis,
            },
        )
        .returning(Entity)
    )
    # populate_existing: satır bu session'ın kimlik haritasında zaten varsa
    # RETURNING'den gelen taze değerlerle ezilir, bayat nesne dönmez.
    return (
        session.execute(stmt, execution_options={"populate_existing": True})
        .scalars()
        .one()
    )


def upsert_relationship(
    session: Session,
    investigation_id: uuid.UUID,
    kaynak: Entity | uuid.UUID,
    hedef: Entity | uuid.UUID,
    tip: str,
    nitelikler: dict[str, Any] | None = None,
) -> Relationship | None:
    """İlişkiyi ekler veya `son_gorulme`'sini tazeler. TEK SORGUDA.

    `upsert_entity` ile aynı gerekçe: `uq_rel (kaynak, hedef, tip)` üzerinden
    `ON CONFLICT DO UPDATE`. Aynı ilişkiyi iki tool paralel bulduğunda —
    örneğin `dns-resolver` ile `shodan-lookup` aynı `resolves_to` bağını —
    `SELECT` + `INSERT` deseni yarışır; bu ifade yarışmaz.

    İlişkiler yönlüdür; çift yönlü kayıt tutulmaz (Bölüm 2.4).

    `kaynak == hedef` ise SESSİZCE ATLANIR ve `None` döner. Kendine döngü
    `ck_rel_self` kısıtına çarpardı; bunu istisnaya çevirmek yerine burada
    elemek doğrudur, çünkü bozuk tek bir gözlem yüzünden tüm ingest turunun
    düşmesi anlamsızdır (Bölüm 4.5: bozuk kayıt sessizce atlanır).

    `nitelikler` çakışmada GÜNCELLENMEZ; ilk gözlemin bağlamı korunur.
    """
    kaynak_id, hedef_id = _id(kaynak), _id(hedef)
    if kaynak_id == hedef_id:
        return None

    stmt = (
        pg_insert(Relationship)
        .values(
            investigation_id=investigation_id,
            kaynak_entity_id=kaynak_id,
            hedef_entity_id=hedef_id,
            tip=str(tip),
            nitelikler=nitelikler or {},
        )
        .on_conflict_do_update(
            constraint="uq_rel",
            set_={"son_gorulme": func.now()},
        )
        .returning(Relationship)
    )
    return (
        session.execute(stmt, execution_options={"populate_existing": True})
        .scalars()
        .one()
    )


def kuyruga_al(
    session: Session,
    investigation_id: uuid.UUID,
    tool_adi: str,
    tool_version: str,
    entity: Entity,
    *,
    parent: Job | None = None,
    derinlik: int = 0,
) -> Job | None:
    """Zincirleme işi kuyruğa alır. Zaten varsa `None` döner.

    DİKKAT: Bu fonksiyon yalnızca `job` SATIRINI yazar; Celery görevini
    GÖNDERMEZ. Gönderim çağıranın işidir ve COMMIT'TEN SONRA yapılmalıdır.
    Aksi hâlde iş satırı sonsuza kadar `queued` durumunda kalır — zincirleme
    sessizce çalışmaz. (Bu tam olarak Hafta 4 ölçümünde yakalanan hataydı.)

    SONSUZ DÖNGÜ KORUMASI `uq_job_tekrar (investigation_id, tool, hedef_deger)`
    kısıtındadır ve `ON CONFLICT DO NOTHING` ile kullanılır. Otomatik
    zincirlemede A→B→A çevrimleri kaçınılmazdır; bu kısıt aynı tool'un aynı
    hedefte ikinci kez kuyruğa girmesini VERİTABANI SEVİYESİNDE imkânsız kılar.
    Uygulama katmanında "daha önce çalıştırdım mı" sorgusu yazmak, `upsert`'teki
    ile aynı yarış koşuluna düşerdi.
    """
    stmt = (
        pg_insert(Job)
        .values(
            investigation_id=investigation_id,
            tool=tool_adi,
            tool_version=tool_version,
            hedef_entity_id=entity.id,
            hedef_deger=entity.deger_norm,
            durum="queued",
            parent_job_id=parent.id if parent is not None else None,
            derinlik=derinlik,
        )
        .on_conflict_do_nothing(constraint="uq_job_tekrar")
        .returning(Job)
    )
    return session.execute(stmt).scalars().one_or_none()


# --------------------------------------------------------------------------- #
# Ingest hattı
# --------------------------------------------------------------------------- #


@dataclass
class IngestSonucu:
    """Turun özeti — çağıran loglar, testler doğrular.

    `entity_sayisi` UPSERT ÇAĞRISI sayısıdır, tekil varlık sayısı değil: aynı
    varlık turda beş kez görülürse beş sayılır. Tekil sayı için veritabanına
    bakılır; buradaki rakam "kaç yazma denemesi oldu"yu ölçer.
    """

    entity_sayisi: int = 0
    observation_sayisi: int = 0
    relationship_sayisi: int = 0
    atlanan: int = 0
    kuyruga_alinan: int = 0
    atlanan_ayrinti: list[str] = field(default_factory=list)
    # Kuyruğa alınan işlerin ID'leri. Çağıran bunları Celery'ye GÖNDERMEK
    # ZORUNDADIR — `kuyruga_al` yalnızca `job` satırını yazar, görevi
    # dağıtmaz. Gönderim COMMIT'TEN SONRA yapılmalıdır (bkz. worker).
    kuyruk_idleri: list[uuid.UUID] = field(default_factory=list)


def _tip_duzelt(tip: EntityType, norm: str) -> EntityType:
    """Host tiplerinde parser'ın verdiği tipi PSL ile düzeltir.

    Parser'lar tip konusunda güvenilmez: `crt.sh` her adı SUBDOMAIN etiketler,
    kök hedefin kendisi dahil. Kararın tek kaynağı `domain_mi()`'dir.

    Diğer tipler dokunulmadan geçer — bir IP'nin tipini tahmin etmeye
    çalışmayız, parser orada zaten kesin bilgiye sahiptir.
    """
    if tip in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
        return EntityType.DOMAIN if domain_mi(norm) else EntityType.SUBDOMAIN
    return tip


def _cozumle(
    tip: EntityType, ham: str, baglam: str, sonuc: IngestSonucu
) -> tuple[EntityType, str] | None:
    """normalize + gecerli_mi + tip düzeltme. Geçersizse WARNING loglar.

    VERİ SESSİZCE KAYBOLMAZ (İlke 1'in aynı mantığı): kayıt atlanır ama
    atlandığı iz bırakır. Sessiz `continue`, yanlış negatifi görünmez kılar —
    ayrıştırıcı bozulduğunda kimse fark etmez.
    """
    try:
        norm = normalize(tip, ham)
    except NormalizeError as e:
        mesaj = f"{baglam}: normalize edilemedi tip={tip} ham={ham!r}: {e}"
        log.warning(mesaj)
        sonuc.atlanan += 1
        sonuc.atlanan_ayrinti.append(mesaj)
        return None

    if not gecerli_mi(tip, norm):
        mesaj = f"{baglam}: kanonik değil tip={tip} norm={norm!r}"
        log.warning(mesaj)
        sonuc.atlanan += 1
        sonuc.atlanan_ayrinti.append(mesaj)
        return None

    return _tip_duzelt(tip, norm), norm


def _iliski_yaz(
    session: Session,
    investigation_id: uuid.UUID,
    kaynak: Entity,
    il: ObservedRelation,
    baglam: str,
    sonuc: IngestSonucu,
) -> None:
    cozum = _cozumle(il.hedef_tip, il.hedef_deger, f"{baglam}/ilişki", sonuc)
    if cozum is None:
        return
    hedef_tip, hedef_norm = cozum

    # İlişki hedefi bir GÖZLEM değildir: karşılığında observation satırı
    # yazılmaz, dolayısıyla gozlem_sayisi de artmaz.
    hedef = upsert_entity(
        session, investigation_id, hedef_tip, hedef_norm, il.hedef_deger,
        gozlem=False,
    )
    sonuc.entity_sayisi += 1

    # Yön: "gelen" ise kaynak/hedef yer değiştirir. İlişkiler yönlüdür ve
    # çift yönlü kayıt tutulmaz; yönü burada bir kez sabitleriz.
    a, b = (kaynak, hedef) if il.yon == "giden" else (hedef, kaynak)
    if upsert_relationship(session, investigation_id, a, b, str(il.tip)) is not None:
        sonuc.relationship_sayisi += 1


def ingest(
    session: Session,
    job: Job,
    gozlemler: list[Observation],
    *,
    spec: ToolSpec,
    ham_cikti_ref: str,
    registry: ToolRegistry | None = None,
    max_derinlik: int = MAX_DERINLIK,
    secili_toollar: list[str] | None = None,
) -> IngestSonucu:
    """Gözlemleri veritabanına yazar ve zincirleme işleri kuyruğa alır.

    Bölüm 4.5'teki hat:
        normalize -> gecerli_mi -> upsert_entity -> observation yaz ->
        ilişkileri çöz -> zincirleme işleri kuyruğa al

    `ham_cikti_ref` PARAMETREDİR, `job` üzerinden okunmaz: `job` tablosunda
    böyle bir kolon yok (Bölüm 2.5). Değer runner'ın `RunSonucu`'ndan gelir ve
    her `observation` satırına yazılır — İlke 2'nin (her bulgu ham çıktısına
    kadar izlenebilir) taşıyıcısı odur.

    `secili_toollar` BOŞ ya da None ise kısıt yoktur. Doluysa zincirleme
    yalnızca o tool'ları kuyruğa alır: analist araştırmayı kurarken "shodan
    kullanma" dediyse üçüncü derinlikte de kullanılmamalıdır. Kısıt burada
    uygulanır çünkü zincirleme işleri doğuran tek yer burasıdır.

    Commit ETMEZ. İşlem sınırını çağıran belirler; bir tool turunun tamamı tek
    işlemde ya yazılır ya yazılmaz.
    """
    izinli = frozenset(secili_toollar or ())
    sonuc = IngestSonucu()
    zincirlenen: set[tuple[str, str]] = set()

    for sira, g in enumerate(gozlemler):
        baglam = f"{spec.name}#{sira}"

        cozum = _cozumle(g.tip, g.deger_ham, baglam, sonuc)
        if cozum is None:
            continue
        tip, norm = cozum

        # 2) Varlığı upsert et (yarış koşulunu DB kısıtı çözer)
        entity = upsert_entity(
            session, job.investigation_id, tip, norm, g.deger_ham
        )
        sonuc.entity_sayisi += 1

        # 3) Gözlemi yaz — kanıt kaydı
        session.add(
            ObservationRow(
                entity_id=entity.id,
                job_id=job.id,
                tool=job.tool,
                tool_version=job.tool_version,
                ham_cikti_ref=ham_cikti_ref,
                ham_cikti_yol=g.kaynak_yol,
                guven=g.guven if g.guven is not None else spec.varsayilan_guven,
                veri=g.nitelikler or {},
            )
        )
        sonuc.observation_sayisi += 1

        # 4) İlişkileri çöz — hedef varlık yoksa oluştur
        for il in g.iliskiler:
            _iliski_yaz(session, job.investigation_id, entity, il, baglam, sonuc)

        # 5) Zincirleme işleri kuyruğa al
        #
        # YALNIZCA GÖZLEM VARLIKLARI ZİNCİRLENİR, ilişki hedefleri DEĞİL
        # (Bölüm 4.5'teki hat da `g.tip` üzerinden zincirler). İlişki hedefi
        # çoğu zaman zaten GELDİĞİMİZ yerdir: `subdomain_of` hedefi kök
        # domain'dir, yani şu an koşan işin kendi hedefi. Onu zincirlemek her
        # turda kök hedefi yeniden kuyruğa sokmaya çalışmak olurdu.
        # Kural şu: bir adapter, taranmasını istediği her şeyi Observation
        # olarak yayar; `iliskiler` yalnızca bağ kurmak içindir.
        if registry is None:
            continue
        if job.derinlik >= max_derinlik:
            # `derinlik` ikinci güvenliktir: `uq_job_tekrar` çevrimleri keser
            # ama sürekli YENİ varlık üreten bir tool (örn. geniş bir netblock)
            # döngüye girmeden de tarama patlaması yaratabilir.
            log.info(
                "%s: MAX_DERINLIK=%d aşıldı, zincirleme durduruldu (%s)",
                baglam,
                max_derinlik,
                norm,
            )
            continue

        anahtar = (str(tip), norm)
        if anahtar in zincirlenen:
            continue  # aynı turda aynı varlık için tekrar sorgu atmayalım
        zincirlenen.add(anahtar)

        for adapter in registry.tuketenler(tip):
            if izinli and adapter.spec.name not in izinli:
                continue
            yeni = kuyruga_al(
                session,
                job.investigation_id,
                adapter.spec.name,
                adapter.spec.version,
                entity,
                parent=job,
                derinlik=job.derinlik + 1,
            )
            if yeni is not None:
                sonuc.kuyruga_alinan += 1
                sonuc.kuyruk_idleri.append(yeni.id)

    if sonuc.atlanan:
        log.warning(
            "%s: %d gözlem atlandı (%d yazıldı)",
            spec.name,
            sonuc.atlanan,
            sonuc.observation_sayisi,
        )
    return sonuc
