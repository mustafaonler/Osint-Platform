"""Ingest yapı taşları — `docs/veri-modeli.md` Bölüm 4.5.

Bu modül, parser çıktısını veritabanına yazan tek yerdir; tüm tool'lar bu hattı
paylaşır. Şimdilik yalnızca iki upsert ilkeli hazırdır — tam `ingest()` hattı
henüz yazılmadı.

Ortak ilke: **dedup uygulama katmanında değil, veritabanı kısıtında çözülür.**
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import Entity, Relationship
from app.normalize import EntityType

__all__ = ["upsert_entity", "upsert_relationship"]


def _id(x: Entity | Relationship | uuid.UUID) -> uuid.UUID:
    """Entity nesnesi de UUID de kabul edilir — çağıranın elinde hangisi varsa."""
    return x if isinstance(x, uuid.UUID) else x.id


def upsert_entity(
    session: Session,
    investigation_id: uuid.UUID,
    tip: EntityType | str,
    deger_norm: str,
    deger_ham: str,
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
    """
    stmt = (
        pg_insert(Entity)
        .values(
            investigation_id=investigation_id,
            tip=str(tip),
            deger_norm=deger_norm,
            deger_ham=deger_ham,
            gozlem_sayisi=1,
        )
        .on_conflict_do_update(
            constraint="uq_entity",
            set_={
                "son_gorulme": func.now(),
                # Sağ taraftaki kolon referansı MEVCUT satırın değeridir
                # (SQL karşılığı: `entity.gozlem_sayisi + 1`).
                "gozlem_sayisi": Entity.__table__.c.gozlem_sayisi + 1,
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
