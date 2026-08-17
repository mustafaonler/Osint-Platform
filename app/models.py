"""SQLAlchemy 2.x şeması — `docs/veri-modeli.md` Bölüm 2. PostgreSQL 16.

Üç katman ayrıdır ve karıştırılmaları en yaygın mimari hatadır:

    entity       "Bu araştırmada hangi şeyler var?"        → tekil
    observation  "Bunu kim, ne zaman, nasıl gördü?"        → çoğul
    assessment   "Bu ne kadar önemli?"                     → türetilmiş

Aynı IP'yi 3 tool bulduysa: 1 entity, 3 observation. AI skorladıysa: +1 assessment.
`entity` satırı ASLA tool'a özgü bilgi taşımaz.

Enum'lar veritabanında native PostgreSQL enum olarak DEĞİL, TEXT + CHECK olarak
tutulur: native enum'a değer eklemek migration gerektirir ve tool ekledikçe bu
sık olacaktır.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    ARRAY,
    CheckConstraint,
    ForeignKey,
    Index,
    DateTime,
    Integer,
    SmallInteger,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "Base",
    "JobStatus",
    "MAX_DERINLIK",
    "Investigation",
    "Entity",
    "Observation",
    "Relationship",
    "Job",
    "Assessment",
    "Hypothesis",
]


# `derinlik` ikinci güvenliktir: kök hedef 0, ondan türeyen işler 1, 2...
# Aşılırsa iş `skipped` olur. Tek başına `uq_job_tekrar` yeterli görünür ama bir
# tool sürekli yeni varlık üretiyorsa (örn. geniş bir netblock) derinlik sınırı
# tarama patlamasını durdurur.
MAX_DERINLIK = 3


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"  # kota/limit/yetki nedeniyle atlandı
    CANCELLED = "cancelled"


_JOB_DURUMLARI = "'queued','running','success','failed','timeout','skipped','cancelled'"

_UUID = UUID(as_uuid=True)
_TS = DateTime(timezone=True)   # TIMESTAMPTZ — naive datetime KABUL EDİLMEZ
_NOW = text("now()")
_GEN_UUID = text("gen_random_uuid()")


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# 2.1 investigation
# --------------------------------------------------------------------------- #


class Investigation(Base):
    __tablename__ = "investigation"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    ad: Mapped[str] = mapped_column(Text, nullable=False)
    # normalize edilmiş kök domain
    kok_hedef: Mapped[str] = mapped_column(Text, nullable=False)
    kapsam_notu: Mapped[str | None] = mapped_column(Text)

    # FALSE ise runner P2 ve A seviyesindeki HİÇBİR modülü çalıştırmaz.
    # Bu kontrol RUNNER'da yapılır, arayüzde değil — arayüz kontrolü atlanabilir.
    yetki_onayi: Mapped[bool] = mapped_column(
        nullable=False, server_default=text("false")
    )
    # kim, ne zaman, hangi belgeye dayanarak
    yetki_notu: Mapped[str | None] = mapped_column(Text)

    olusturan: Mapped[str] = mapped_column(Text, nullable=False)
    durum: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'active'")
    )
    olusturma: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)
    guncelleme: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)

    __table_args__ = (
        CheckConstraint(
            "durum IN ('active','archived')", name="ck_investigation_durum"
        ),
        Index("ix_investigation_durum", "durum", text("olusturma DESC")),
    )


# --------------------------------------------------------------------------- #
# 2.2 entity
# --------------------------------------------------------------------------- #


class Entity(Base):
    """Tekil varlık. `uq_entity` bu şemanın KALBİDİR."""

    __tablename__ = "entity"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("investigation.id", ondelete="CASCADE"), nullable=False
    )
    tip: Mapped[str] = mapped_column(Text, nullable=False)
    deger_norm: Mapped[str] = mapped_column(Text, nullable=False)  # eşleştirme anahtarı
    deger_ham: Mapped[str] = mapped_column(Text, nullable=False)  # ilk görülen hâli

    # Tipe özgü, aramada kullanılmayan alanlar. Bir alan sık filtreleniyorsa
    # JSONB'den çıkarılıp kolon yapılır. Başlangıçta JSONB, ihtiyaç netleşince kolon.
    nitelikler: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    ilk_gorulme: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)
    son_gorulme: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)
    # denormalize, sıralama için
    gozlem_sayisi: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default=text("0")
    )

    __table_args__ = (
        # Dedup uygulama katmanında `if exists` sorgusuyla DEĞİL, veritabanı
        # kısıtıyla çözülür — paralel worker'lar aynı anda aynı varlığı yazmaya
        # çalıştığında yalnızca kısıt doğru davranır.
        UniqueConstraint("investigation_id", "tip", "deger_norm", name="uq_entity"),
        Index("ix_entity_inv_tip", "investigation_id", "tip"),
        Index("ix_entity_son_gorulme", "investigation_id", text("son_gorulme DESC")),
        Index("ix_entity_nitelikler", "nitelikler", postgresql_using="gin"),
        # Arayüzdeki serbest arama için (pg_trgm eklentisi gerekir)
        Index(
            "ix_entity_arama",
            "deger_norm",
            postgresql_using="gin",
            postgresql_ops={"deger_norm": "gin_trgm_ops"},
        ),
    )


# --------------------------------------------------------------------------- #
# 2.3 observation
# --------------------------------------------------------------------------- #


class Observation(Base):
    """Kanıt kaydı.

    NOT: Bu, `app/tools/_base.py` içindeki `Observation` dataclass'ı DEĞİLDİR.
    O, parser'ın DB'den habersiz çıktısıdır (entity_id taşımaz); bu ise ingest
    katmanının yazdığı satırdır. Ingest hattında ORM sınıfı `Observation_`
    takma adıyla kullanılır.
    """

    __tablename__ = "observation"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("entity.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("job.id", ondelete="CASCADE"), nullable=False
    )
    tool: Mapped[str] = mapped_column(Text, nullable=False)
    tool_version: Mapped[str] = mapped_column(Text, nullable=False)

    # Bu ikili, İlke 2'nin (her bulgu izlenebilir) teknik karşılığıdır:
    # arayüzde bir varlığa tıklandığında "subfinder çıktısının 47. satırı" gösterilir.
    ham_cikti_ref: Mapped[str] = mapped_column(Text, nullable=False)  # /data/raw/{job}/…
    ham_cikti_yol: Mapped[str | None] = mapped_column(Text)  # JSONPath

    # Kaynağa göre sabit atanır: CT log / RDAP gibi otoriter kaynaklar 90,
    # API tabanlı indeksler 70, scraping/tahmin tabanlı çıktılar 40.
    guven: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("50")
    )
    veri: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    zaman: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)

    __table_args__ = (
        CheckConstraint("guven BETWEEN 0 AND 100", name="ck_obs_guven"),
        Index("ix_obs_entity", "entity_id", text("zaman DESC")),
        Index("ix_obs_job", "job_id"),
        Index("ix_obs_tool", "tool", text("zaman DESC")),
    )


# --------------------------------------------------------------------------- #
# 2.4 relationship
# --------------------------------------------------------------------------- #


class Relationship(Base):
    """İlişkiler YÖNLÜDÜR. `resolves_to` her zaman domain→IP yönünde yazılır;
    ters yön sorgusu `ix_rel_hedef` indeksiyle karşılanır. Çift yönlü kayıt yok.
    """

    __tablename__ = "relationship"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("investigation.id", ondelete="CASCADE"), nullable=False
    )
    kaynak_entity_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("entity.id", ondelete="CASCADE"), nullable=False
    )
    hedef_entity_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("entity.id", ondelete="CASCADE"), nullable=False
    )
    tip: Mapped[str] = mapped_column(Text, nullable=False)
    ilk_gorulme: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)
    son_gorulme: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)
    nitelikler: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        UniqueConstraint(
            "kaynak_entity_id", "hedef_entity_id", "tip", name="uq_rel"
        ),
        CheckConstraint(
            "kaynak_entity_id <> hedef_entity_id", name="ck_rel_self"
        ),
        Index("ix_rel_kaynak", "kaynak_entity_id", "tip"),
        Index("ix_rel_hedef", "hedef_entity_id", "tip"),
        Index("ix_rel_inv", "investigation_id"),
    )


# --------------------------------------------------------------------------- #
# 2.5 job
# --------------------------------------------------------------------------- #


class Job(Base):
    __tablename__ = "job"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("investigation.id", ondelete="CASCADE"), nullable=False
    )
    tool: Mapped[str] = mapped_column(Text, nullable=False)
    tool_version: Mapped[str] = mapped_column(Text, nullable=False)
    hedef_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID, ForeignKey("entity.id", ondelete="SET NULL")
    )
    # entity silinse de kalır
    hedef_deger: Mapped[str] = mapped_column(Text, nullable=False)
    durum: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'queued'")
    )
    parent_job_id: Mapped[uuid.UUID | None] = mapped_column(
        _UUID, ForeignKey("job.id", ondelete="SET NULL")
    )
    derinlik: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    hata_mesaji: Mapped[str | None] = mapped_column(Text)
    cikis_kodu: Mapped[int | None] = mapped_column(Integer)
    baslangic: Mapped[datetime | None] = mapped_column(_TS)
    bitis: Mapped[datetime | None] = mapped_column(_TS)
    sure_ms: Mapped[int | None] = mapped_column(Integer)
    olusturma: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)

    __table_args__ = (
        CheckConstraint(f"durum IN ({_JOB_DURUMLARI})", name="ck_job_durum"),
        # SONSUZ DÖNGÜ KORUMASI. Otomatik zincirleme kurulduğunda A→B→A gibi
        # çevrimler kaçınılmazdır; bu kısıt aynı tool'un aynı hedefte ikinci kez
        # kuyruğa girmesini VERİTABANI SEVİYESİNDE imkânsız kılar.
        UniqueConstraint(
            "investigation_id", "tool", "hedef_deger", name="uq_job_tekrar"
        ),
        Index("ix_job_inv_durum", "investigation_id", "durum"),
        Index(
            "ix_job_kuyruk",
            "durum",
            "olusturma",
            postgresql_where=text("durum = 'queued'"),
        ),
    )


# --------------------------------------------------------------------------- #
# 2.6 assessment
# --------------------------------------------------------------------------- #


class Assessment(Base):
    """AI skorlaması.

    Assessment kayıtları ASLA GÜNCELLENMEZ, yalnızca eklenir. Prompt değiştiğinde
    eski skorlar durur; "eski model neden böyle demişti" sorusu cevaplanabilir kalır.
    """

    __tablename__ = "assessment"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    entity_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("entity.id", ondelete="CASCADE"), nullable=False
    )
    skor: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    gerekce: Mapped[str] = mapped_column(Text, nullable=False)
    etiketler: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default=text("'{}'")
    )
    model: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_versiyon: Mapped[str] = mapped_column(Text, nullable=False)
    # aynı girdi + aynı prompt = modele tekrar gitmez (Gemini kotasını korur)
    girdi_hash: Mapped[str] = mapped_column(Text, nullable=False)
    zaman: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)

    __table_args__ = (
        CheckConstraint("skor BETWEEN 0 AND 100", name="ck_assess_skor"),
        Index("ix_assess_entity", "entity_id", text("zaman DESC")),
        Index("ix_assess_skor", text("skor DESC"), text("zaman DESC")),
    )


# --------------------------------------------------------------------------- #
# 2.7 hypothesis
# --------------------------------------------------------------------------- #


class Hypothesis(Base):
    """AI korelasyon çıktısı.

    `analist_durumu` AI çıktısını insan onayına bağlar. Rapora yalnızca
    `dogrulandi` olanlar otomatik girer; diğerleri "AI hipotezi" başlığı altında
    ayrı listelenir.
    """

    __tablename__ = "hypothesis"

    id: Mapped[uuid.UUID] = mapped_column(
        _UUID, primary_key=True, server_default=_GEN_UUID
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        _UUID, ForeignKey("investigation.id", ondelete="CASCADE"), nullable=False
    )
    baslik: Mapped[str] = mapped_column(Text, nullable=False)
    aciklama: Mapped[str] = mapped_column(Text, nullable=False)
    guven: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # dayandığı varlıklar
    entity_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(_UUID), nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    prompt_versiyon: Mapped[str] = mapped_column(Text, nullable=False)
    analist_durumu: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("'beklemede'")
    )
    zaman: Mapped[datetime] = mapped_column(_TS, nullable=False, server_default=_NOW)

    __table_args__ = (
        CheckConstraint("guven BETWEEN 0 AND 100", name="ck_hyp_guven"),
        CheckConstraint(
            "analist_durumu IN ('beklemede','dogrulandi','reddedildi')",
            name="ck_hyp_analist_durumu",
        ),
        Index("ix_hyp_inv", "investigation_id", text("guven DESC")),
    )
