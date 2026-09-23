"""Araştırmaya sınırlandırılmış toplu okumalar; N+1 veya DB yazımı yok."""

from collections import Counter
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, literal, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session

from app.models import Entity, Observation, Relationship
from app.triage import ISARETLER, OnEleme, degerlendir

SAYFA_BOYUTU = 100


@dataclass(frozen=True)
class VarlikSatiri:
    entity: Entity
    tools: tuple[str, ...]
    on_eleme: OnEleme
    # Ham sinyaller de taşınır. AI katmanı bunlara ihtiyaç duyar ve Türkçe
    # gerekçe metninden geri ayıklamak kırılgandır: metin değişince sessizce bozulur.
    isaretler: frozenset[str] = frozenset()
    iliskili: bool = True


def listele(session: Session, inv_id: UUID, kok_hedef: str):
    # İşaretler Entity.nitelikler'e kopyalanmıyor: asıl kaynak Observation.veri.
    # Herhangi bir gözlemde true varsa korunur; metin "false" işaret sayılmaz.
    gozlemler = (
        select(
            Observation.entity_id,
            func.array_agg(func.distinct(Observation.tool)).label("tools"),
            *(func.bool_or(Observation.veri[ad] == literal(True, type_=JSONB)).label(ad)
              for ad in ISARETLER),
        )
        .join(Entity, Entity.id == Observation.entity_id)
        .where(Entity.investigation_id == inv_id)
        .group_by(Observation.entity_id).subquery()
    )
    baglar = select(Relationship.kaynak_entity_id.label("id")).where(
        Relationship.investigation_id == inv_id
    ).union(select(Relationship.hedef_entity_id.label("id")).where(
        Relationship.investigation_id == inv_id
    )).subquery()
    sonuc = session.execute(
        select(Entity, gozlemler.c.tools, baglar.c.id.is_not(None).label("iliskili"),
               *(gozlemler.c[ad] for ad in ISARETLER))
        .outerjoin(gozlemler, gozlemler.c.entity_id == Entity.id)
        .outerjoin(baglar, baglar.c.id == Entity.id)
        .where(Entity.investigation_id == inv_id)
    )
    satirlar = []
    for row in sonuc:
        e = row[0]
        tools = tuple(sorted(row.tools or ()))
        isaretler = frozenset(
            ad for ad in ISARETLER
            if row._mapping[ad] is True or (e.nitelikler or {}).get(ad) is True
        )
        on_eleme = degerlendir(
            e.tip, len(tools), row.iliskili, isaretler,
            kok=e.tip == "domain" and e.deger_norm == kok_hedef,
        )
        satirlar.append(VarlikSatiri(e, tools, on_eleme, isaretler, bool(row.iliskili)))
    # Tek tool'un binlerce tekrarı sıralamayı değiştirmez. Tam bağlayıcı sıra
    # aynı veri için DB dönüş sırasından bağımsızdır.
    satirlar.sort(key=lambda s: (
        s.on_eleme.sira, -len(s.tools), s.entity.tip,
        s.entity.deger_norm, str(s.entity.id),
    ))
    return satirlar


def sayfala(satirlar, grup: str, sayfa: int):
    sayim = Counter(s.on_eleme.grup for s in satirlar)
    secilen = [s for s in satirlar if grup == "tumu" or s.on_eleme.grup == grup]
    sayfa_sayisi = max(1, (len(secilen) + SAYFA_BOYUTU - 1) // SAYFA_BOYUTU)
    sayfa = min(max(1, sayfa), sayfa_sayisi)
    bas = (sayfa - 1) * SAYFA_BOYUTU
    return dict(
        satirlar=secilen[bas:bas + SAYFA_BOYUTU], toplam=len(satirlar),
        secilen_sayisi=len(secilen), sayim=sayim, grup=grup, sayfa=sayfa,
        sayfa_sayisi=sayfa_sayisi,
    )
