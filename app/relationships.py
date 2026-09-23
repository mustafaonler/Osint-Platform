"""Varlık komşuları: aynı araştırmadaki yönlü ilişkilerin salt okunur görünümü."""

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, aliased

from app.models import Entity, Relationship

SAYFA_BOYUTU = 50
ILISKI_ADLARI = {
    "subdomain_of": "Alt alan adı",
    "resolves_to": "IP adresine çözülür",
    "cname_for": "Takma ad",
    "mx_for": "E-posta sunucusu",
    "ns_for": "Ad sunucusu",
    "cert_for": "Sertifikası",
    "in_netblock": "IP bloğunda",
    "announced_by": "ASN tarafından duyurulur",
    "owned_by": "Sahiplik kaydı",
    "runs_on": "Üzerinde çalışır",
    "uses_tech": "Teknoloji kullanır",
    "email_at": "Alan adına ait e-posta",
}


def komsular(session: Session, entity: Entity, sayfa: int = 1) -> dict:
    kaynak, hedef = aliased(Entity), aliased(Entity)
    # İlişkinin ve İKİ ucunun araştırması doğrulanır. Bozuk/eskiden kalmış
    # çapraz araştırma ilişkileri başka araştırmanın varlığını sızdırmaz.
    sorgu = (
        select(Relationship, kaynak, hedef)
        .join(kaynak, kaynak.id == Relationship.kaynak_entity_id)
        .join(hedef, hedef.id == Relationship.hedef_entity_id)
        .where(
            Relationship.investigation_id == entity.investigation_id,
            kaynak.investigation_id == entity.investigation_id,
            hedef.investigation_id == entity.investigation_id,
            or_(kaynak.id == entity.id, hedef.id == entity.id),
        )
    )
    toplam = session.scalar(select(func.count()).select_from(sorgu.subquery())) or 0
    sayfa_sayisi = max(1, (toplam + SAYFA_BOYUTU - 1) // SAYFA_BOYUTU)
    sayfa = min(max(1, sayfa), sayfa_sayisi)
    satirlar = session.execute(
        sorgu.order_by(Relationship.tip, kaynak.deger_norm, hedef.deger_norm, Relationship.id)
        .offset((sayfa - 1) * SAYFA_BOYUTU).limit(SAYFA_BOYUTU)
    ).all()
    return dict(satirlar=satirlar, toplam=toplam, sayfa=sayfa, sayfa_sayisi=sayfa_sayisi)
