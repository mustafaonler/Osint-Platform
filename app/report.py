"""Araştırmanın tamamını kapsayan Markdown anlık görüntüsü. AI çağrısı yok."""
import html
import re
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.models import Assessment, Entity, Hypothesis, Investigation, Job, Observation, Relationship
from app.triage import GRUPLAR
from app.triage_query import listele


def metin(deger) -> str:
    """Tool metni HTML, bağlantı, resim veya Markdown tablosu üretemez."""
    temiz = " ".join(str(deger if deger is not None else "—").split())
    temiz = "".join(c for c in temiz if ord(c) >= 32)
    return re.sub(r"([\\`*_{}\[\]()#+.!|~\-])", r"\\\1", html.escape(temiz, quote=False))


def markdown_rapor(session: Session, inv: Investigation) -> str:
    satirlar = listele(session, inv.id, inv.kok_hedef)
    entity_ids = {r.entity.id for r in satirlar}
    isler = session.scalars(select(Job).where(Job.investigation_id == inv.id)
                           .order_by(Job.olusturma, Job.id)).all()
    gozlemler = session.scalars(select(Observation).join(Entity, Entity.id == Observation.entity_id)
                               .join(Job, Job.id == Observation.job_id)
                               .where(Entity.investigation_id == inv.id, Job.investigation_id == inv.id)
                               .order_by(Observation.entity_id, Observation.zaman, Observation.id)).all()
    kaynak, hedef = aliased(Entity), aliased(Entity)
    iliskiler = session.scalars(select(Relationship)
        .join(kaynak, kaynak.id == Relationship.kaynak_entity_id)
        .join(hedef, hedef.id == Relationship.hedef_entity_id)
        .where(Relationship.investigation_id == inv.id,
               kaynak.investigation_id == inv.id, hedef.investigation_id == inv.id)
        .order_by(Relationship.tip, Relationship.id)).all()
    skorlar = session.scalars(select(Assessment).join(Entity, Entity.id == Assessment.entity_id)
        .where(Entity.investigation_id == inv.id).distinct(Assessment.entity_id)
        .order_by(Assessment.entity_id, Assessment.zaman.desc(), Assessment.id.desc())).all()
    hipotezler = session.scalars(select(Hypothesis).where(Hypothesis.investigation_id == inv.id)
                                .order_by(Hypothesis.zaman, Hypothesis.id)).all()
    satir = [f"# OSINT araştırma raporu: {metin(inv.ad)}", "",
             "AI skorları önceliklendirme amaçlıdır. Doğrulama sorumluluğu analiste aittir.", "",
             f"- Araştırma kimliği: {inv.id}", f"- Kök hedef: {metin(inv.kok_hedef)}",
             f"- Kapsam: {metin(inv.kapsam_notu)}", f"- Oluşturan: {metin(inv.olusturan)}",
             f"- Yetki onayı: {'Var' if inv.yetki_onayi else 'Yok'}",
             f"- Rapor zamanı (UTC): {datetime.now(timezone.utc).isoformat()}", "",
             "Bu rapor üretim anındaki kayıtları içerir; çalışan/kuyruktaki işler henüz tamamlanmamış olabilir.",
             "Ön eleme grupları risk skoru değildir. Farklı tool sayısı bağımsız doğrulama garantisi değildir.", "",
             f"Varlık: {len(satirlar)} · Gözlem: {len(gozlemler)} · İlişki: {len(iliskiler)} · İş: {len(isler)}", ""]

    def tablo(basliklar, rows):
        satir.append("| " + " | ".join(basliklar) + " |")
        satir.append("| " + " | ".join("---" for _ in basliklar) + " |")
        for row in rows:
            satir.append("| " + " | ".join(metin(v) for v in row) + " |")
        satir.append("")

    sayim = Counter(s.on_eleme.grup for s in satirlar)
    satir.extend(["## Varlıklar — tüm kayıtlar", ""])
    for grup, ad in GRUPLAR.items():
        satir.extend([f"### {ad} ({sayim[grup]})", ""])
        tablo(["Kimlik", "Tip", "Değer", "Gözlem", "Farklı tool", "Kaynaklar", "Gerekçeler"],
              ((r.entity.id, r.entity.tip, r.entity.deger_ham, r.entity.gozlem_sayisi,
                len(r.tools), ", ".join(r.tools), "; ".join(r.on_eleme.gerekceler))
               for r in satirlar if r.on_eleme.grup == grup))
    satir.extend(["## İlişkiler — kaynak → hedef", ""])
    tablo(["Kaynak kimliği", "Tür", "Hedef kimliği"],
          ((r.kaynak_entity_id, r.tip, r.hedef_entity_id) for r in iliskiler))
    satir.extend(["## İşler", ""])
    tablo(["Kimlik", "Tool", "Hedef", "Durum", "Deneme", "Hata"],
          ((j.id, j.tool, j.hedef_deger, j.durum, j.deneme_sayisi, j.hata_mesaji) for j in isler))
    satir.extend(["## Kanıt zinciri", "", "Arşiv referansları yerel kurulumdaki dosyalardır; ham dosyalar rapora gömülmez.", ""])
    tablo(["Gözlem kimliği", "Varlık kimliği", "Tool / sürüm", "Güven", "Zaman", "Arşiv", "Kaynak yolu"],
          ((o.id, o.entity_id, f"{o.tool} / {o.tool_version}", o.guven, o.zaman,
            o.ham_cikti_ref, o.ham_cikti_yol) for o in gozlemler))
    satir.extend(["## Güncel AI değerlendirmeleri", ""])
    if not skorlar:
        satir.extend(["Henüz AI değerlendirmesi yok.", ""])
    else:
        tablo(["Varlık kimliği", "Skor", "Gerekçe", "Model", "Prompt sürümü", "Zaman"],
              ((a.entity_id, a.skor, a.gerekce, a.model, a.prompt_versiyon, a.zaman) for a in skorlar))
    for onayli, baslik in ((True, "Analist tarafından doğrulanmış hipotezler"),
                           (False, "AI hipotezleri — doğrulanmamış / reddedilmiş")):
        satir.extend([f"## {baslik}", ""])
        tablo(["Başlık", "Açıklama", "Güven", "Analist durumu", "Varlık kimlikleri", "Model"],
              ((h.baslik, h.aciklama, h.guven, h.analist_durumu,
                ", ".join(str(eid) if eid in entity_ids else "Araştırma dışı veya eksik referans"
                          for eid in h.entity_ids), h.model)
               for h in hipotezler if (h.analist_durumu == "dogrulandi") == onayli))
    return "\n".join(satir)
