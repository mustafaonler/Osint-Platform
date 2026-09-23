"""Skorlama akışı: ön eleme çıktısı -> model -> doğrulama -> assessment.

SINIRLAR (docs/kapsam.md 3.5, İlke 1)
------------------------------------------------------------------
Bu modül YALNIZCA `assessment` ve `hypothesis` satırı EKLER. Hiçbir entity,
observation veya relationship satırına dokunmaz; hiçbir şey silmez, hiçbir
skoru güncellemez. Skor bir görünüm sinyalidir, veri değildir.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai import prompt as P
from app.ai.provider import AiHatasi, AiProvider
from app.models import Assessment, Entity, Hypothesis, Investigation
from app.triage_query import listele

log = logging.getLogger(__name__)

# Sertifikalar hacmin üçte biri ve en az aksiyon veren tip (docs/on-eleme.md).
# Skorlanmamaları bir veri kaybı değildir: ön eleme onları zaten en sona
# koyuyor ve modele gönderilmeleri kotanın üçte birini götürürdü.
ATLANAN_GRUPLAR = frozenset({"sertifika"})


@dataclass
class SkorlamaSonucu:
    yigin: int = 0
    skor_yazilan: int = 0
    hipotez_yazilan: int = 0
    atlanan_onbellek: int = 0
    halusinasyon: int = 0
    eksik: int = 0
    hatalar: list[str] = field(default_factory=list)

    @property
    def basarili(self) -> bool:
        return self.yigin > 0 and len(self.hatalar) < self.yigin


def _varliklar(session: Session, inv: Investigation) -> list[P.AiVarlik]:
    """Ön elemenin sırasını aynen kullanır — modele önce önemli olan gider."""
    cikti = []
    for s in listele(session, inv.id, inv.kok_hedef):
        if s.on_eleme.grup in ATLANAN_GRUPLAR:
            continue
        cikti.append(
            P.AiVarlik(
                entity_id=s.entity.id,
                tip=s.entity.tip,
                deger=s.entity.deger_norm,
                kaynak_sayisi=len(s.tools),
                tools=s.tools,
                grup=s.on_eleme.grup,
                isaretler=tuple(sorted(s.isaretler)),
                iliskili=s.iliskili,
            )
        )
    return cikti


def son_skorlar(session: Session, inv_id: uuid.UUID) -> dict[uuid.UUID, Assessment]:
    """Her varlık için EN SON assessment. Eskiler silinmez, sadece gösterilmez.

    `DISTINCT ON` ile tek sorguda okunur; varlık başına sorgu açılmaz.
    """
    satirlar = session.execute(
        select(Assessment)
        .join(Entity, Entity.id == Assessment.entity_id)
        .where(Entity.investigation_id == inv_id)
        .distinct(Assessment.entity_id)
        .order_by(Assessment.entity_id, Assessment.zaman.desc())
    ).scalars()
    return {a.entity_id: a for a in satirlar}


def _onbellekte(session: Session, entity_idler: list[uuid.UUID], hash_: str) -> set[uuid.UUID]:
    """Aynı girdi + aynı prompt daha önce skorlandıysa modele gidilmez.

    `assessment.girdi_hash` tam olarak bunun için var (veri-modeli.md 2.6);
    Gemini kotası bu projenin bilinen darboğazıdır.
    """
    if not entity_idler:
        return set()
    return set(
        session.execute(
            select(Assessment.entity_id).where(
                Assessment.entity_id.in_(entity_idler),
                Assessment.girdi_hash == hash_,
                Assessment.prompt_versiyon == P.PROMPT_VERSIYON,
            )
        ).scalars()
    )


def skorla(
    session: Session,
    inv_id: uuid.UUID,
    saglayici: AiProvider,
    *,
    yigin_boyutu: int = P.YIGIN_BOYUTU,
) -> SkorlamaSonucu:
    """Bir araştırmayı skorlar. Commit ETMEZ — çağıran karar verir."""
    sonuc = SkorlamaSonucu()
    inv = session.get(Investigation, inv_id)
    if inv is None:
        sonuc.hatalar.append("araştırma bulunamadı")
        return sonuc

    varliklar = _varliklar(session, inv)
    if not varliklar:
        return sonuc

    for yigin in P.yigina_bol(varliklar, yigin_boyutu):
        hash_ = P.girdi_hash(yigin)
        zaten = _onbellekte(session, [v.entity_id for v in yigin], hash_)
        kalan = [v for v in yigin if v.entity_id not in zaten]
        sonuc.atlanan_onbellek += len(zaten)
        if not kalan:
            continue

        sonuc.yigin += 1
        mesaj, harita = P.kullanici_mesaji(kalan, kok_hedef=inv.kok_hedef)
        try:
            ham = saglayici.uret(P.SISTEM, mesaj, P.SEMA)
        except AiHatasi as e:
            # Bir yığın düşse de diğerleri yazılır: kısmi skor, sıfır skordan iyidir.
            log.warning("yığın skorlanamadı: %s", e)
            sonuc.hatalar.append(str(e))
            continue

        dogrulama = P.dogrula(ham, harita)
        sonuc.halusinasyon += dogrulama.atilan_skor + dogrulama.atilan_hipotez
        sonuc.eksik += len(dogrulama.eksik_etiketler)
        if dogrulama.atilan_skor or dogrulama.atilan_hipotez:
            log.warning(
                "model sözleşme dışı çıktı verdi: %d skor, %d hipotez atıldı",
                dogrulama.atilan_skor, dogrulama.atilan_hipotez,
            )

        # İKİNCİ HALÜSİNASYON FİLTRESİ: etiket haritası doğru olsa bile,
        # entity satırının HÂLÂ bu araştırmada durduğu DB'den doğrulanır.
        gecerli = set(
            session.execute(
                select(Entity.id).where(
                    Entity.investigation_id == inv_id,
                    Entity.id.in_([s.entity_id for s in dogrulama.skorlar]),
                )
            ).scalars()
        )
        for s in dogrulama.skorlar:
            if s.entity_id not in gecerli:
                sonuc.halusinasyon += 1
                continue
            session.add(
                Assessment(
                    entity_id=s.entity_id,
                    skor=s.skor,
                    gerekce=s.gerekce,
                    etiketler=list(s.etiketler),
                    model=saglayici.model,
                    prompt_versiyon=P.PROMPT_VERSIYON,
                    girdi_hash=hash_,
                )
            )
            sonuc.skor_yazilan += 1

        for h in dogrulama.hipotezler:
            dayanak = [e for e in h.entity_idler if e in gecerli]
            if not dayanak:
                sonuc.halusinasyon += 1
                continue
            session.add(
                Hypothesis(
                    investigation_id=inv_id,
                    baslik=h.baslik,
                    aciklama=h.aciklama,
                    guven=h.guven,
                    entity_ids=dayanak,
                    model=saglayici.model,
                    prompt_versiyon=P.PROMPT_VERSIYON,
                )
            )
            sonuc.hipotez_yazilan += 1

    return sonuc
