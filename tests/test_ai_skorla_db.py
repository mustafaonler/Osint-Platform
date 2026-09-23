"""Skorlama akışı gerçek PostgreSQL üzerinde. Sahte sağlayıcı — ağa çıkılmaz.

docker compose exec -T api python -m pytest tests/test_ai_skorla_db.py -q

En kritik iddia: AI HİÇBİR ŞEYİ SİLMEZ VE DEĞİŞTİRMEZ (İlke 1). Yalnızca
`assessment` ve `hypothesis` satırı eklenir.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.ai import prompt as P
from app.ai.provider import AiHatasi, SahteProvider
from app.ai.skorla import skorla
from app.db import SessionLocal
from app.models import (
    Assessment, Entity, Hypothesis, Investigation, Job, Observation, Relationship,
)


@pytest.fixture
def veri():
    with SessionLocal() as s:
        inv = Investigation(ad="ai-test", kok_hedef="example.com", olusturan="pytest")
        diger = Investigation(ad="ai-other", kok_hedef="example.org", olusturan="pytest")
        s.add_all([inv, diger])
        s.flush()

        def entity(tip, deger, arastirma=None):
            e = Entity(investigation_id=(arastirma or inv).id, tip=tip,
                       deger_norm=deger, deger_ham=deger)
            s.add(e)
            s.flush()
            return e

        kok = entity("domain", "example.com")
        vpn = entity("subdomain", "vpn.example.com")
        cert = entity("cert", "abcdef0123456789")
        yabanci = entity("subdomain", "foreign.example.org", diger)
        job = Job(investigation_id=inv.id, tool="test", tool_version="1",
                  hedef_deger="example.com")
        s.add(job)
        s.flush()
        for e, tool in ((vpn, "crtsh"), (vpn, "subfinder"), (cert, "crtsh")):
            s.add(Observation(entity_id=e.id, job_id=job.id, tool=tool,
                              tool_version="1", ham_cikti_ref="t.json", veri={}))
        s.add(Relationship(investigation_id=inv.id, kaynak_entity_id=vpn.id,
                           hedef_entity_id=kok.id, tip="subdomain_of"))
        s.flush()
        try:
            yield s, inv, dict(kok=kok, vpn=vpn, cert=cert, yabanci=yabanci)
        finally:
            s.rollback()


def _sayimlar(s, inv):
    return (
        s.scalar(select(func.count()).select_from(Entity)
                 .where(Entity.investigation_id == inv.id)),
        s.scalar(select(func.count()).select_from(Observation)
                 .join(Entity, Entity.id == Observation.entity_id)
                 .where(Entity.investigation_id == inv.id)),
        s.scalar(select(func.count()).select_from(Relationship)
                 .where(Relationship.investigation_id == inv.id)),
    )


def _yanit_hepsine(saglayici_girdisi: dict, skor: int = 70) -> str:
    return SahteProvider.yanit(
        [{"id": e, "skor": skor, "gerekce": "test"} for e in saglayici_girdisi]
    )


# --------------------------------------------------------------------------- #
# İLKE 1 — AI VERİ SİLMEZ
# --------------------------------------------------------------------------- #


def test_ai_hicbir_veriyi_silmez_veya_degistirmez(veri):
    s, inv, e = veri
    once = _sayimlar(s, inv)
    kok_deger = e["kok"].deger_norm
    vpn_gozlem = e["vpn"].gozlem_sayisi

    p = SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 90, "gerekce": "kök"},
         {"id": "v2", "skor": 85, "gerekce": "vpn"}]
    )])
    sonuc = skorla(s, inv.id, p)
    s.flush()

    assert sonuc.skor_yazilan == 2
    assert _sayimlar(s, inv) == once, "AI veri sildi veya ekledi"
    assert e["kok"].deger_norm == kok_deger
    assert e["vpn"].gozlem_sayisi == vpn_gozlem


def test_sertifikalar_modele_gonderilmez(veri):
    """Hacmin üçte biri; ön eleme onları zaten en sona koyuyor (docs/on-eleme.md)."""
    s, inv, e = veri
    p = SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 50, "gerekce": "x"}, {"id": "v2", "skor": 50, "gerekce": "y"}]
    )])
    skorla(s, inv.id, p)
    assert e["cert"].deger_norm not in p.cagrilar[0][1]


def test_baska_arastirmanin_varligi_gonderilmez(veri):
    s, inv, e = veri
    p = SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 50, "gerekce": "x"}, {"id": "v2", "skor": 50, "gerekce": "y"}]
    )])
    skorla(s, inv.id, p)
    assert "foreign.example.org" not in p.cagrilar[0][1]


# --------------------------------------------------------------------------- #
# HALÜSİNASYON FİLTRESİ — DB katmanı
# --------------------------------------------------------------------------- #


def test_uydurma_etiket_yazilmaz(veri):
    s, inv, _ = veri
    p = SahteProvider([SahteProvider.yanit([
        {"id": "v1", "skor": 90, "gerekce": "gerçek"},
        {"id": "v77", "skor": 95, "gerekce": "uydurma"},
    ])])
    sonuc = skorla(s, inv.id, p)
    s.flush()

    assert sonuc.skor_yazilan == 1
    assert sonuc.halusinasyon == 1
    assert s.scalar(select(func.count()).select_from(Assessment)
                    .join(Entity, Entity.id == Assessment.entity_id)
                    .where(Entity.investigation_id == inv.id)) == 1


def test_arada_silinen_varlik_icin_skor_yazilmaz(veri):
    """Etiket haritası doğru olsa bile entity satırı DB'den doğrulanır."""
    s, inv, e = veri
    p = SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 90, "gerekce": "x"}, {"id": "v2", "skor": 80, "gerekce": "y"}]
    )])
    # Model çağrısından önce varlığı kaldır: yarış durumunun benzetimi.
    hedef = e["vpn"]
    s.delete(hedef)
    s.flush()

    sonuc = skorla(s, inv.id, p)
    s.flush()
    assert sonuc.skor_yazilan <= 1


def test_bozuk_yanit_turu_dusurmez(veri):
    s, inv, _ = veri
    sonuc = skorla(s, inv.id, SahteProvider(["bu JSON degil {{{"]))
    assert sonuc.skor_yazilan == 0
    assert sonuc.eksik == 2  # iki varlık da skorsuz kaldı, sessizce yutulmadı


def test_saglayici_hatasi_turu_dusurmez(veri):
    s, inv, _ = veri
    p = SahteProvider([AiHatasi("kota doldu")])
    sonuc = skorla(s, inv.id, p)
    assert sonuc.skor_yazilan == 0 and sonuc.hatalar == ["kota doldu"]


def test_bir_yigin_dusse_digeri_yazilir(veri):
    s, inv, _ = veri
    p = SahteProvider([
        AiHatasi("geçici"),
        SahteProvider.yanit([{"id": "v1", "skor": 60, "gerekce": "ikinci yığın"}]),
    ])
    sonuc = skorla(s, inv.id, p, yigin_boyutu=1)
    s.flush()
    assert sonuc.yigin == 2 and len(sonuc.hatalar) == 1
    assert sonuc.skor_yazilan == 1


# --------------------------------------------------------------------------- #
# Kota koruması — girdi_hash önbelleği
# --------------------------------------------------------------------------- #


def test_ayni_girdi_ikinci_kez_modele_gitmez(veri):
    s, inv, _ = veri
    yanit = SahteProvider.yanit(
        [{"id": "v1", "skor": 90, "gerekce": "x"}, {"id": "v2", "skor": 80, "gerekce": "y"}]
    )
    p1 = SahteProvider([yanit])
    skorla(s, inv.id, p1)
    s.flush()

    p2 = SahteProvider([yanit])
    sonuc = skorla(s, inv.id, p2)
    assert p2.cagrilar == [], "aynı girdi için modele tekrar gidildi (kota israfı)"
    assert sonuc.atlanan_onbellek == 2 and sonuc.skor_yazilan == 0


def test_veri_degisince_yeniden_skorlanir(veri):
    s, inv, e = veri
    yanit = SahteProvider.yanit(
        [{"id": "v1", "skor": 90, "gerekce": "x"}, {"id": "v2", "skor": 80, "gerekce": "y"}]
    )
    skorla(s, inv.id, SahteProvider([yanit]))
    s.flush()

    # Yeni bir tool aynı varlığı doğruladı: girdi değişti.
    job = s.scalar(select(Job).where(Job.investigation_id == inv.id))
    s.add(Observation(entity_id=e["vpn"].id, job_id=job.id, tool="theharvester",
                      tool_version="1", ham_cikti_ref="t.json", veri={}))
    s.flush()

    p = SahteProvider([yanit])
    skorla(s, inv.id, p)
    assert len(p.cagrilar) == 1, "girdi değiştiği hâlde yeniden skorlanmadı"


def test_eski_skorlar_silinmez_ustune_eklenir(veri):
    """`assessment` yalnızca eklenir (veri-modeli.md 2.6)."""
    s, inv, e = veri
    skorla(s, inv.id, SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 10, "gerekce": "ilk"}, {"id": "v2", "skor": 10, "gerekce": "ilk"}]
    )]))
    s.flush()

    job = s.scalar(select(Job).where(Job.investigation_id == inv.id))
    s.add(Observation(entity_id=e["kok"].id, job_id=job.id, tool="whois-rdap",
                      tool_version="1", ham_cikti_ref="t.json", veri={}))
    s.flush()
    skorla(s, inv.id, SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 95, "gerekce": "ikinci"}, {"id": "v2", "skor": 95, "gerekce": "ikinci"}]
    )]))
    s.flush()

    skorlar = s.execute(
        select(Assessment.skor, Assessment.gerekce)
        .where(Assessment.entity_id == e["kok"].id)
        .order_by(Assessment.skor)
    ).all()
    assert [r.skor for r in skorlar] == [10, 95], "eski skor kayboldu"


# --------------------------------------------------------------------------- #
# Hipotezler ve kayıt alanları
# --------------------------------------------------------------------------- #


def test_hipotez_yazilir_ve_beklemede_baslar(veri):
    s, inv, _ = veri
    p = SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 60, "gerekce": "x"}, {"id": "v2", "skor": 70, "gerekce": "y"}],
        [{"baslik": "vpn ucu", "aciklama": "vpn alt alanı uzaktan erişime işaret ediyor",
          "guven": 75, "ids": ["v1", "v2"]}],
    )])
    sonuc = skorla(s, inv.id, p)
    s.flush()

    assert sonuc.hipotez_yazilan == 1
    h = s.scalar(select(Hypothesis).where(Hypothesis.investigation_id == inv.id))
    assert h.analist_durumu == "beklemede", "AI kendi hipotezini doğrulanmış sayamaz"
    assert len(h.entity_ids) == 2
    assert h.prompt_versiyon == P.PROMPT_VERSIYON


def test_model_ve_prompt_versiyonu_kaydedilir(veri):
    s, inv, _ = veri
    p = SahteProvider(
        [SahteProvider.yanit([{"id": "v1", "skor": 50, "gerekce": "x"},
                              {"id": "v2", "skor": 50, "gerekce": "y"}])],
        model="gemini-test-9",
    )
    skorla(s, inv.id, p)
    s.flush()

    a = s.scalar(select(Assessment).join(Entity, Entity.id == Assessment.entity_id)
                 .where(Entity.investigation_id == inv.id))
    assert a.model == "gemini-test-9"
    assert a.prompt_versiyon == P.PROMPT_VERSIYON
    assert len(a.girdi_hash) == 64


def test_bilinmeyen_arastirma_sessizce_doner(veri):
    import uuid as _u

    s, _, _ = veri
    sonuc = skorla(s, _u.uuid4(), SahteProvider([]))
    assert sonuc.skor_yazilan == 0 and sonuc.hatalar == ["araştırma bulunamadı"]


def test_skorla_commit_etmez(veri):
    """Commit kararı çağırana aittir; rollback testi temizleyebilmeli."""
    s, inv, _ = veri
    skorla(s, inv.id, SahteProvider([SahteProvider.yanit(
        [{"id": "v1", "skor": 50, "gerekce": "x"}, {"id": "v2", "skor": 50, "gerekce": "y"}]
    )]))
    assert s.new, "satırlar oturumda beklemeli, commit edilmiş olmamalı"
