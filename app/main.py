"""FastAPI + Jinja2 + HTMX arayüzü — iç araç, süsleme yok.

`docs/kapsam.md` Bölüm 5: React/SPA yok, HTMX yeterli.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.ingest import kuyruga_al, upsert_entity
from app.models import Entity, Investigation, Job
from app.models import Observation as ObservationRow
from app.normalize import NormalizeError, domain_mi, kok_domain, normalize
from app.normalize import EntityType
from app.tools._base import ToolRegistry
from app.ai.skorla import son_skorlar
from app.triage import GRUPLAR
from app.triage_query import listele, sayfala
from app.relationships import ILISKI_ADLARI, komsular
from app.raw_output import ONIZLEME_BAYT, arsiv_yolu, onizle
from app.report import markdown_rapor

Grup = Literal["tumu", "oncelikli", "incele", "baglam", "sertifika"]
Onem = Literal["tumu", "kritik", "yuksek", "orta", "dusuk", "skorsuz"]

# AI skorunun analiste gosterilen karsiligi. Esikler prompt'taki rubrikle
# (app/ai/prompt.py SISTEM) AYNI olmak zorunda: modele "90+ essiz bir sebep
# ister" deyip arayuzde 85'i kritik gostermek, skoru anlamsizlastirir.
ONEM_DUZEYLERI = {
    "kritik": ("Kritik", 90, 101),
    "yuksek": ("Yüksek", 70, 90),
    "orta": ("Orta", 50, 70),
    "dusuk": ("Düşük", 0, 50),
    "skorsuz": ("Skorlanmadı", None, None),
}


def _onem_kodu(skor: int | None) -> str:
    if skor is None:
        return "skorsuz"
    for kod, (_, alt, ust) in ONEM_DUZEYLERI.items():
        if alt is not None and alt <= skor < ust:
            return kod
    return "skorsuz"

KOK = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(KOK / "templates"))

app = FastAPI(title="OSINT Orkestrasyon Platformu")

# htmx CDN'den DEĞİL yerelden servis edilir: sistem kapalı çalışır (VPN/Tailscale
# arkası), dış ağ olmadan da arayüz açılmalıdır.
app.mount("/static", StaticFiles(directory=str(KOK / "static")), name="static")

_registry: ToolRegistry | None = None


def registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry(KOK / "tools")
    return _registry


def oturum():
    with SessionLocal() as s:
        yield s


def _kuyruga_gonder(job_id: uuid.UUID) -> None:
    """Celery'ye gönder. Broker yoksa istek düşmesin — job 'queued' kalır.

    Arayüz kuyruğun ayakta olmasına bağımlı değildir; iş satırı zaten
    veritabanında durur ve worker geldiğinde alınabilir.
    """
    from app.worker import kuyruga_gonder

    kuyruga_gonder(job_id)


# --------------------------------------------------------------------------- #
# Araştırma listesi
# --------------------------------------------------------------------------- #


@app.get("/", response_class=HTMLResponse)
def kok(request: Request, session: Session = Depends(oturum)):
    arastirmalar = (
        session.execute(
            select(Investigation).order_by(desc(Investigation.olusturma))
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request, "index.html",
        {
            "arastirmalar": arastirmalar,
            "tools": sorted(registry().hepsi(), key=lambda a: a.spec.name),
        },
    )


@app.post("/investigations")
def arastirma_olustur(
    ad: str = Form(...),
    kok_hedef: str = Form(...),
    olusturan: str = Form("ekip"),
    kapsam_notu: str = Form(""),
    yetki_onayi: bool = Form(False),
    yetki_notu: str = Form(""),
    toollar: list[str] = Form(default=[]),
    session: Session = Depends(oturum),
):
    """Araştırmayı kurar: kök hedef + bu araştırmada kullanılacak tool'lar.

    Kök hedef DOMAIN ya da IP olabilir. Tip burada bir kez belirlenir ve
    saklanır; taramanın hangi tool'larla başlayacağı ve zincirin nereden
    açılacağı buna bağlıdır.
    """
    norm, kok_tip = _kok_hedef_coz(kok_hedef)

    gecerli = {a.spec.name for a in registry().hepsi()}
    secili = [t for t in dict.fromkeys(toollar) if t in gecerli]
    bilinmeyen = set(toollar) - gecerli
    if bilinmeyen:
        raise HTTPException(400, f"bilinmeyen tool: {', '.join(sorted(bilinmeyen))}")

    inv = Investigation(
        ad=ad.strip() or norm,
        kok_hedef=norm,
        kok_tip=kok_tip.value,
        secili_toollar=secili,
        kapsam_notu=kapsam_notu.strip() or None,
        yetki_onayi=yetki_onayi,
        yetki_notu=yetki_notu.strip() or None,
        olusturan=olusturan.strip() or "ekip",
    )
    session.add(inv)
    session.commit()
    return RedirectResponse(f"/investigations/{inv.id}", status_code=303)


def _kok_hedef_coz(ham: str) -> tuple[str, EntityType]:
    """Kullanıcının girdiği hedefi normalize eder ve tipini belirler.

    ÖNCE IP DENENİR: `1.2.3.4` bir domain olarak da ayrıştırılmaya çalışılırsa
    PSL'de karşılığı olmadığı için kafa karıştırıcı bir hata verir. IP değilse
    domain kabul edilir; subdomain girilmişse köke indirilir.
    """
    ham = (ham or "").strip()
    if not ham:
        raise HTTPException(400, "kök hedef boş olamaz")
    try:
        return normalize(EntityType.IP, ham), EntityType.IP
    except NormalizeError:
        pass
    try:
        norm = normalize(EntityType.DOMAIN, ham)
    except NormalizeError as e:
        raise HTTPException(400, f"geçersiz kök hedef: {e}") from e
    if not domain_mi(norm):
        norm = kok_domain(norm)  # subdomain girilmişse köke indir
    return norm, EntityType.DOMAIN


# --------------------------------------------------------------------------- #
# Araştırma detayı
# --------------------------------------------------------------------------- #


def _arastirma(session: Session, inv_id: uuid.UUID) -> Investigation:
    inv = session.get(Investigation, inv_id)
    if inv is None:
        raise HTTPException(404, "araştırma bulunamadı")
    return inv


@app.get("/investigations/{inv_id}", response_class=HTMLResponse)
def arastirma(
    inv_id: uuid.UUID, request: Request, session: Session = Depends(oturum),
    grup: Grup = "tumu", onem: Onem = "tumu", sayfa: int = Query(1, ge=1),
):
    inv = _arastirma(session, inv_id)
    kok_tip = EntityType(inv.kok_tip)
    adapterlar = _secili_adapterlar(inv)
    return templates.TemplateResponse(
        request,
        "investigation.html",
        {
            "inv": inv,
            "tools": adapterlar,
            # Bu turda hangileri BAŞLAYACAK: kök hedefin tipini kabul edenler.
            # Kalanlar zincirde sonraki derinlikte devreye girer.
            "baslayanlar": [a.spec.name for a in adapterlar
                            if kok_tip in a.spec.kabul_eder],
            "isler": _isler(session, inv_id),
            "grup": grup,
            "onem": onem,
            "sayfa": sayfa,
        },
    )


@app.post("/investigations/{inv_id}/run")
def calistir(inv_id: uuid.UUID, session: Session = Depends(oturum)):
    """Araştırmanın SEÇİLİ TOOL'LARINI kök hedef üzerinde kuyruğa alır.

    Tek tek tool seçtirmek yerine tarama tek hamlede başlar: analist tool
    kararını araştırmayı kurarken verdi, her turda tekrar vermek zorunda
    değil. Kök hedefin tipini kabul etmeyen tool'lar bu turda atlanır —
    atlanmaları veri kaybı değildir, zincir onları sonraki derinlikte
    kendiliğinden çağırır (`shodan-lookup` IP bekler, domain'den başlayan
    bir turda ikinci derinlikte devreye girer).

    YETKİ KONTROLÜ BURADA DA VAR ama asıl kontrol runner'dadır. Arayüzdeki
    `disabled` özniteliği atlanabilir — form elle POST edilebilir. Bu yüzden
    sunucu tarafında da denetlenir; runner ise üçüncü ve son savunmadır.
    """
    inv = _arastirma(session, inv_id)
    kok_tip = EntityType(inv.kok_tip)

    adapterlar = _secili_adapterlar(inv)
    if not adapterlar:
        raise HTTPException(400, "bu araştırmada seçili tool yok")

    baslayanlar = [a for a in adapterlar if kok_tip in a.spec.kabul_eder]
    if not baslayanlar:
        raise HTTPException(
            400,
            f"seçili tool'ların hiçbiri {kok_tip.value} kabul etmiyor; "
            "araştırmayı uygun bir tool ile kurun",
        )

    # Kök hedef arayüzden girildi, bir tool GÖRMEDİ: gozlem_sayisi artmaz.
    entity = upsert_entity(
        session, inv.id, kok_tip, inv.kok_hedef, inv.kok_hedef, gozlem=False,
    )
    idler: list[uuid.UUID] = []
    for adapter in baslayanlar:
        if adapter.spec.yetki_ister() and not inv.yetki_onayi:
            continue  # sessizce atlanmaz: arayüz bu tool'u zaten kapalı gösterir
        job = kuyruga_al(
            session, inv.id, adapter.spec.name, adapter.spec.version,
            entity, derinlik=0,
        )
        if job is not None:
            idler.append(job.id)
    session.commit()

    # GÖNDERİM COMMIT'TEN SONRA: önce gönderilirse görev, job satırı görünür
    # olmadan alınabilir ve "job bulunamadı" ile düşer.
    for jid in idler:
        _kuyruga_gonder(jid)
    return RedirectResponse(f"/investigations/{inv_id}", status_code=303)


def _secili_adapterlar(inv: Investigation) -> list:
    """Araştırmanın tool'ları. Liste boşsa kısıt yoktur, hepsi kullanılır."""
    secili = set(inv.secili_toollar or ())
    return sorted(
        (a for a in registry().hepsi() if not secili or a.spec.name in secili),
        key=lambda a: a.spec.name,
    )


# --------------------------------------------------------------------------- #
# HTMX parçaları — canlı dolan tablo
# --------------------------------------------------------------------------- #


def _isler(session: Session, inv_id: uuid.UUID) -> list[Job]:
    return list(
        session.execute(
            select(Job)
            .where(Job.investigation_id == inv_id)
            .order_by(desc(Job.olusturma))
        )
        .scalars()
        .all()
    )


@app.get("/investigations/{inv_id}/entities", response_class=HTMLResponse)
def varliklar(
    inv_id: uuid.UUID, request: Request, session: Session = Depends(oturum),
    grup: Grup = "tumu", onem: Onem = "tumu", sayfa: int = Query(1, ge=1),
):
    """Varlık tablosu. Çalışan iş varken HTMX ile canlı yenilenir.

    İKİ AYRI SÜZGEÇ, İKİSİ DE YALNIZCA GÖRÜNÜM: `grup` deterministik ön
    elemenin sonucu, `onem` AI skorunun bandı. Hiçbiri veri silmez; sayımlar
    her zaman TÜM varlıklar üzerinden hesaplanır ki analist neyi daralttığını
    görsün (İlke 1).
    """
    inv = _arastirma(session, inv_id)
    skorlar = son_skorlar(session, inv_id)
    satirlar = listele(session, inv_id, inv.kok_hedef)

    onem_sayim = {kod: 0 for kod in ONEM_DUZEYLERI}
    for s in satirlar:
        a = skorlar.get(s.entity.id)
        onem_sayim[_onem_kodu(a.skor if a else None)] += 1

    if onem != "tumu":
        satirlar = [
            s for s in satirlar
            if _onem_kodu(
                (skorlar.get(s.entity.id).skor if skorlar.get(s.entity.id) else None)
            ) == onem
        ]

    gorunum = sayfala(satirlar, grup, sayfa)
    return templates.TemplateResponse(
        request,
        "_entities.html",
        {
            "inv_id": inv_id,
            **gorunum,
            "gruplar": GRUPLAR,
            "isler": _isler(session, inv_id),
            "skorlar": skorlar,
            "onem": onem,
            "onem_duzeyleri": ONEM_DUZEYLERI,
            "onem_sayim": onem_sayim,
            "skorlandi": bool(skorlar),
        },
    )


@app.get("/entities/{entity_id}", response_class=HTMLResponse)
def varlik(
    entity_id: uuid.UUID, request: Request, session: Session = Depends(oturum),
    iliski_sayfa: int = Query(1, ge=1),
):
    """Varlığın kanıt zinciri: hangi tool, ne zaman, hangi ham çıktının neresinde."""
    entity = session.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(404, "varlık bulunamadı")
    gozlemler = (
        session.execute(
            select(ObservationRow)
            .where(ObservationRow.entity_id == entity_id)
            .order_by(desc(ObservationRow.zaman))
        )
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request,
        "entity.html",
        {
            "entity": entity,
            "gozlemler": gozlemler,
            "inv": session.get(Investigation, entity.investigation_id),
            "iliskiler": komsular(session, entity, iliski_sayfa),
            "iliski_adlari": ILISKI_ADLARI,
        },
    )


@app.get("/saglik")
def saglik():
    return {"durum": "ok", "tool_sayisi": len(registry())}


@app.get("/observations/{observation_id}/raw", response_class=HTMLResponse)
def ham_cikti(
    observation_id: uuid.UUID, request: Request,
    indir: bool = False, session: Session = Depends(oturum),
):
    gozlem = session.scalar(
        select(ObservationRow).join(Entity, Entity.id == ObservationRow.entity_id)
        .join(Job, Job.id == ObservationRow.job_id)
        .where(ObservationRow.id == observation_id,
               Job.investigation_id == Entity.investigation_id)
    )
    if gozlem is None:
        raise HTTPException(404, "Gözlem bulunamadı")
    yol = arsiv_yolu(gozlem)
    headers = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    if indir:
        return FileResponse(yol, media_type="application/octet-stream",
                            filename=f"{gozlem.job_id}-{yol.name}", headers=headers)
    icerik, kirpildi = onizle(yol)
    return templates.TemplateResponse(request, "raw.html", {
        "gozlem": gozlem, "icerik": icerik, "kirpildi": kirpildi,
        "limit_kib": ONIZLEME_BAYT // 1024,
    }, headers=headers)


@app.get("/investigations/{inv_id}/report.md")
def rapor(inv_id: uuid.UUID, session: Session = Depends(oturum)):
    inv = _arastirma(session, inv_id)
    return Response(markdown_rapor(session, inv), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="osint-{inv.id}.md"',
                             "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})
