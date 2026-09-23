"""FastAPI + Jinja2 + HTMX arayüzü — iç araç, süsleme yok.

`docs/kapsam.md` Bölüm 5: React/SPA yok, HTMX yeterli.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.ingest import kuyruga_al, upsert_entity
from app.models import Entity, Investigation, Job
from app.models import Observation as ObservationRow
from app.normalize import NormalizeError, domain_mi, kok_domain, normalize
from app.normalize import EntityType
from app.tools._base import ToolRegistry

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
        request, "index.html", {"arastirmalar": arastirmalar}
    )


@app.post("/investigations")
def arastirma_olustur(
    ad: str = Form(...),
    kok_hedef: str = Form(...),
    olusturan: str = Form("ekip"),
    kapsam_notu: str = Form(""),
    yetki_onayi: bool = Form(False),
    yetki_notu: str = Form(""),
    session: Session = Depends(oturum),
):
    """Kök hedef normalize edilerek saklanır — dedup'ın başlangıç noktası."""
    try:
        norm = normalize(EntityType.DOMAIN, kok_hedef)
        if not domain_mi(norm):
            norm = kok_domain(norm)  # subdomain girilmişse köke indir
    except NormalizeError as e:
        raise HTTPException(400, f"geçersiz kök hedef: {e}") from e

    inv = Investigation(
        ad=ad.strip() or norm,
        kok_hedef=norm,
        kapsam_notu=kapsam_notu.strip() or None,
        yetki_onayi=yetki_onayi,
        yetki_notu=yetki_notu.strip() or None,
        olusturan=olusturan.strip() or "ekip",
    )
    session.add(inv)
    session.commit()
    return RedirectResponse(f"/investigations/{inv.id}", status_code=303)


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
    inv_id: uuid.UUID, request: Request, session: Session = Depends(oturum)
):
    inv = _arastirma(session, inv_id)
    return templates.TemplateResponse(
        request,
        "investigation.html",
        {
            "inv": inv,
            "tools": sorted(registry().hepsi(), key=lambda a: a.spec.name),
            "isler": _isler(session, inv_id),
        },
    )


@app.post("/investigations/{inv_id}/run")
def calistir(
    inv_id: uuid.UUID,
    tool: str = Form("subfinder"),
    session: Session = Depends(oturum),
):
    """Tool'u kök hedef üzerinde kuyruğa alır.

    YETKİ KONTROLÜ BURADA DA VAR ama asıl kontrol runner'dadır. Arayüzdeki
    `disabled` özniteliği atlanabilir — form elle POST edilebilir. Bu yüzden
    sunucu tarafında da denetlenir; runner ise üçüncü ve son savunmadır.
    """
    inv = _arastirma(session, inv_id)
    adapter = registry().get(tool)
    if adapter is None:
        raise HTTPException(400, f"bilinmeyen tool: {tool}")
    if adapter.spec.yetki_ister() and not inv.yetki_onayi:
        raise HTTPException(
            403,
            f"{tool} seviyesi {adapter.spec.passivity.value}; yetki onayı gerekir",
        )

    # Kök hedef arayüzden girildi, bir tool GÖRMEDİ: gozlem_sayisi artmaz.
    entity = upsert_entity(
        session, inv.id, EntityType.DOMAIN, inv.kok_hedef, inv.kok_hedef,
        gozlem=False,
    )
    job = kuyruga_al(
        session,
        inv.id,
        adapter.spec.name,
        adapter.spec.version,
        entity,
        derinlik=0,
    )
    session.commit()

    if job is not None:
        _kuyruga_gonder(job.id)
    return RedirectResponse(f"/investigations/{inv_id}", status_code=303)


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
    inv_id: uuid.UUID, request: Request, session: Session = Depends(oturum)
):
    """HTMX ile 2 saniyede bir yenilenen tablo — sonuçlar canlı dolar."""
    _arastirma(session, inv_id)

    # Her varlığın hangi tool'lardan geldiği: İlke 2'nin liste görünümündeki hâli.
    satirlar = session.execute(
        select(
            Entity,
            func.string_agg(func.distinct(ObservationRow.tool), ", ").label("tools"),
        )
        .outerjoin(ObservationRow, ObservationRow.entity_id == Entity.id)
        .where(Entity.investigation_id == inv_id)
        .group_by(Entity.id)
        .order_by(desc(Entity.gozlem_sayisi), Entity.deger_norm)
    ).all()

    return templates.TemplateResponse(
        request,
        "_entities.html",
        {
            "inv_id": inv_id,
            "satirlar": satirlar,
            "isler": _isler(session, inv_id),
        },
    )


@app.get("/entities/{entity_id}", response_class=HTMLResponse)
def varlik(
    entity_id: uuid.UUID, request: Request, session: Session = Depends(oturum)
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
        },
    )


@app.get("/saglik")
def saglik():
    return {"durum": "ok", "tool_sayisi": len(registry())}
