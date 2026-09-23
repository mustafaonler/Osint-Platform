"""Ham çıktı ve rapor için gerçek PostgreSQL/HTTP testleri; rollback ile yalıtım."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.db import SessionLocal
from app.main import app, oturum
from app.models import Assessment, Entity, Hypothesis, Investigation, Job, Observation, Relationship
from app.raw_output import ONIZLEME_BAYT
from app.report import metin


@pytest.fixture
def rapor_verisi(tmp_path, monkeypatch):
    monkeypatch.setenv("RAW_DIR_HOST", str(tmp_path))
    with SessionLocal() as s:
        inv = Investigation(ad="Rapor <script> [x](https://example.com)", kok_hedef="example.com", olusturan="pytest")
        other = Investigation(ad="OTHER-PRIVATE", kok_hedef="example.org", olusturan="pytest")
        s.add_all([inv, other])
        s.flush()
        entities = [Entity(investigation_id=inv.id, tip="subdomain", deger_norm=f"n{i}.example.com",
                           deger_ham=f"n{i}.example.com") for i in range(105)]
        foreign = Entity(investigation_id=other.id, tip="domain", deger_norm="example.org", deger_ham="OTHER-PRIVATE")
        s.add_all([*entities, foreign])
        s.flush()
        job = Job(investigation_id=inv.id, tool="test", tool_version="1", hedef_deger="example.com", durum="failed", hata_mesaji="timeout")
        other_job = Job(investigation_id=other.id, tool="test", tool_version="1", hedef_deger="example.org")
        s.add_all([job, other_job])
        s.flush()
        folder = tmp_path / str(job.id)
        folder.mkdir()
        path = folder / "output.json"
        path.write_bytes(b'<script>alert(1)</script>' + b'a' * ONIZLEME_BAYT + b'\xffEND')
        obs = Observation(entity_id=entities[0].id, job_id=job.id, tool="test", tool_version="1", ham_cikti_ref=str(path), ham_cikti_yol="$.items[0]")
        cross = Observation(entity_id=entities[0].id, job_id=other_job.id, tool="OTHER-PRIVATE", tool_version="1", ham_cikti_ref=str(path))
        s.add_all([obs, cross, Relationship(investigation_id=inv.id, kaynak_entity_id=entities[0].id, hedef_entity_id=entities[1].id, tip="cname_for")])
        now = datetime.now(timezone.utc)
        for index, reason in enumerate(("old-assessment", "latest-assessment")):
            s.add(Assessment(entity_id=entities[0].id, skor=10 + index, gerekce=reason,
                             model="test-model", prompt_versiyon="1", girdi_hash=reason,
                             zaman=now + timedelta(seconds=index)))
        for status in ("dogrulandi", "beklemede", "reddedildi"):
            s.add(Hypothesis(investigation_id=inv.id, baslik=status, aciklama="test",
                             guven=50, entity_ids=[entities[0].id], model="test", prompt_versiyon="1", analist_durumu=status))
        s.flush()
        app.dependency_overrides[oturum] = lambda: s
        try:
            with TestClient(app) as client:
                yield client, s, inv, entities, obs, cross, path
        finally:
            app.dependency_overrides.pop(oturum, None)
            s.rollback()


def test_raw_http_guvenli_onizleme_tam_indirme_ve_hatalar(rapor_verisi):
    client, s, inv, entities, obs, cross, path = rapor_verisi
    url = f"/observations/{obs.id}/raw"
    response = client.get(url)
    assert response.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "256 KiB" in response.text and "$.items[0]" in response.text
    download = client.get(url + "?indir=true")
    assert download.content == path.read_bytes()
    assert "attachment" in download.headers["content-disposition"]
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "application/octet-stream" in download.headers["content-type"]
    assert client.get(f"/observations/{cross.id}/raw").status_code == 404
    assert client.get(f"/observations/{uuid.uuid4()}/raw").status_code == 404
    assert url in client.get(f"/entities/{entities[0].id}").text
    obs.ham_cikti_ref = str(path.parent / "output.missing")
    s.flush()
    assert client.get(url).status_code == 404


def test_rapor_tum_varliklar_kanitlar_izolasyon_ve_ai_ayrimi(rapor_verisi):
    client, s, inv, entities, obs, cross, path = rapor_verisi
    response = client.get(f"/investigations/{inv.id}/report.md")
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "text/markdown" in response.headers["content-type"]
    md = response.text
    assert all(metin(e.id) in md for e in entities)
    assert "Varlık: 105" in md and "Gözlem: 1" in md
    assert "OTHER-PRIVATE" not in md
    assert metin("latest-assessment") in md and metin("old-assessment") not in md
    assert metin(obs.id) in md and metin("$.items[0]") in md
    assert "&lt;script&gt;" in md and "[x](https://example.com)" not in md
    confirmed, unconfirmed = md.split("## AI hipotezleri — doğrulanmamış / reddedilmiş")
    assert "dogrulandi" in confirmed
    assert "beklemede" in unconfirmed and "reddedildi" in unconfirmed
    assert "failed" in md and "timeout" in md
    assert client.get(f"/investigations/{uuid.uuid4()}/report.md").status_code == 404
    assert not s.dirty and not s.new and not s.deleted


def test_bos_rapor_ve_gecersiz_hipotez_referansi(rapor_verisi):
    client, s, inv, entities, obs, cross, path = rapor_verisi
    empty = Investigation(ad="empty", kok_hedef="example.net", olusturan="pytest")
    invalid_id = uuid.uuid4()
    s.add(empty)
    s.add(Hypothesis(investigation_id=inv.id, baslik="invalid-ref", aciklama="test", guven=20,
                     entity_ids=[invalid_id], model="test", prompt_versiyon="1"))
    s.flush()
    report = client.get(f"/investigations/{inv.id}/report.md").text
    assert metin(invalid_id) not in report
    assert "Araştırma dışı veya eksik referans" in report
    report = client.get(f"/investigations/{empty.id}/report.md")
    assert report.status_code == 200 and "Varlık: 0" in report.text
    assert "Henüz AI değerlendirmesi yok" in report.text
