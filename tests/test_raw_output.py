import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.raw_output import ONIZLEME_BAYT, arsiv_yolu, onizle


@pytest.fixture
def arsiv(tmp_path, monkeypatch):
    root = tmp_path / "raw"
    job = uuid.uuid4()
    folder = root / str(job)
    folder.mkdir(parents=True)
    monkeypatch.setenv("RAW_DIR_HOST", str(root))
    path = folder / "output.json"
    path.write_bytes(b'{"value":"<script>alert(1)</script>"}')
    return root, SimpleNamespace(job_id=job, ham_cikti_ref=str(path)), path


def test_arsiv_ve_sinirli_onizleme(arsiv):
    _, obs, path = arsiv
    assert arsiv_yolu(obs) == path
    assert not onizle(path)[1]
    path.write_bytes(b"a" * ONIZLEME_BAYT + b"\xffEND")
    preview, truncated = onizle(path)
    assert len(preview) == ONIZLEME_BAYT and truncated
    assert path.read_bytes().endswith(b"\xffEND")


@pytest.mark.parametrize("kind", ["outside", "other_job", "traversal", "name", "missing", "symlink"])
def test_yol_kacisi_ve_eksik_dosya(arsiv, tmp_path, kind):
    root, obs, path = arsiv
    if kind == "outside":
        other = tmp_path / "output.json"
        other.write_text("secret")
        obs.ham_cikti_ref = str(other)
    elif kind == "other_job":
        obs.job_id = uuid.uuid4()
    elif kind == "traversal":
        obs.ham_cikti_ref = str(path.parent / ".." / str(obs.job_id) / path.name)
    elif kind == "name":
        obs.ham_cikti_ref = str(path.parent / ".env")
    elif kind == "missing":
        obs.ham_cikti_ref = str(path.parent / "output.txt")
    else:
        other = tmp_path / "secret.txt"
        other.write_text("secret")
        link = path.parent / "output.txt"
        try:
            link.symlink_to(other)
        except OSError:
            pytest.skip("Symlink oluşturulamıyor")
        obs.ham_cikti_ref = str(link)
    with pytest.raises(HTTPException) as error:
        arsiv_yolu(obs)
    assert error.value.status_code == 404
