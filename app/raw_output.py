"""Gözlem kimliği üzerinden, yalnızca o işin arşivindeki dosyaya erişim."""
import re
from pathlib import Path

from fastapi import HTTPException

from app.models import Observation
from app.runner import varsayilan_raw_kok

ONIZLEME_BAYT = 256 * 1024


def arsiv_yolu(gozlem: Observation) -> Path:
    kok = varsayilan_raw_kok().resolve()
    ref = Path(gozlem.ham_cikti_ref)
    # DB referansı da güvenilmeyen girdidir. Dosya adı serbest bir yol değildir.
    if not re.fullmatch(r"output\.[a-zA-Z0-9]+", ref.name) or ".." in ref.parts:
        raise HTTPException(404, "Ham çıktı arşivde bulunamadı")
    beklenen = kok / str(gozlem.job_id) / ref.name
    try:
        # Symlink ile başka işe/arşiv dışına çıkış da reddedilir.
        if ref.resolve() != beklenen or beklenen.resolve() != beklenen or not beklenen.is_file():
            raise HTTPException(404, "Ham çıktı arşivde bulunamadı")
    except (OSError, RuntimeError, ValueError):
        raise HTTPException(404, "Ham çıktı arşivde bulunamadı") from None
    return beklenen


def onizle(yol: Path) -> tuple[str, bool]:
    try:
        with yol.open("rb") as dosya:
            veri = dosya.read(ONIZLEME_BAYT + 1)
    except OSError:
        raise HTTPException(404, "Ham çıktı okunamadı") from None
    return veri[:ONIZLEME_BAYT].decode("utf-8", errors="replace"), len(veri) > ONIZLEME_BAYT
