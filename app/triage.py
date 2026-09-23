"""Deterministik ön eleme v1: yalnızca görünüm, hiçbir kayıt değiştirilmez.

Eşiklerin ölçüm dayanağı ve sınırları: docs/on-eleme.md.
Gözlem tekrarları kaynak çeşitliliği veya risk skoru değildir.
"""

from dataclasses import dataclass


GRUPLAR = {
    "oncelikli": "Öncelikli",
    "incele": "İncelenecek",
    "baglam": "Bağlam / sağlayıcı",
    "sertifika": "Sertifikalar",
}
KAYNAK_ESIKLERI = {
    "domain": 1, "subdomain": 2, "ip": 1, "netblock": 2, "asn": 1,
    "email": 1, "service": 1, "cert": 1, "org": 1, "tech": 1,
}
ISARETLER = {
    "hedefe_ait_degil": "Hedefe ait olmayabilir",
    "saglayici_olabilir": "Sağlayıcı olabilir",
    "prefiks_sinir_asildi": "Prefiks sınırı aşılmış",
}


@dataclass(frozen=True)
class OnEleme:
    grup: str
    gerekceler: tuple[str, ...]

    @property
    def sira(self) -> int:
        return tuple(GRUPLAR).index(self.grup)


def degerlendir(
    tip: str, kaynak_sayisi: int, iliskili: bool,
    isaretler: frozenset[str] = frozenset(), *, kok: bool = False,
) -> OnEleme:
    """Saf fonksiyon; aynı girdi aynı grubu ve gerekçeleri üretir."""
    esik = KAYNAK_ESIKLERI.get(tip, 1)
    gerekceler = []
    if kok:
        gerekceler.append("Araştırmanın kök hedefi")
    if kaynak_sayisi == 0:
        gerekceler.append("Doğrudan tool gözlemi yok")
    elif kaynak_sayisi < esik:
        gerekceler.append(f"{tip} için {esik} farklı tool eşiğinin altında")
    else:
        gerekceler.append(f"{tip} için {esik} farklı tool eşiği sağlandı")
    if not iliskili:
        gerekceler.append("İlişkisi bulunmayan varlık")
    gerekceler.extend(metin for ad, metin in ISARETLER.items() if ad in isaretler)

    if tip == "cert":
        grup = "sertifika"
        gerekceler.append("Sertifika: destekleyici kanıt olarak geride sıralandı")
    elif kok:
        grup = "oncelikli"
    elif isaretler.intersection(ISARETLER):
        grup = "baglam"
    elif kaynak_sayisi < esik or not iliskili:
        grup = "incele"
    else:
        grup = "oncelikli"
    return OnEleme(grup, tuple(gerekceler))
