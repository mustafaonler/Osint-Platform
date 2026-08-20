"""Tool sözleşmesi — `docs/veri-modeli.md` Bölüm 4, `docs/kapsam.md` Bölüm 5.2.

Sistemin en kritik tasarım kararı burada yaşar: **yeni tool eklemek çekirdek
koda dokunmadan yapılır.** Her tool bir klasör, üç dosya (manifest.yaml,
adapter.py, fixtures/).

Sorumluluk sınırı (adapter bunları BİLMEZ, runner yapar):
timeout uygulama, rate limit, retry/backoff, kota takibi, hata izolasyonu,
ham çıktıyı diske yazma, pasiflik seviyesi kontrolü.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Protocol, runtime_checkable

import yaml

from app.normalize import EntityType

class ToolYuklemeHatasi(Exception):
    """manifest.yaml var ama tool yüklenemiyor — sessizce atlanmaz."""


# manifest.yaml'da bulunması ZORUNLU alanlar (docs/kapsam.md 5.2).
_MANIFEST_ZORUNLU = (
    "name",
    "version",
    "passivity",
    "kabul_eder",
    "uretir",
    "calistirma",
)

__all__ = [
    "ToolYuklemeHatasi",
    "Passivity",
    "RelationType",
    "ToolSpec",
    "ToolConfig",
    "RawResult",
    "Observation",
    "ObservedRelation",
    "ToolAdapter",
    "ToolRegistry",
]


# --------------------------------------------------------------------------- #
# Enum'lar — Bölüm 1
# --------------------------------------------------------------------------- #


class Passivity(StrEnum):
    """Pasiflik sınıflandırması — `docs/kapsam.md` Bölüm 3.2."""

    P0 = "P0"  # hedefe hiç dokunulmaz (crt.sh, Shodan, RDAP, BGP)
    P1 = "P1"  # ortak altyapı (public resolver üzerinden DNS)
    P2 = "P2"  # hedefe normal kullanıcı düzeyinde — yetki onayı ister
    A = "A"  # aktif — v1 kapsam dışı


class RelationType(StrEnum):
    """İlişkiler YÖNLÜDÜR. Çift yönlü kayıt tutulmaz."""

    SUBDOMAIN_OF = "subdomain_of"  # sub → domain
    RESOLVES_TO = "resolves_to"  # domain/sub → ip
    MX_FOR = "mx_for"  # sub → domain
    NS_FOR = "ns_for"  # sub → domain
    CERT_FOR = "cert_for"  # cert → domain/sub
    IN_NETBLOCK = "in_netblock"  # ip → netblock
    ANNOUNCED_BY = "announced_by"  # netblock → asn
    OWNED_BY = "owned_by"  # netblock/domain → org
    RUNS_ON = "runs_on"  # service → ip
    USES_TECH = "uses_tech"  # sub/service → tech
    EMAIL_AT = "email_at"  # email → domain


# --------------------------------------------------------------------------- #
# Veri sınıfları — Bölüm 4.1
# --------------------------------------------------------------------------- #

_BOS_MAP: Mapping[str, Any] = MappingProxyType({})


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    passivity: Passivity
    kabul_eder: frozenset[EntityType]
    uretir: frozenset[EntityType]
    calistirma: str  # "api" | "docker" | "python"
    image: str | None = None
    auth_env: tuple[str, ...] = ()
    timeout_sn: int = 60
    dakikalik_istek: int | None = None
    aylik_kota: int | None = None
    varsayilan_guven: int = 50
    etkin: bool = True

    def yetki_ister(self) -> bool:
        """P2 ve A seviyesi `investigation.yetki_onayi` olmadan ÇALIŞTIRILMAZ.

        Bu kontrol RUNNER'da yapılır, arayüzde değil — arayüz kontrolü atlanabilir.
        """
        return self.passivity in (Passivity.P2, Passivity.A)


@dataclass(frozen=True)
class ToolConfig:
    """Runner'ın adapter'a verdiği çalışma zamanı ayarları.

    API anahtarları `env` içinden okunur; adapter `os.environ`'a doğrudan
    bakmaz, böylece test edilebilir kalır.

    Timeout BURADA YOKTUR — tek doğruluk kaynağı `ToolSpec.timeout_sn`'dir
    (manifest'ten okunur). Zaten timeout'u uygulayan da adapter değil runner'dır.

    `resolver` pasiflik seviyesini doğrudan belirler (`docs/kapsam.md` 3.2):
    public resolver (1.1.1.1) üzerinden sorgu P1'dir ve varsayılan açıktır;
    hedefin kendi authoritative NS'ine yöneltilirse aynı modül P2'ye düşer ve
    `investigation.yetki_onayi` ister. Resolver konfigüre edilebilir olmadan bu
    ayrım uygulanamaz.
    """

    env: Mapping[str, str] = field(default_factory=lambda: _BOS_MAP)
    resolver: str = "1.1.1.1"  # public resolver → P1. Değiştirilirse P2 olabilir.
    proxy: str | None = None
    ekstra: Mapping[str, Any] = field(default_factory=lambda: _BOS_MAP)


@dataclass(frozen=True)
class RawResult:
    """Tool'un işlenmemiş çıktısı."""

    icerik: bytes
    format: str  # "json" | "text" | "xml"
    cikis_kodu: int = 0
    sure_ms: int = 0
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ObservedRelation:
    """Bu gözlemin başka bir varlıkla ilişkisi.

    DEĞERLERLE ifade edilir, ID ile değil — parser veritabanını tanımaz.
    """

    tip: RelationType
    hedef_tip: EntityType
    hedef_deger: str
    yon: str = "giden"  # "giden" | "gelen"


@dataclass(frozen=True)
class Observation:
    """Parser çıktısı. DİKKAT: `entity_id` YOK — henüz varlık oluşmamış olabilir.

    ---------------------------------------------------------------------------
    BU EKSİKLİK BİLİNÇLİDİR — alan EKLENMEYECEKTİR.
    ---------------------------------------------------------------------------
    Projenin en önemli tasarım kararı budur. `Observation` bir `entity_id`
    taşımadığı için parser veritabanının varlığından habersiz kalır; ID
    çözümlemesi tamamen ingest katmanının işidir (Bölüm 4.5).

    Sonuç: `parse()` SAF FONKSİYON olur ve tek başına, yalnızca bir fixture
    dosyasıyla test edilebilir. Buraya `entity_id` eklemek parser'ı DB'ye
    bağlar, fixture testlerini imkânsızlaştırır ve "fixture'sız tool kabul
    edilmez" kuralını çöpe atar.
    """

    tip: EntityType
    deger_ham: str
    nitelikler: dict[str, Any] = field(default_factory=dict)
    guven: int | None = None  # None → spec.varsayilan_guven
    kaynak_yol: str | None = None  # ham çıktı içindeki JSONPath
    iliskiler: tuple[ObservedRelation, ...] = ()


# --------------------------------------------------------------------------- #
# Adapter protokolü — Bölüm 4.2
# --------------------------------------------------------------------------- #


@runtime_checkable
class ToolAdapter(Protocol):
    spec: ToolSpec

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        """Tool'u çalıştırır, ham çıktıyı döndürür.

        Diske yazma, timeout, retry: RUNNER'ın sorumluluğudur — burada YAPILMAZ.
        """
        ...

    def parse(self, ham: RawResult) -> list[Observation]:
        """Ham çıktı → gözlemler.

        SAF FONKSİYON: ağ yok, DB yok, dosya yok, saat okuma yok, rastgelelik yok.
        Bozuk/eksik çıktıda istisna fırlatmaz, elden geldiğince ayrıştırır.
        """
        ...

    def saglik(self) -> bool:
        """Bağımlılık ve kimlik doğrulama kontrolü. Açılışta çalışır."""
        ...


# --------------------------------------------------------------------------- #
# Registry ve yetenek grafiği — Bölüm 4.4
# --------------------------------------------------------------------------- #


class ToolRegistry:
    """Eklenti keşfi + yetenek grafiği.

    Zincirleme kuralı hiçbir yerde ELLE YAZILMAZ. Grafik, manifest'lerdeki
    `kabul_eder` / `uretir` alanlarından kendiliğinden kurulur.
    """

    def __init__(self, kok: Path | str) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self._kesfet(Path(kok))

    # -- keşif -------------------------------------------------------------- #

    def _kesfet(self, kok: Path) -> None:
        """`app/tools/*/manifest.yaml` dosyalarını okur, adapter'ları yükler.

        SESSİZ ATLAMA İLE NET HATA ARASINDAKİ SINIR:

        * Klasörde `manifest.yaml` YOKSA burası bir tool değildir (`__pycache__`,
          yardımcı modüller). Sessizce atlanır — bu normal durumdur.
        * `manifest.yaml` VARSA burası bir tool olmak İDDİASINDADIR. Bozuksa
          `ToolYuklemeHatasi` fırlatılır. Sessizce atlamak, sistemin bir
          tool'u fark ettirmeden kaybetmesi demektir; yanlış negatif
          görünmezdir (İlke 1'in aynı mantığı).

        Olmayan veya boş klasör hata DEĞİLDİR: registry boş açılır.
        """
        if not kok.is_dir():
            return
        for klasor in sorted(p for p in kok.iterdir() if p.is_dir()):
            if klasor.name.startswith((".", "_")) or klasor.name == "__pycache__":
                continue
            manifest = klasor / "manifest.yaml"
            if not manifest.is_file():
                continue  # tool değil
            self.kayit(self._yukle(klasor, manifest))

    @staticmethod
    def _manifest_oku(manifest: Path) -> dict[str, Any]:
        try:
            veri = yaml.safe_load(manifest.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            raise ToolYuklemeHatasi(f"{manifest}: okunamadı/ayrıştırılamadı: {e}") from e
        if not isinstance(veri, dict):
            raise ToolYuklemeHatasi(f"{manifest}: kök öğe sözlük olmalı")

        eksik = [a for a in _MANIFEST_ZORUNLU if a not in veri]
        if eksik:
            raise ToolYuklemeHatasi(f"{manifest}: zorunlu alan eksik: {eksik}")

        try:
            Passivity(str(veri["passivity"]))
        except ValueError as e:
            raise ToolYuklemeHatasi(
                f"{manifest}: geçersiz passivity {veri['passivity']!r}; "
                f"beklenen: {[p.value for p in Passivity]}"
            ) from e

        for alan in ("kabul_eder", "uretir"):
            deger = veri[alan]
            if not isinstance(deger, list):
                raise ToolYuklemeHatasi(f"{manifest}: {alan} liste olmalı")
            for tip in deger:
                try:
                    EntityType(str(tip).lower())
                except ValueError as e:
                    raise ToolYuklemeHatasi(
                        f"{manifest}: {alan} içinde bilinmeyen varlık tipi {tip!r}"
                    ) from e
        return veri

    @staticmethod
    def _yukle(klasor: Path, manifest: Path) -> ToolAdapter:
        """Manifest'i doğrular, adapter.py'yi yükler, ikisinin tutarlılığını denetler.

        Manifest ile `ToolSpec` iki ayrı doğruluk kaynağıdır ve zamanla
        birbirinden kayabilir; kaydıkları an registry bir şey, runner başka bir
        şey görür. Bu yüzden uyuşmazlık sessiz kalmaz, hata olur.
        """
        veri = ToolRegistry._manifest_oku(manifest)

        adapter_py = klasor / "adapter.py"
        if not adapter_py.is_file():
            raise ToolYuklemeHatasi(f"{klasor}: manifest.yaml var ama adapter.py yok")

        # Fixture'sız tool kabul edilmez (docs/kapsam.md 5.2).
        fixtures = klasor / "fixtures"
        if not fixtures.is_dir() or not any(fixtures.iterdir()):
            raise ToolYuklemeHatasi(
                f"{klasor}: fixtures/ boş veya yok — fixture'sız tool kabul edilmez"
            )

        modul_adi = f"app.tools.{klasor.name}.adapter"
        yukleyici = importlib.util.spec_from_file_location(modul_adi, adapter_py)
        if yukleyici is None or yukleyici.loader is None:
            raise ToolYuklemeHatasi(f"{adapter_py}: modül yükleyicisi kurulamadı")
        modul = importlib.util.module_from_spec(yukleyici)
        try:
            sys.modules[modul_adi] = modul
            yukleyici.loader.exec_module(modul)
        except Exception as e:
            sys.modules.pop(modul_adi, None)
            raise ToolYuklemeHatasi(f"{adapter_py}: import edilemedi: {e}") from e

        adaylar = [
            obj
            for ad in dir(modul)
            if not ad.startswith("_")
            for obj in [getattr(modul, ad)]
            if isinstance(obj, type) and isinstance(getattr(obj, "spec", None), ToolSpec)
        ]
        if not adaylar:
            raise ToolYuklemeHatasi(
                f"{adapter_py}: `spec: ToolSpec` taşıyan sınıf bulunamadı"
            )
        if len(adaylar) > 1:
            raise ToolYuklemeHatasi(
                f"{adapter_py}: birden fazla adapter sınıfı: "
                f"{[c.__name__ for c in adaylar]}"
            )

        try:
            adapter = adaylar[0]()
        except Exception as e:
            raise ToolYuklemeHatasi(
                f"{adapter_py}: {adaylar[0].__name__}() örneklenemedi: {e}"
            ) from e

        ToolRegistry._tutarlilik_denetle(manifest, veri, adapter.spec)
        return adapter

    @staticmethod
    def _tutarlilik_denetle(
        manifest: Path, veri: dict[str, Any], spec: ToolSpec
    ) -> None:
        """Manifest ile ToolSpec aynı şeyi söylemeli."""
        beklenen: list[tuple[str, Any, Any]] = [
            ("name", str(veri["name"]), spec.name),
            ("version", str(veri["version"]), spec.version),
            ("passivity", Passivity(str(veri["passivity"])), spec.passivity),
            (
                "kabul_eder",
                frozenset(EntityType(str(t).lower()) for t in veri["kabul_eder"]),
                spec.kabul_eder,
            ),
            (
                "uretir",
                frozenset(EntityType(str(t).lower()) for t in veri["uretir"]),
                spec.uretir,
            ),
        ]
        for alan, m_deger, s_deger in beklenen:
            if m_deger != s_deger:
                raise ToolYuklemeHatasi(
                    f"{manifest}: manifest ile ToolSpec uyuşmuyor — "
                    f"{alan}: manifest={m_deger!r}, spec={s_deger!r}"
                )

    def kayit(self, adapter: ToolAdapter) -> None:
        """Adapter'ı elle kaydeder (test ve `calistirma: python` tool'lar için)."""
        self._adapters[adapter.spec.name] = adapter

    # -- sorgular ----------------------------------------------------------- #

    def get(self, ad: str) -> ToolAdapter | None:
        return self._adapters.get(ad)

    def hepsi(self) -> list[ToolAdapter]:
        return list(self._adapters.values())

    def uretenler(self, tip: EntityType) -> list[ToolAdapter]:
        """Bu tipte varlık üreten etkin tool'lar."""
        return [
            a for a in self._adapters.values() if a.spec.etkin and tip in a.spec.uretir
        ]

    def tuketenler(self, tip: EntityType) -> list[ToolAdapter]:
        """Bu tipte varlığı girdi olarak kabul eden etkin tool'lar.

        ---------------------------------------------------------------------
        ZİNCİRLEMENİN KALBİ.
        ---------------------------------------------------------------------
        Yeni bir varlık oluştuğunda sıradaki işler BURADAN türetilir:
        `subfinder` SUBDOMAIN üretir → `tuketenler(SUBDOMAIN)` çağrılır →
        `dns-resolver` döner → iş kuyruğa girer.

        Elle "şundan sonra bunu çalıştır" tanımı yazılmaz; yeni tool eklendiğinde
        yetenek grafiğine kendiliğinden dahil olur.
        """
        return [
            a
            for a in self._adapters.values()
            if a.spec.etkin and tip in a.spec.kabul_eder
        ]

    def __len__(self) -> int:
        return len(self._adapters)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ToolRegistry {len(self._adapters)} tool: {sorted(self._adapters)}>"
