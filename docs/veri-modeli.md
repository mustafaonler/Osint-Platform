# Veri Modeli ve Tool Sözleşmesi

**Sürüm:** 1.0.1
**Bağlı doküman:** `docs/kapsam.md` v1.1
**Hedef:** PostgreSQL 16, Python 3.12, SQLAlchemy 2.x

> **v1.0.1 düzeltmesi:** Bölüm 3.1 ve 3.10'da `şirket.com.tr` için beklenen punycode
> değeri `xn--irket-bua.com.tr` yazıyordu; doğrusu **`xn--irket-idb.com.tr`**'dir
> (`"şirket".encode("idna")` → `b"xn--irket-idb"`). Testler doğru değerle yazılmıştır.

---

## 0. Modelin Temel Kavrayışı

Sistem **tool çıktısı saklamaz**. Üç ayrı katman vardır ve karıştırılmaları en yaygın mimari hatadır:

| Katman | Soru | Tablo |
|--------|------|-------|
| **Varlık (entity)** | "Bu araştırmada hangi şeyler var?" | `entity` — tekil |
| **Gözlem (observation)** | "Bunu kim, ne zaman, nasıl gördü?" | `observation` — çoğul |
| **Değerlendirme (assessment)** | "Bu ne kadar önemli?" | `assessment` — türetilmiş |

Aynı IP'yi 3 tool bulduysa: **1 entity, 3 observation.** AI skorladıysa: **+1 assessment.** Entity satırı asla tool'a özgü bilgi taşımaz.

---

## 1. Enum Tanımları

Veritabanında native PostgreSQL enum yerine `TEXT + CHECK` kullanılır — enum'a yeni değer eklemek migration gerektirir ve tool ekledikçe bu sık olacaktır.

```python
class EntityType(StrEnum):
    DOMAIN    = "domain"
    SUBDOMAIN = "subdomain"
    IP        = "ip"
    NETBLOCK  = "netblock"
    ASN       = "asn"
    EMAIL     = "email"
    SERVICE   = "service"
    CERT      = "cert"
    ORG       = "org"
    TECH      = "tech"

class RelationType(StrEnum):
    SUBDOMAIN_OF  = "subdomain_of"    # sub → domain
    RESOLVES_TO   = "resolves_to"     # domain/sub → ip
    MX_FOR        = "mx_for"          # sub → domain
    NS_FOR        = "ns_for"          # sub → domain
    CERT_FOR      = "cert_for"        # cert → domain/sub
    IN_NETBLOCK   = "in_netblock"     # ip → netblock
    ANNOUNCED_BY  = "announced_by"    # netblock → asn
    OWNED_BY      = "owned_by"        # netblock/domain → org
    RUNS_ON       = "runs_on"         # service → ip
    USES_TECH     = "uses_tech"       # sub/service → tech
    EMAIL_AT      = "email_at"        # email → domain

class JobStatus(StrEnum):
    QUEUED    = "queued"
    RUNNING   = "running"
    SUCCESS   = "success"
    FAILED    = "failed"
    TIMEOUT   = "timeout"
    SKIPPED   = "skipped"        # kota/limit/yetki nedeniyle atlandı
    CANCELLED = "cancelled"

class Passivity(StrEnum):
    P0 = "P0"   # hedefe hiç dokunulmaz
    P1 = "P1"   # ortak altyapı
    P2 = "P2"   # hedefe normal kullanıcı düzeyinde
    A  = "A"    # aktif — v1 kapsam dışı
```

---

## 2. Tablo Şemaları

### 2.1 `investigation`

```sql
CREATE TABLE investigation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ad              TEXT NOT NULL,
    kok_hedef       TEXT NOT NULL,              -- normalize edilmiş kök domain
    kapsam_notu     TEXT,
    yetki_onayi     BOOLEAN NOT NULL DEFAULT FALSE,
    yetki_notu      TEXT,                       -- kim, ne zaman, hangi belgeye dayanarak
    olusturan       TEXT NOT NULL,
    durum           TEXT NOT NULL DEFAULT 'active'
                    CHECK (durum IN ('active','archived')),
    olusturma       TIMESTAMPTZ NOT NULL DEFAULT now(),
    guncelleme      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_investigation_durum ON investigation (durum, olusturma DESC);
```

> `yetki_onayi` FALSE ise runner, P2 ve A seviyesindeki hiçbir modülü çalıştırmaz. Bu kontrol **runner'da** yapılır, arayüzde değil — arayüz kontrolü atlanabilir.

### 2.2 `entity`

```sql
CREATE TABLE entity (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id  UUID NOT NULL REFERENCES investigation(id) ON DELETE CASCADE,
    tip               TEXT NOT NULL,
    deger_norm        TEXT NOT NULL,            -- eşleştirme anahtarı
    deger_ham         TEXT NOT NULL,            -- ilk görülen orijinal hali
    nitelikler        JSONB NOT NULL DEFAULT '{}'::jsonb,
    ilk_gorulme       TIMESTAMPTZ NOT NULL DEFAULT now(),
    son_gorulme       TIMESTAMPTZ NOT NULL DEFAULT now(),
    gozlem_sayisi     INT NOT NULL DEFAULT 0,   -- denormalize, sıralama için

    CONSTRAINT uq_entity UNIQUE (investigation_id, tip, deger_norm)
);

CREATE INDEX ix_entity_inv_tip     ON entity (investigation_id, tip);
CREATE INDEX ix_entity_son_gorulme ON entity (investigation_id, son_gorulme DESC);
CREATE INDEX ix_entity_nitelikler  ON entity USING GIN (nitelikler);

-- Arayüzdeki serbest arama için (pg_trgm eklentisi gerekir)
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX ix_entity_arama ON entity USING GIN (deger_norm gin_trgm_ops);
```

**`uq_entity` bu şemanın kalbidir.** Dedup, uygulama katmanında `if exists` sorgusuyla değil, veritabanı kısıtıyla çözülür — paralel worker'lar aynı anda aynı varlığı yazmaya çalıştığında yalnızca kısıt doğru davranır.

**`nitelikler` JSONB'de ne durur:** tipe özgü, aramada kullanılmayan alanlar. Örnek:
- IP → `{"asn": 13335, "ulke": "US", "ptr": "..."}`
- CERT → `{"issuer": "...", "not_after": "...", "sans": [...]}`
- SERVICE → `{"port": 443, "proto": "tcp", "banner": "..."}`

Bir alan sık filtreleniyorsa JSONB'den çıkarılıp kolon yapılır. Başlangıçta JSONB, ihtiyaç netleşince kolon.

### 2.3 `observation`

```sql
CREATE TABLE observation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id       UUID NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
    job_id          UUID NOT NULL REFERENCES job(id) ON DELETE CASCADE,
    tool            TEXT NOT NULL,
    tool_version    TEXT NOT NULL,
    ham_cikti_ref   TEXT NOT NULL,              -- /data/raw/{job_id}/output.json
    ham_cikti_yol   TEXT,                       -- JSONPath: dosya içinde nerede
    guven           SMALLINT NOT NULL DEFAULT 50 CHECK (guven BETWEEN 0 AND 100),
    veri            JSONB NOT NULL DEFAULT '{}'::jsonb,
    zaman           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_obs_entity ON observation (entity_id, zaman DESC);
CREATE INDEX ix_obs_job    ON observation (job_id);
CREATE INDEX ix_obs_tool   ON observation (tool, zaman DESC);
```

**`ham_cikti_ref` + `ham_cikti_yol` ikilisi, İlke 2'nin (her bulgu izlenebilir) teknik karşılığıdır.** Arayüzde bir varlığa tıklandığında bu iki alan sayesinde "subfinder'ın çıktısının 47. satırı" gösterilebilir.

**`guven` skoru kaynağa göre sabit atanır:** CT log / RDAP gibi otoriter kaynaklar 90, API tabanlı indeksler 70, scraping/tahmin tabanlı çıktılar 40.

### 2.4 `relationship`

```sql
CREATE TABLE relationship (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id   UUID NOT NULL REFERENCES investigation(id) ON DELETE CASCADE,
    kaynak_entity_id   UUID NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
    hedef_entity_id    UUID NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
    tip                TEXT NOT NULL,
    ilk_gorulme        TIMESTAMPTZ NOT NULL DEFAULT now(),
    son_gorulme        TIMESTAMPTZ NOT NULL DEFAULT now(),
    nitelikler         JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT uq_rel UNIQUE (kaynak_entity_id, hedef_entity_id, tip),
    CONSTRAINT ck_rel_self CHECK (kaynak_entity_id <> hedef_entity_id)
);

CREATE INDEX ix_rel_kaynak ON relationship (kaynak_entity_id, tip);
CREATE INDEX ix_rel_hedef  ON relationship (hedef_entity_id, tip);
CREATE INDEX ix_rel_inv    ON relationship (investigation_id);
```

İlişkiler **yönlüdür**. `resolves_to` her zaman domain→IP yönünde yazılır; ters yön sorgusu `ix_rel_hedef` indeksiyle karşılanır. Çift yönlü kayıt tutulmaz.

### 2.5 `job`

```sql
CREATE TABLE job (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id  UUID NOT NULL REFERENCES investigation(id) ON DELETE CASCADE,
    tool              TEXT NOT NULL,
    tool_version      TEXT NOT NULL,
    hedef_entity_id   UUID REFERENCES entity(id) ON DELETE SET NULL,
    hedef_deger       TEXT NOT NULL,            -- entity silinse de kalır
    durum             TEXT NOT NULL DEFAULT 'queued',
    parent_job_id     UUID REFERENCES job(id) ON DELETE SET NULL,
    derinlik          SMALLINT NOT NULL DEFAULT 0,
    hata_mesaji       TEXT,
    cikis_kodu        INT,
    baslangic         TIMESTAMPTZ,
    bitis             TIMESTAMPTZ,
    sure_ms           INT,
    olusturma         TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ck_job_durum CHECK (durum IN
        ('queued','running','success','failed','timeout','skipped','cancelled')),
    CONSTRAINT uq_job_tekrar UNIQUE (investigation_id, tool, hedef_deger)
);

CREATE INDEX ix_job_inv_durum ON job (investigation_id, durum);
CREATE INDEX ix_job_kuyruk    ON job (durum, olusturma) WHERE durum = 'queued';
```

**`uq_job_tekrar` sonsuz döngüyü engeller.** Otomatik zincirleme kurulduğunda A→B→A gibi çevrimler kaçınılmazdır; bu kısıt aynı tool'un aynı hedefte ikinci kez kuyruğa girmesini veritabanı seviyesinde imkânsız kılar.

**`derinlik` ikinci güvenliktir:** kök hedef 0, ondan türeyen işler 1, 2... `MAX_DERINLIK = 3` aşılırsa iş `skipped` olur. Tek başına `uq_job_tekrar` yeterli görünür ama bir tool sürekli yeni varlık üretiyorsa (örneğin geniş bir netblock) derinlik sınırı tarama patlamasını durdurur.

### 2.6 `assessment`

```sql
CREATE TABLE assessment (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id        UUID NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
    skor             SMALLINT NOT NULL CHECK (skor BETWEEN 0 AND 100),
    gerekce          TEXT NOT NULL,
    etiketler        TEXT[] NOT NULL DEFAULT '{}',
    model            TEXT NOT NULL,
    prompt_versiyon  TEXT NOT NULL,
    girdi_hash       TEXT NOT NULL,             -- aynı girdi + aynı prompt = tekrar çağırma
    zaman            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_assess_entity ON assessment (entity_id, zaman DESC);
CREATE INDEX ix_assess_skor   ON assessment (skor DESC, zaman DESC);
```

**Assessment kayıtları asla güncellenmez, yalnızca eklenir.** Prompt değiştiğinde eski skorlar durur; "eski model neden böyle demişti" sorusu cevaplanabilir kalır. Güncel skor şöyle alınır:

```sql
SELECT DISTINCT ON (entity_id) *
FROM assessment
WHERE entity_id = ANY($1)
ORDER BY entity_id, zaman DESC;
```

`girdi_hash` sayesinde aynı veri aynı prompt'la ikinci kez modele gönderilmez — Gemini kotasını korur.

### 2.7 `hypothesis` (AI korelasyon çıktısı)

```sql
CREATE TABLE hypothesis (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id  UUID NOT NULL REFERENCES investigation(id) ON DELETE CASCADE,
    baslik            TEXT NOT NULL,
    aciklama          TEXT NOT NULL,
    guven             SMALLINT NOT NULL CHECK (guven BETWEEN 0 AND 100),
    entity_ids        UUID[] NOT NULL,          -- dayandığı varlıklar
    model             TEXT NOT NULL,
    prompt_versiyon   TEXT NOT NULL,
    analist_durumu    TEXT NOT NULL DEFAULT 'beklemede'
                      CHECK (analist_durumu IN ('beklemede','dogrulandi','reddedildi')),
    zaman             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_hyp_inv ON hypothesis (investigation_id, guven DESC);
```

`analist_durumu` alanı, AI çıktısını insan onayına bağlar. Rapora yalnızca `dogrulandi` olanlar otomatik girer; diğerleri "AI hipotezi" başlığı altında ayrı listelenir.

---

## 3. Normalizasyon Kuralları

**Altın kural: normalizasyon yazma anında yapılır, sorgu anında değil.** `deger_norm` üretimi saf ve deterministik bir fonksiyondur; aynı girdi her zaman aynı çıktıyı verir.

```python
def normalize(tip: EntityType, ham: str) -> str:
    """Saf fonksiyon. Ağ erişimi yok, DB erişimi yok, rastgelelik yok."""
```

### 3.1 DOMAIN / SUBDOMAIN

| Adım | Örnek |
|------|-------|
| Boşluk kırp | `" firma.com "` → `firma.com` |
| Şema ve yol at | `https://firma.com/a?b=1` → `firma.com` |
| Port at | `firma.com:443` → `firma.com` |
| Kullanıcı bilgisi at | `user@firma.com` → `firma.com` |
| Sondaki nokta at | `firma.com.` → `firma.com` |
| Küçült | `WWW.Firma.COM` → `www.firma.com` |
| IDN → punycode | `şirket.com.tr` → `xn--irket-idb.com.tr` |
| Wildcard temizle | `*.firma.com` → `firma.com` (+ `nitelikler.wildcard = true`) |

**`www` ASLA atılmaz.** `www.firma.com` ayrı bir subdomain'dir ve farklı bir sunucuya çözülebilir. Bunu atmak veri kaybıdır.

**DOMAIN mi SUBDOMAIN mi:** Public Suffix List ile karar verilir (`tldextract` kütüphanesi). `firma.com.tr` → DOMAIN (çünkü `com.tr` bir public suffix), `mail.firma.com.tr` → SUBDOMAIN. Elle nokta sayarak karar verilmez — `.co.uk`, `.com.tr`, `.gov.tr` gibi durumlarda yanlış sonuç verir.

### 3.2 IP

```python
import ipaddress
addr = ipaddress.ip_address(ham.strip())
deger_norm = str(addr)   # IPv6 sıkıştırılmış küçük harf kanonik forma döner
```

`2001:0DB8:0000::1` ve `2001:db8::1` aynı adrestir; `ipaddress` bunu otomatik çözer. Özel/ayrılmış aralıklar **reddedilmez**, `nitelikler.ozel = true` ile işaretlenir — iç ağ sızıntısı tespiti için değerlidir.

### 3.3 NETBLOCK

```python
net = ipaddress.ip_network(ham, strict=False)
deger_norm = str(net)    # 10.0.0.5/24 → 10.0.0.0/24
```

`strict=False` şart: tool'lar sık sık host bitleri set edilmiş CIDR döndürür.

### 3.4 EMAIL

| Adım | Örnek |
|------|-------|
| Domain kısmını küçült + punycode | `A@Firma.COM` → `A@firma.com` |
| Local kısmı küçült | `Ahmet@firma.com` → `ahmet@firma.com` |
| Plus-tag ayır | `ahmet+test@firma.com` → `ahmet@firma.com` |

Plus-tag ve orijinal büyük/küçük hali `deger_ham`'da korunur. RFC'ye göre local kısım teorik olarak büyük/küçük harfe duyarlıdır; pratikte hiçbir sağlayıcı böyle davranmaz, küçültmek doğru tercihtir.

### 3.5 CERT

```python
deger_norm = sha256_fingerprint.lower()   # 64 karakter hex
```

Sertifikanın kimliği parmak izidir. CN, SAN listesi, issuer, geçerlilik tarihleri `nitelikler`'de durur. SAN'lardan çıkan her alan adı **ayrı SUBDOMAIN entity'si** olarak `cert_for` ilişkisiyle bağlanır.

### 3.6 ASN

```python
deger_norm = str(int(ham.upper().removeprefix("AS").strip()))   # "AS13335" → "13335"
```

### 3.7 SERVICE

```python
deger_norm = f"{ip}:{port}/{proto.lower()}"   # "1.2.3.4:443/tcp"
```

### 3.8 ORG — en kirli tip

Kurum adları serbest metindir ve tam tekilleştirme mümkün değildir.

| Adım | Örnek |
|------|-------|
| Küçült, boşlukları tekle | `"ABC   Teknoloji  A.Ş."` → `abc teknoloji a.ş.` |
| Hukuki ek at | `a.ş.`, `ltd. şti.`, `inc.`, `llc`, `gmbh`, `b.v.`, `co.` |
| Noktalama at | `abc teknoloji` |

Kalan risk kabul edilir: `ABC Teknoloji` ile `ABC Teknoloji ve Danışmanlık` ayrı varlık olarak kalır. **v1'de bu kabul edilmiş bir sınırlamadır**; bulanık eşleştirme (Levenshtein / trigram) v2 işidir ve gereksiz birleştirme, ayrı kalmaktan daha zararlıdır.

### 3.9 TECH

```python
deger_norm = f"{vendor}:{product}:{version or '*'}".lower()   # "nginx:nginx:1.24.0"
```

### 3.10 Zorunlu testler

Her normalizasyon kuralı için `tests/test_normalize.py` altında parametrik test bulunur. Bu dosya projedeki **en yüksek öncelikli test setidir** — buradaki bir hata tüm veritabanını sessizce bozar.

```python
@pytest.mark.parametrize("tip,ham,beklenen", [
    (EntityType.SUBDOMAIN, "WWW.Firma.COM.",        "www.firma.com"),
    (EntityType.SUBDOMAIN, "https://a.firma.com:8443/x", "a.firma.com"),
    (EntityType.DOMAIN,    "şirket.com.tr",          "xn--irket-idb.com.tr"),
    (EntityType.IP,        "2001:0DB8:0000::1",      "2001:db8::1"),
    (EntityType.NETBLOCK,  "10.0.0.5/24",            "10.0.0.0/24"),
    (EntityType.EMAIL,     "Ahmet+spam@Firma.COM",   "ahmet@firma.com"),
    (EntityType.ASN,       "AS13335",                "13335"),
])
def test_normalize(tip, ham, beklenen):
    assert normalize(tip, ham) == beklenen
```

---

## 4. Tool Sözleşmesi

### 4.1 Veri sınıfları

```python
from dataclasses import dataclass, field
from typing import Protocol, Any

@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    passivity: Passivity
    kabul_eder: frozenset[EntityType]
    uretir: frozenset[EntityType]
    calistirma: str                      # "api" | "docker" | "python"
    image: str | None = None
    auth_env: tuple[str, ...] = ()
    timeout_sn: int = 60
    dakikalik_istek: int | None = None
    aylik_kota: int | None = None
    varsayilan_guven: int = 50
    etkin: bool = True


@dataclass(frozen=True)
class RawResult:
    """Tool'un işlenmemiş çıktısı."""
    icerik: bytes
    format: str                          # "json" | "text" | "xml"
    cikis_kodu: int = 0
    sure_ms: int = 0
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Observation:
    """Parser çıktısı. DİKKAT: entity_id YOK — henüz varlık oluşmamış olabilir."""
    tip: EntityType
    deger_ham: str
    nitelikler: dict[str, Any] = field(default_factory=dict)
    guven: int | None = None             # None → spec.varsayilan_guven
    kaynak_yol: str | None = None        # ham çıktı içindeki JSONPath
    iliskiler: tuple["ObservedRelation", ...] = ()


@dataclass(frozen=True)
class ObservedRelation:
    """Bu gözlemin başka bir varlıkla ilişkisi — değerlerle ifade edilir, ID ile değil."""
    tip: RelationType
    hedef_tip: EntityType
    hedef_deger: str
    yon: str = "giden"                   # "giden" | "gelen"
```

**En önemli tasarım kararı burada:** `Observation` nesnesi `entity_id` taşımaz. Parser, veritabanının varlığından habersizdir. ID çözümlemesi ingest katmanının işidir. Bu ayrım sayesinde parser saf fonksiyon kalır ve fixture'la test edilebilir.

### 4.2 Adapter protokolü

```python
class ToolAdapter(Protocol):
    spec: ToolSpec

    def calistir(self, hedef: str, cfg: "ToolConfig") -> RawResult:
        """Tool'u çalıştırır, ham çıktıyı döndürür.
        Diske yazma, timeout, retry: RUNNER'ın sorumluluğudur — burada YAPILMAZ."""
        ...

    def parse(self, ham: RawResult) -> list[Observation]:
        """Ham çıktı → gözlemler.
        SAF FONKSİYON: ağ yok, DB yok, dosya yok, saat okuma yok, rastgelelik yok.
        Bozuk/eksik çıktıda istisna fırlatmaz, elden geldiğince ayrıştırır."""
        ...

    def saglik(self) -> bool:
        """Bağımlılık ve kimlik doğrulama kontrolü. Açılışta çalışır."""
        return True
```

### 4.3 Örnek: crt.sh adapter

```python
class CrtShAdapter:
    spec = ToolSpec(
        name="crtsh",
        version="1.0",
        passivity=Passivity.P0,
        kabul_eder=frozenset({EntityType.DOMAIN}),
        uretir=frozenset({EntityType.SUBDOMAIN, EntityType.CERT}),
        calistirma="api",
        timeout_sn=45,
        dakikalik_istek=5,
        varsayilan_guven=90,          # CT logları otoriter kaynaktır
    )

    def calistir(self, hedef: str, cfg: ToolConfig) -> RawResult:
        r = httpx.get(
            "https://crt.sh/",
            params={"q": f"%.{hedef}", "output": "json"},
            timeout=self.spec.timeout_sn,
        )
        return RawResult(icerik=r.content, format="json", cikis_kodu=0)

    def parse(self, ham: RawResult) -> list[Observation]:
        try:
            kayitlar = json.loads(ham.icerik)
        except json.JSONDecodeError:
            return []

        cikti: list[Observation] = []
        for i, k in enumerate(kayitlar):
            fp = k.get("serial_number", "")
            adlar = {a.strip() for a in k.get("name_value", "").split("\n") if a.strip()}

            for ad in adlar:
                cikti.append(Observation(
                    tip=EntityType.SUBDOMAIN,
                    deger_ham=ad,
                    kaynak_yol=f"$[{i}].name_value",
                    iliskiler=(ObservedRelation(
                        tip=RelationType.CERT_FOR,
                        hedef_tip=EntityType.CERT,
                        hedef_deger=fp,
                        yon="gelen",
                    ),) if fp else (),
                ))

            if fp:
                cikti.append(Observation(
                    tip=EntityType.CERT,
                    deger_ham=fp,
                    kaynak_yol=f"$[{i}]",
                    nitelikler={
                        "issuer": k.get("issuer_name"),
                        "not_before": k.get("not_before"),
                        "not_after": k.get("not_after"),
                    },
                ))
        return cikti
```

### 4.4 Registry ve yetenek grafiği

```python
class ToolRegistry:
    def __init__(self, kok: Path):
        self._adapters: dict[str, ToolAdapter] = {}
        self._kesfet(kok)

    def _kesfet(self, kok: Path) -> None:
        """app/tools/*/manifest.yaml dosyalarını okur, adapter'ları yükler."""

    def uretenler(self, tip: EntityType) -> list[ToolAdapter]:
        """Bu tipte varlık üreten etkin tool'lar."""
        return [a for a in self._adapters.values()
                if a.spec.etkin and tip in a.spec.uretir]

    def tuketenler(self, tip: EntityType) -> list[ToolAdapter]:
        """Bu tipte varlığı girdi olarak kabul eden etkin tool'lar.
        ZİNCİRLEMENİN KALBİ: yeni varlık oluşunca buradan sıradaki işler türetilir."""
        return [a for a in self._adapters.values()
                if a.spec.etkin and tip in a.spec.kabul_eder]
```

Zincirleme kuralı hiçbir yerde elle yazılmaz. `subfinder` SUBDOMAIN üretir → `tuketenler(SUBDOMAIN)` çağrılır → `dns-resolver` döner → iş kuyruğa girer. Yeni tool eklendiğinde grafiğe kendiliğinden dahil olur.

### 4.5 Ingest hattı

Parser çıktısını veritabanına yazan tek yer. Tüm tool'lar bu hattı paylaşır.

```python
def ingest(job: Job, gozlemler: list[Observation], session: Session) -> None:
    for g in gozlemler:
        # 1) Normalize et
        norm = normalize(g.tip, g.deger_ham)
        if not gecerli_mi(g.tip, norm):
            continue                                    # bozuk kayıt sessizce atlanır

        # 2) Varlığı upsert et (yarış koşulunu DB kısıtı çözer)
        entity = upsert_entity(session, job.investigation_id, g.tip, norm, g.deger_ham)

        # 3) Gözlemi yaz
        session.add(Observation_(
            entity_id=entity.id,
            job_id=job.id,
            tool=job.tool,
            tool_version=job.tool_version,
            ham_cikti_ref=job.ham_cikti_ref,
            ham_cikti_yol=g.kaynak_yol,
            guven=g.guven or spec.varsayilan_guven,
            veri=g.nitelikler,
        ))

        # 4) İlişkileri çöz — hedef varlık yoksa oluştur
        for il in g.iliskiler:
            hedef_norm = normalize(il.hedef_tip, il.hedef_deger)
            hedef = upsert_entity(session, job.investigation_id,
                                  il.hedef_tip, hedef_norm, il.hedef_deger)
            upsert_relationship(session, entity, hedef, il)

        # 5) Zincirleme işleri kuyruğa al
        if job.derinlik < MAX_DERINLIK:
            for adapter in registry.tuketenler(g.tip):
                kuyruga_al(job.investigation_id, adapter, entity,
                           parent=job, derinlik=job.derinlik + 1)
```

`upsert_entity` implementasyonu:

```sql
INSERT INTO entity (investigation_id, tip, deger_norm, deger_ham)
VALUES ($1, $2, $3, $4)
ON CONFLICT (investigation_id, tip, deger_norm)
DO UPDATE SET son_gorulme   = now(),
              gozlem_sayisi = entity.gozlem_sayisi + 1
RETURNING id;
```

Tek sorguda hem ekleme hem güncelleme; `SELECT` sonra `INSERT` yapılmaz. Paralel worker'larda tek doğru yöntem budur.

---

## 5. Sık Sorgular

```sql
-- Araştırmadaki tüm varlıklar + güncel AI skoru + kaynak sayısı
SELECT e.tip, e.deger_ham, e.gozlem_sayisi, a.skor, a.gerekce
FROM entity e
LEFT JOIN LATERAL (
    SELECT skor, gerekce FROM assessment
    WHERE entity_id = e.id ORDER BY zaman DESC LIMIT 1
) a ON TRUE
WHERE e.investigation_id = $1
ORDER BY a.skor DESC NULLS LAST, e.gozlem_sayisi DESC;

-- Yalnızca tek kaynaktan gelen varlıklar (doğrulanmamış, dikkat gerektirir)
SELECT * FROM entity
WHERE investigation_id = $1 AND gozlem_sayisi = 1;

-- Bir varlığın kanıt zinciri
SELECT o.tool, o.zaman, o.guven, o.ham_cikti_ref, o.ham_cikti_yol
FROM observation o WHERE o.entity_id = $1 ORDER BY o.zaman;
```

---

## 6. Migration Politikası

- Araç: **Alembic**. Şema değişikliği elle SQL ile yapılmaz.
- Yeni `EntityType` / `RelationType` eklemek migration **gerektirmez** (TEXT + uygulama katmanı doğrulaması).
- `nitelikler` JSONB alanına yeni anahtar eklemek migration gerektirmez.
- Bir JSONB anahtarı kolona terfi ettiğinde migration + geri doldurma scripti yazılır.
- Her migration geri alınabilir (`downgrade` dolu) olmalıdır.

---

## 7. Hafta 1 Kabul Kriterleri

- [ ] Tüm tablolar Alembic migration'ı ile oluşuyor, `upgrade`/`downgrade` çalışıyor
- [ ] `normalize()` fonksiyonu 10 varlık tipinin tamamını kapsıyor
- [ ] `tests/test_normalize.py` yeşil, kenar durumlar (IDN, IPv6, CIDR, plus-tag) dahil
- [ ] `upsert_entity` paralel çağrıda tek satır üretiyor (eşzamanlılık testi yazılmış)
- [ ] `ToolSpec`, `Observation`, `ToolAdapter` tanımları `app/tools/_base.py`'de hazır
- [ ] `ToolRegistry` boş klasörle sorunsuz açılıyor, `tuketenler()` boş liste dönüyor
