# AGENTS.md — bu depoda çalışma kılavuzu

> Bu dosya deponun **tek doğruluk kaynağıdır**. Kod yazmadan önce tamamını oku.
> Bağlayıcı spesifikasyon: [docs/kapsam.md](docs/kapsam.md) ve
> [docs/veri-modeli.md](docs/veri-modeli.md). Bu ikisiyle çelişen kod hatalıdır.

---

## 1. Proje nedir

Ekip içi (kapalı, halka açılmayan) **OSINT orkestrasyon platformu**. Bir kök
hedef (domain) verilir; sistem bunu birbirine zincirlenmiş pasif keşif
tool'larından geçirir, çıkan varlıkları **normalize eder, tekilleştirir,
ilişkilendirir** ve analiste önceliklendirilmiş bir liste sunar.

**Değer toplama katmanında DEĞİLDİR.** Yeni bir tarama tekniği geliştirmek amaç
değildir. Değer; normalizasyon + korelasyon + önceliklendirmededir. subfinder
zaten var; olmayan şey, yedi tool'un çıktısını tek ve güvenilir bir varlık
grafiğine indirgeyen katmandır.

Yığın: Python 3.12 · FastAPI · PostgreSQL 16 · Celery/Redis · Jinja2 + HTMX ·
Gemini API (henüz yazılmadı) · docker-compose.

---

## 2. Değişmez ilkeler (tartışmaya kapalı)

Her teknik kararda bunlara başvurulur. Bir öneri bunlardan biriyle çelişiyorsa
öneri yanlıştır, ilke değil.

1. **AI veri silmez, sadece skorlar.** Yanlış negatif görünmezdir. Filtre yok,
   sıralama var. **Bu kural ön elemeye de aynen uygulanır** — hiçbir varlık
   silinmez, yalnızca sıralanır ve gruplanır; analist istediğinde tam listeye
   erişebilmelidir.
2. **Her bulgu ham çıktısına kadar izlenebilir.** Arayüzdeki her satırın yanında
   "kaynağı gör". Teknik karşılığı: `observation.ham_cikti_ref` + `ham_cikti_yol`.
3. **Tool çıktısı güvenilmeyen veridir.** Hedefin kontrolündeki metin (özellikle
   Shodan banner'ları, sertifika CN'leri, WHOIS serbest metin alanları) modele
   giriyorsa prompt injection savunması zorunludur.
4. **v1 tamamen pasiftir (P0/P1).** Hedefe doğrudan paket gönderen hiçbir modül
   varsayılan açık değildir.
5. **Her tool kendi container'ında izole çalışır.** Bozuk bir tool sistemi düşürmez.
6. **Tool eklemek birinci sınıf işlemdir.** Yeni tool = 1 manifest + 1 adapter +
   1 fixture. Çekirdek koda dokunulmaz. (Ölçüldü — bkz. Bölüm 6.)
7. **Yetenek bazlı düşünülür, araç bazlı değil.** Soru "dig ekleyeyim mi" değil,
   "DNS yeteneğim yeterli mi"dir.

Veri modelinin iki ek değişmezi:

8. **Normalizasyon yazma anında yapılır, sorgu anında değil.** `deger_norm`
   üretimi saf ve deterministik bir fonksiyondur ([app/normalize.py](app/normalize.py)).
   Dedup'ı sorgu anında çözmeye çalışmak mimari hatadır.
9. **Üç katman karıştırılmaz:** `entity` (ne var) / `observation` (kim gördü) /
   `assessment` (ne kadar önemli). Aynı IP'yi 3 tool bulduysa **1 entity,
   3 observation** olur.

---

## 3. Mimari — veri akışı

```
Arayüz (POST /investigations/{id}/run)
   |
   +- upsert_entity(kök hedef, gozlem=False)   <- tool görmedi, sayaç artmaz
   +- kuyruga_al(...)                          <- job satırı yazar
   +- worker.kuyruga_gonder(job_id)            <- Celery'ye görev
        |
        v
   Celery: osint.job_calistir
        |
        +- 1. ToolRunner.calistir()   <- spec.calistirma'ya bakıp dağıtır
        |      +- ContainerRunner     (docker: subfinder, theharvester)
        |      +- ApiRunner           (api: crtsh, dns-resolver, whois-rdap,
        |                              asn-bgp, shodan-lookup)
        |      · timeout, retry/backoff, rate limit, yetki kontrolü,
        |        ham çıktının diske yazımı — HEPSİ RUNNER'IN İŞİ
        |
        +- 2. adapter.parse(RawResult) -> list[Observation]   <- SAF fonksiyon
        |
        +- 3. ingest(session, job, gozlemler, ...)
               +- upsert_entity     (ON CONFLICT, dedup)
               +- upsert_relationship
               +- kuyruga_al        <- zincirleme: yetenek grafiğinden türer
                    |
                    +- commit SONRASI kuyruga_gonder(jid)   <- Bölüm 7'deki hata
```

Zincir dört katmanlı:
`DOMAIN -> SUBDOMAIN -> IP -> {ASN -> NETBLOCK, SERVICE, ORG}`

**Zincirleme kuralı elle yazılmaz.** Hangi tool'un hangi işi doğuracağı,
manifest'lerdeki `kabul_eder` / `uretir` alanlarından `ToolRegistry.tuketenler()`
ile türetilir. Sonsuz döngüye karşı iki koruma var: `uq_job_tekrar` UNIQUE kısıtı
(aynı tool+hedef ikinci kez kuyruğa girmez) ve `MAX_DERINLIK=3`.

---

## 4. Dosya haritası

### Çekirdek (dokunmadan önce iki kez düşün)

| Dosya | Satır | İçerik |
|---|---|---|
| [app/normalize.py](app/normalize.py) | 552 | `EntityType` (10 tip), `normalize()`, `gecerli_mi()`, `domain_mi()`, `kok_domain()`, `service_parcala()` |
| [app/models.py](app/models.py) | 406 | 7 tablo (SQLAlchemy 2.x) + `JobStatus`, `MAX_DERINLIK` |
| [app/tools/_base.py](app/tools/_base.py) | 520 | Tool sözleşmesi + `ToolRegistry` (manifest keşfi, yetenek grafiği) |
| [app/runner.py](app/runner.py) | 893 | `ContainerRunner`, `ApiRunner`, `ToolRunner`, retry, `HizSinirlayici` |
| [app/ingest.py](app/ingest.py) | 416 | `upsert_entity`, `upsert_relationship`, `kuyruga_al`, `ingest()` |
| [app/worker.py](app/worker.py) | 255 | Celery görevi + `kuyruga_gonder()` |
| [app/main.py](app/main.py) | 258 | FastAPI + Jinja2 + HTMX, 6 rota |
| [app/db.py](app/db.py) | 27 | Oturum fabrikası |

### Tablolar

`investigation` · `entity` · `observation` · `relationship` · `job` ·
`assessment` · `hypothesis`

Kritik kısıtlar:

- `uq_entity (investigation_id, tip, deger_norm)` — dedup'ın temeli
- `uq_job_tekrar (investigation_id, tool, hedef_tip, hedef_deger)` — döngü koruması
- `assessment` **yalnızca eklenir**, güncellenmez; skor geçmişi durur

### Tool'lar (7/7 — v1 çekirdeği tamam)

| Tool | Seviye | Çalıştırma | Girdi -> Çıktı |
|---|---|---|---|
| `subfinder` | P0 | docker | DOMAIN -> SUBDOMAIN |
| `crtsh` | P0 | api | DOMAIN -> SUBDOMAIN, CERT |
| `dns-resolver` | P1 | api | DOMAIN, SUBDOMAIN -> IP, SUBDOMAIN, TECH, ORG |
| `whois-rdap` | P0 | api | DOMAIN, IP, NETBLOCK -> ORG, SUBDOMAIN, NETBLOCK, ASN |
| `asn-bgp` | P0 | api | IP, ASN -> ASN, NETBLOCK, ORG |
| `theharvester` | P0 | docker | DOMAIN -> EMAIL, SUBDOMAIN |
| `shodan-lookup` | P0 | api | IP -> SERVICE, TECH, ORG · **API key ZORUNLU** |

Her tool klasörü: `manifest.yaml` + `adapter.py` + `fixtures/` (gerçek yanıtlar).

---

## 5. Yeni tool ekleme reçetesi

```
app/tools/<yeni_tool>/
├── __init__.py
├── manifest.yaml       # şema: docs/kapsam.md Bölüm 5.2
├── adapter.py          # spec: ToolSpec · calistir() · parse()
└── fixtures/
    └── <ornek>.json    # GERÇEK yanıt, elle uydurulmuş değil
```

`manifest.yaml` ile `adapter.spec` **tutarlı olmak zorundadır**; `ToolRegistry`
uyuşmazlıkta istisna fırlatır (sessizce atlamaz). Fixture'sız tool reddedilir.

`ToolSpec` alanları:

```python
name, version, passivity, kabul_eder, uretir, calistirma,   # zorunlu
image, auth_env, auth_gerekli, timeout_sn, dakikalik_istek,
aylik_kota, varsayilan_guven, etkin, max_deneme, geri_cekilme_sn
```

`parse()` sözleşmesi:

- **Saf**: ağ yok, DB yok, dosya yok, saat okuma yok, rastgelelik yok
- İstisna fırlatmaz
- `list[Observation]` döner; `Observation` **`entity_id` TAŞIMAZ** (bilinçli —
  parser'ı DB'den bağımsız tutar, fixture ile test edilebilir kılar)

`calistir()` sözleşmesi:

- timeout / retry / rate limit / kota / diske yazma **YAPMAZ** — runner'ın işi
- Taşıma hatasında istisna yerine `cikis_kodu=-1` döner, runner retry'a düşer

---

## 6. Şu ana kadar ne yapıldı

### Hafta 1 — veri modeli ve normalizasyon

- `docs/kapsam.md` + `docs/veri-modeli.md` bağlayıcı spesifikasyon olarak yerleşti
- `app/normalize.py`: 10 entity tipi, saf `normalize()`. Çözülen kenar durumlar:
  - PSL (`tldextract`, gömülü snapshot, `suffix_list_urls=()`) — **nokta sayılmaz**
  - `www` asla atılmaz (ayrı subdomain, farklı sunucuya çözülebilir)
  - Punycode **etiket bazında** uygulanır (`_dmarc` tüm adın IDNA'sını bozar)
  - Türkçe `İ`/`I` -> `i`, **`.lower()`'dan ÖNCE** (yoksa birleşen aksan kalır)
  - SERVICE'te IPv6 köşeli parantez **zorunlu** (RFC 3986)
- `app/models.py`: 7 tablo, native enum YOK (`TEXT + CHECK`)
- `app/tools/_base.py`: tool sözleşmesi
- Alembic kurulumu + ilk migration (`alembic.ini`'de parola yok)
- `upsert_entity` / `upsert_relationship` — `ON CONFLICT`, eşzamanlılık testli

### Hafta 2 — dikey dilim

- `app/runner.py`: container izolasyonu — `read_only`, `cap_drop=ALL`,
  `user=1000:1000`, `no-new-privileges`, `mem_limit=512m`, `nano_cpus`, `tmpfs /tmp`
- **Ağ gerilimi çözüldü**: tool'ların internete çıkması gerekir ama db/redis'i
  görmemeleri gerekir. Ayrı bridge **yetmedi** (ölçüldü: tool container'ı
  `172.18.0.3:5432`'ye ulaştı). Çözüm: veri katmanında `internal: true`. Bedeli:
  db host'tan TCP ile erişilemez -> migration ve DB testleri container içinden koşar.
- subfinder adapter'ı, registry manifest okuması, tam ingest hattı
- `app/worker.py` (Celery), `app/main.py` (FastAPI + HTMX), e2e test

### Hafta 3 — eklenti sisteminin sınanması

Hafta 3'ün çıktısı "tool eklendi" değil, **"tool eklemek ucuzladı"**dır ve ölçüldü:

| Tool | Süre | Çekirdek dosya |
|---|---|---|
| `crtsh` | 68 dk | 3 — `ApiRunner` yoktu, CERT kuralı bozuktu |
| `dns-resolver` | 15 dk | 1 satır — `RelationType.CNAME_FOR` |
| `whois-rdap` | 8 dk | **0** |
| `asn-bgp` | 7 dk | **0** |
| `theharvester` | 10 dk | **0** |
| `shodan-lookup` | 8 dk | 2 — `ToolSpec.auth_gerekli` yoktu |

İlk tool'dan sonraki altısının ortalaması **9,6 dakika**; dördü çekirdeğe **hiç
dokunmadı**. Çekirdeğe dokunan iki tool da aynı sınıf boşluğu kapattı: manifest
şemasında TANIMLI olan ama `ToolSpec`'te KARŞILIĞI OLMAYAN alan.

Ayrıca eklendi: retry/backoff (geçici 408/429/502/503/504/−1 vs kalıcı
400/401/403/404/410/422/500), `HizSinirlayici`, `auth_gerekli` (opsiyonel anahtar
-> çalışır, zorunlu anahtar -> `SKIPPED`, asla `FAILED` değil).

### Hafta 4 ADIM 1 — gerçek veriyle gürültü ölçümü (TAMAMLANDI)

Hedef: `iana.org`, yedi tool, tam zincir. **580 varlık, 527 iş, 842 ilişki.**

**Tip dağılımı:** cert 197 (%34) · subdomain 184 (%31,7) · netblock 101 (%17,4) ·
ip 81 (%14) · asn 8 · org 8 · domain 1

**Kaç farklı tool doğruluyor — en önemli sayı:**

| Farklı tool | Varlık | % |
|---|---|---|
| 0 (ilişkiden türedi) | 12 | 2,1 |
| **1** | **410** | **70,7** |
| 2 | 89 | 15,3 |
| 3 | 56 | 9,7 |
| 4 | 13 | 2,2 |

**Tek kaynaklılık tipe göre çok değişiyor** — tasarımı bu belirleyecek:

| Tip | Tek kaynak | Toplam | % |
|---|---|---|---|
| cert | 128 | 197 | **65** |
| ip | 40 | 81 | 49 |
| netblock | 13 | 101 | 13 |
| subdomain | 0 | 184 | **0** |

**Yetim varlık:** 2 / 580 (%0,3). İlişki grafiği neredeyse tamamen bağlı —
"yetimleri ele" stratejisi burada işe yaramaz.

**Bulut/CDN işaretli: 0.** `hedefe_ait_degil`, `saglayici_olabilir`,
`prefiks_sinir_asildi` üçü de sıfır. iana.org kendi altyapısını kullanıyor.
**Bu ölçüm bulut filtresini SINAMADI** — Cloudflare/AWS arkasındaki bir hedefte
tekrarlanmalı.

**ADIM 2 düzeltmesi:** Ön eleme için `observation.veri` de okununca 3 ASN'de
işaret bulundu: prefiks sınırı 3, hedefe ait olmama 2, sağlayıcı olma 1.
Yukarıdaki sıfır sayımı tüm gözlem işaretlerini temsil etmiyor.
580 varlığın grup dağılımı ve doğrulama: [docs/on-eleme.md](docs/on-eleme.md).

**Tool başına üretim:**

| Tool | Gözlem | Tekil varlık | Oran |
|---|---|---|---|
| dns-resolver | 398 | 265 | 1,5 |
| crtsh | 708 | 225 | 3,1 |
| subfinder | 124 | 124 | 1,0 |
| asn-bgp | 825 | 91 | **9,1 — en gürültülü** |
| theharvester | 131 | 69 | 1,9 |
| whois-rdap | 257 | 34 | 7,6 |

**İş durumu:** success 415 · skipped 82 (hepsi shodan, anahtar yok — doğru
davranış) · failed 27 (whois-rdap taşıma hatası) · timeout 3 (dns-resolver)

**Derinlik:** 6 -> 154 -> 277 -> 90, sonra durdu. `MAX_DERINLIK=3` çalışıyor.

**İlişki tipleri:** `cert_for` 322 · `resolves_to` 161 · `subdomain_of` 124 ·
`announced_by` 91 · `in_netblock` 60 · `cname_for` 40 · `owned_by` 32 ·
`mx_for` 8 · `ns_for` 4

**Ölçek uyarısı:** iana.org 580 varlık verdi; `example.com` tek tool'la 17.057
vermişti. Ölçek hedefe göre **30 kat** değişiyor. Ön eleme tasarımı mutlak sayıya
değil, bu oranlara dayanmalıdır.

---

## 7. Ölçüm sırasında bulunan kritik hata (düzeltildi)

**Zincirleme işler hiç gönderilmiyormuş.** `send_task` **yalnızca
`app/main.py`'de** vardı. API derinlik-0 işlerini gönderiyordu, onlar koşuyordu,
`ingest()` derinlik-1 iş *satırlarını* yaratıyordu — ama Celery'ye kimse haber
vermiyordu. 154 iş sonsuza kadar `queued` bekledi. **Otomatik zincirleme
üretimde hiç çalışmamıştı.**

E2E testi bunu kaçırdı çünkü `job_calistir`'ı doğrudan çağırıp yalnızca job
satırının *oluştuğunu* doğruluyordu. Ancak gerçek bir tur bulabilirdi.

Düzeltme: `IngestSonucu.kuyruk_idleri` alanı, `worker.kuyruga_gonder()` ortak
yardımcısı, gönderim **commit'ten sonra** (önce gönderilirse yarış: görev, job
satırı görünür olmadan alınabilir), `main.py` aynı yardımcıyı kullanıyor.
2 regresyon testi eklendi. Düzeltmeden sonra iş sayısı 160 -> 527.

**Ders:** "satır yazıldı" ile "görev gönderildi" iki ayrı olaydır. Yeni bir iş
üretme yolu eklenirse ikisinin de yapıldığından emin ol.

---

## 8. Sırada ne var

### Hafta 4 ADIM 2 — ön eleme kuralları (TAMAMLANDI)

Uygulama: `app/triage.py` (saf kurallar), `app/triage_query.py` (araştırmaya
sınırlı toplu okuma), gerekçeli grup görünümü ve 100 satırlık sayfalama.
Farklı tool sayısı kullanılır; ham gözlem tekrarları sıralamayı şişirmez.
Tüm varlıklar varsayılan görünümde korunur. Eşikler, dayanakları ve sınırlamalar:
[docs/on-eleme.md](docs/on-eleme.md). Testler: `tests/test_triage.py` ve gerçek
PostgreSQL/HTTP için `tests/test_triage_db.py` (api container'ında çalıştırılır).

Bölüm 6'daki ölçüm bu tasarımın girdisidir. **Tahminle başlama, ölçüme bak.**

Ölçümün söyledikleri:

- `gozlem_sayisi` iyi bir sinyal ama **tek başına yetmez**: %70,7 tek kaynaklı.
  Global tek eşik listenin üçte ikisini arkaya atar.
- **Tip bazlı eşik gerekiyor**: subdomain'de tek kaynaklılık %0, cert'te %65.
- Sertifikalar hacmin üçte biri ve analistin en az ilgilendiği tip. Silinmez
  (İlke 1) ama varsayılan görünümde geride olmalı.
- Yetimlik ve bulut işareti bu turda ayırt edici değil — kural olarak dursun,
  ama bu hedefte sinyal üretmiyorlar.

Kısıt: **hiçbir varlık silinmez.** Ön eleme = sıralama + gruplama. Analist
istediğinde tam listeye erişebilmelidir. Ön eleme **deterministik** olacak; LLM
ikinci katmandır, birinci değil.

### Hafta 4 ADIM 3 — varlık ilişkileri arayüzü (TAMAMLANDI)

Varlık detayında gelen/giden ilişkiler kaynak → hedef yönüyle gösterilir.
Komşu varlıkların detaylarına bağlantı, ilişki türünün Türkçe açıklaması ve ham
kodu, ilk/son görülme zamanı, 50 ilişkilik DB sayfalaması vardır. İlişkinin ve
iki ucunun aynı araştırmaya ait olduğu doğrulanır. Aynı komşuyla farklı
ilişkiler ayrı tutulur; bilinmeyen türler ham koduyla görünür.
Uygulama: `app/relationships.py`, `app/templates/entity.html`.
PostgreSQL/HTTP testleri: `tests/test_relationships_db.py`.
Graph görselleştirme **v1'de YOK** (bkz. Bölüm 9).

### Hafta 5 — rapor ve ham çıktı görüntüleme

- **Tamamlandı:** Gözlem kimliği üzerinden ham çıktı önizlemesi (ilk 256 KiB)
  ve özgün dosyanın tamamını indirme. Kanıt zincirindeki bağlantıdan açılır.
  Yalnız ilgili işin arşiv yolu kabul edilir; yol/symlink kaçışı reddedilir.
  Tool içeriği HTML olarak çalıştırılmaz. `app/raw_output.py`.
- **Tamamlandı:** Araştırma sayfasından Markdown raporu indirme. Tüm varlıklar,
  ilişkiler, işler, gözlem referansları, varsa son AI değerlendirmeleri ve
  analist durumuna göre ayrılmış hipotezler. UI sayfalaması raporu sınırlamaz.
  `app/report.py`. Ayrıntılar: [docs/rapor-ve-ham-cikti.md](docs/rapor-ve-ham-cikti.md).
- **Tamamlandı:** `aylik_kota` ve süreçler arası rate limit — `app/limits.py`.
  Redis Lua ile atomik; saat `TIME`'dan okunur (yerel saat değil), kota UTC
  takvim ayıdır, anahtarlar hash-tag'li (Cluster'da aynı slot). Redis'e
  erişilemezse **tool başlatılmaz**: yerel sayaca düşmek limitleri sessizce
  worker sayısı kadar çoğaltırdı. `worker.runner()` içinden bağlanır.
  Sayaçlar `redisdata` volume'ünde AOF ile kalıcı.

### Hafta 6 — AI katmanı (KOD TAMAM, CANLI ÇALIŞTIRILMADI)

| Dosya | İçerik |
|---|---|
| `app/ai/prompt.py` | **SAF** — prompt kurma, JSON şema, `dogrula()` |
| `app/ai/provider.py` | `AiProvider` protokolü, `GeminiProvider`, `SahteProvider` |
| `app/ai/skorla.py` | Akış: ön eleme → model → doğrulama → `assessment` |
| `worker.ai_skorla` | Celery görevi; `job` satırı YAZMAZ |

**Prompt injection savunması — üç katman:**

1. Sistem prompt'u bloğu açıkça VERİ ilan eder; içindeki talimat uygulanmaz.
2. Sınırlayıcı **kimliklidir ve veriye göre değişir**
   (`<untrusted_data id="a3f9…">`). Sabit olsaydı saldırgan kendi subdomain
   adına kapanış etiketini yazıp bloktan çıkabilirdi.
3. Değerlerdeki `<` `>` kaçırılır — etiket parçalanır, kaçış imkânsızlaşır.

Model, blok içinde talimat görürse uygulamaz; gerekçede belirtir ve skoru
**yükseltir** (gizlenmeye çalışan varlık ilgi çekicidir).

**Halüsinasyon filtresi — iki katman:**

1. Modele UUID değil `v1`, `v2` … etiketleri gider. Uydurulan etiket haritada
   yoktur, düşer. Filtre "biçim doğru mu" değil **"bu turda gönderdim mi"**
   sorusuna dayanır. Yan fayda: girdi token'ı ~üçte bire iner.
2. Yazımdan hemen önce `entity.id` + `investigation_id` DB'den doğrulanır.

**Kota koruması:** `assessment.girdi_hash` — aynı girdi + aynı
`prompt_versiyon` ikinci kez modele gitmez. Sertifikalar (hacmin %34'ü) hiç
gönderilmez. Yığın boyutu 120 — kota için değil **doğruluk** için: uzun
listede model sona doğru özensizleşir.

**Sınırlar:** `temperature=0`. Anahtar `x-goog-api-key` başlığında gider, URL'de
değil; hata mesajında maskelenir. Bozuk yanıt veya sağlayıcı hatası turu
düşürmez — bir yığın düşse diğerleri yazılır. `skorla()` **commit etmez**.
AI yalnızca `assessment` ve `hypothesis` EKLER; hipotez `beklemede` başlar.
Skor **sıralamayı değiştirmez**, tabloya yalnızca bir sütun ekler.

**Test:** `tests/test_ai_prompt.py` (36, saf), `tests/test_ai_provider.py`
(16, `MockTransport` — ağa çıkmaz), `tests/test_ai_skorla_db.py` (15, gerçek
PostgreSQL).

**YAPILMADI:** `GEMINI_API_KEY` boş olduğu için **canlı model hiç çağrılmadı.**
Anahtar girilip bir tur koşulması gerekiyor; asıl sürpriz orada çıkar
(gerçek yanıt biçimi, gerçek gecikme, gerçek kota). Rapor taslağı üretimi
(kapsam.md 3.5 madde 3) de yazılmadı — rapor şu an şablondan üretiliyor.

### Hafta 7 — toparlama, sunum

### Bilinen açıklar

- 27 whois-rdap taşıma hatası araştırılmadı (3 denemeden sonra `failed`)
- Bulut/CDN filtresi gerçek veriyle **kalibre edilmedi**. iana.org turunda
  yalnızca 3 ASN işaretlendi; Cloudflare/AWS arkasındaki bir hedefle
  tekrarlanmalı. Ön eleme eşikleri de (`docs/on-eleme.md`) tek hedefe dayanıyor.
- Redis düşerse tool çalışmaz (bilinçli: sessiz limit aşımından iyidir), ama
  bu, Redis'i tur için tek hata noktası yapar
- Arşivden silinmiş ham dosyalar geri getirilemez; görüntüleyici 404 gösterir.

---

## 9. Kapsam dışı (v1'de YOK)

Fikirler koda değil `backlog.md`'ye gider.

- Aktif tarama — nmap, port/dizin taraması, brute-force, AXFR (Seviye A)
- Kişi araştırması — Sherlock, Maigret, holehe, GHunt (KVKK + kapsam şişmesi)
- Sosyal medya toplama
- Dark web / breach veritabanları (ücretli API + hukuki gri alan)
- Çok kullanıcılı yetkilendirme, rol yönetimi (kapalı ekip aracı)
- Grafik/görselleştirme (Maltego tarzı graph view) — v2
- Zamanlanmış tarama ve diff — v2'nin ana özelliği
- Halka açık deployment
- Self-hosted LLM (Ollama) — provider soyutlaması var, sonradan eklenir
- React/SPA arayüz — HTMX yeterli
- Web arayüzünden tool yükleme / marketplace

**Tool sayısını şişirme.** v1 çekirdeği 7 tool ile sınırlıdır.

---

## 10. Yapma listesi (kod)

- `normalize()` / `parse()` içinde **ağ, DB, dosya, saat okuma, rastgelelik yok**
- `Observation` dataclass'ına **`entity_id` ekleme** — eksiklik bilinçlidir
- **Nokta sayarak** domain/subdomain kararı verme — PSL kullanılır
  (`.com.tr`, `.co.uk`, `.gov.tr` nokta sayımıyla her zaman yanlış çıkar)
- **`www` atma** — ayrı subdomain'dir, atmak veri kaybıdır
- **Dedup'ı `if exists` sorgusuyla** çözme — `uq_entity` + `ON CONFLICT`;
  paralel worker'larda tek doğru yöntem budur
- **Zincirleme kuralını elle yazma** — `kabul_eder`/`uretir`'den türer
- **`assessment` satırını güncelleme** — yalnızca eklenir
- **Native PostgreSQL enum** — `TEXT + CHECK` (enum'a değer eklemek migration
  ister, tool eklendikçe bu sık olacak)
- **Elle SQL ile şema değiştirme** — Alembic; her migration `downgrade` dolu
- **Adapter içinde** timeout / retry / rate limit / kota / diske yazma
- **Fixture'sız tool**
- **Yetki kontrolünü arayüzde yapma** — P2/A kontrolü runner'da; arayüz atlanabilir
- **Ham tool çıktısını doğrudan modele gönderme**
- **Yatay geliştirme** — dikey dilim önceliklidir

### Depo ve çalıştırma

- Repoda **API key veya gerçek hedef/müşteri verisi** yok — ekran görüntüsü ve
  commit mesajı dahil. `.env` commit edilmez, `.env.example` edilir.
- Servisleri **`0.0.0.0`'a bağlama** — portlar `127.0.0.1`'e; erişim
  VPN/Tailscale arkasından
- Arayüzdeki zorunlu uyarıyı kaldırma:
  *"AI skorları önceliklendirme amaçlıdır. Doğrulama sorumluluğu analiste aittir."*

---

## 11. Çalıştırma ve test

### Ayağa kaldırma

```bash
cp .env.example .env
```

`.env` içinde `POSTGRES_PASSWORD` ve `DATABASE_URL` doldurulur, sonra:

```bash
docker compose up -d
```

Arayüz: `http://127.0.0.1:8000`

### Testler — üç ayrı yol

Veritabanı `osint-data` internal ağındadır; hepsini tek komutla koşmak
**mümkün değildir**.

```bash
python -m pytest tests/ -m "not slow" --ignore=tests/test_ingest.py --ignore=tests/test_e2e.py --ignore=tests/test_triage_db.py --ignore=tests/test_relationships_db.py --ignore=tests/test_report_db.py
```

```bash
docker compose run --rm --no-deps api python -m pytest tests/test_ingest.py -q
```

Ön eleme ve ilişki görünümünün PostgreSQL/HTTP testleri:

```bash
docker compose exec -T api python -m pytest tests/test_triage_db.py tests/test_relationships_db.py tests/test_report_db.py tests/test_raw_output.py -q
```

```bash
docker compose run --rm --no-deps worker python -m pytest tests/test_e2e.py -q
```

Host'takiler hiçbir şeye bağlı değil (runner testleri Docker soketi ister).
`test_ingest.py` veritabanına dokunur. `test_e2e.py` hem veritabanı hem Docker
soketi ister — o yüzden `worker` servisinden koşar.

`-m slow` işaretli testler canlı dış servise çıkar (crt.sh, RIPEstat, rdap.org,
DNS, theHarvester container'ı, Shodan). Servis düşükse `pytest.skip` ile
atlanırlar, **asla `fail` etmezler**.

### Migration

```bash
docker compose run --rm --no-deps api python -m alembic upgrade head
```

### Elle SQL

```bash
docker compose exec db psql -U osint -d osint
```

---

## 12. Ortam tuzakları (hepsi bizzat yaşandı)

- **`crt.sh` sık sık 502 döner.** Dakikalar içinde 200 ve 502 arasında gidip
  gelir. Canlı testler bu yüzden `@pytest.mark.slow` ve servis düşükse
  **atlanır** — asla `fail` etmez. Bir testin crt.sh'ın o anki keyfine bağlı
  olması, "kod mu bozuk, sunucu mu düştü" sorusunu cevaplanamaz hâle getirir.
  Aynı sebeple `crtsh` adapter'ı 502'de istisna fırlatmaz, `cikis_kodu`'na HTTP
  durumunu yazar ve runner retry'a düşer.
- **Windows'ta `localhost` kullanma, `127.0.0.1` yaz.** `localhost` önce `::1`'e
  (IPv6) çözülür, docker portları yalnızca IPv4'e yayınlar; her bağlantı önce
  100+ saniyelik TCP zaman aşımını bekler. (Ölçüldü: 100s+ vs 9ms.)
- **Veritabanı host'tan TCP ile erişilemez** (`osint-data` internal ağ).
  Migration ve DB testleri container içinden koşar.
- **`pip` ve `alembic` PATH'te olmayabilir** — her zaman `python -m ...` kullan.
- **`docker.sock` izni**: soket root:root 660, container uid 1000 ->
  `group_add: ["0"]` gerekti. **Not: docker soketine erişim pratikte host root'u
  demektir.** Bilinçli kabul edildi; üretimde soket proxy'si gerekir.
- **Veritabanında gerçek araştırma kayıtları olabilir.** Testler ve ölçüm
  sorguları `investigation_id` ile filtrelemek **ZORUNDADIR**; filtresiz sorgu
  başka araştırmaların satırlarını toplar ve yanlış sonuç verir. Test temizliği
  yaparken `DELETE FROM investigation` gibi toptan silme **KULLANMA**.
- **`theHarvester`'ın PyPI paketi boş bir 0.0.1 stub'ıdır.** GitHub'dan pinli
  kurulur (`@4.6.0`).
- **RIPEstat `holder` alanı iki biçimde gelir**: `GITHUB - GitHub, Inc.` ve
  `HETZNER-AS Hetzner Online GmbH`. İkisi de ele alınmalı, yoksa ORG tekilleşmez.
- **`private` IP sınıflandırmasında sıra önemlidir**: `is_private`, loopback /
  link_local / reserved kontrollerini gölgeler. Özel olan önce kontrol edilir.
