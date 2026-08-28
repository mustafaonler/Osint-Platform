# CLAUDE.md — bu depoda çalışma kuralları

Ekip içi (kapalı) OSINT orkestrasyon platformu.
Kaynak spesifikasyon: [docs/kapsam.md](docs/kapsam.md) ve
[docs/veri-modeli.md](docs/veri-modeli.md). **Bu iki doküman bağlayıcıdır.**

Yığın: Python 3.12 · FastAPI · PostgreSQL 16 · Celery/Redis · Jinja2 + HTMX ·
Gemini API · docker-compose.

Değer toplama katmanında değil; **normalizasyon + korelasyon + önceliklendirme**
katmanındadır. Amaç yeni bir tarama tekniği geliştirmek DEĞİLDİR.

---

## Değişmez ilkeler (tartışmaya kapalı)

Her teknik kararda bunlara başvurulur.

1. **AI veri silmez, sadece skorlar.** Yanlış negatif görünmezdir. Filtre yok, sıralama var.
2. **Her bulgu ham çıktısına kadar izlenebilir.** Arayüzdeki her satırın yanında "kaynağı gör".
   Teknik karşılığı: `observation.ham_cikti_ref` + `ham_cikti_yol`.
3. **Tool çıktısı güvenilmeyen veridir.** Hedefin kontrolündeki metin modele giriyorsa
   prompt injection savunması zorunludur.
4. **v1 tamamen pasiftir (P0/P1).** Hedefe doğrudan paket gönderen hiçbir modül
   varsayılan açık değildir.
5. **Her tool kendi container'ında izole çalışır.** Bozuk bir tool sistemi düşürmez.
6. **Tool eklemek birinci sınıf işlemdir.** Yeni tool = 1 manifest + 1 adapter + 1 fixture.
   Çekirdek koda dokunulmaz.
7. **Yetenek bazlı düşünülür, araç bazlı değil.** Soru "dig ekleyeyim mi" değil,
   "DNS yeteneğim yeterli mi"dir.

Ek olarak, veri modelinin iki değişmezi:

- **Normalizasyon yazma anında yapılır, sorgu anında değil.** `deger_norm` üretimi
  saf ve deterministik bir fonksiyondur ([app/normalize.py](app/normalize.py)).
  Dedup'ı sorgu anında çözmeye çalışmak mimari hatadır.
- **Üç katman karıştırılmaz:** `entity` (ne var) / `observation` (kim gördü) /
  `assessment` (ne kadar önemli). Aynı IP'yi 3 tool bulduysa 1 entity, 3 observation.

---

## Yapma listesi

### Kapsam (v1'de YOK — fikirler koda değil `backlog.md`'ye gider)

- ❌ **Aktif tarama** — nmap, port/dizin taraması, brute-force, AXFR denemesi (Seviye A)
- ❌ **Kişi araştırması** — Sherlock, Maigret, holehe, GHunt (KVKK yükü + kapsam şişmesi)
- ❌ **Sosyal medya toplama**
- ❌ **Dark web / breach veritabanları** (ücretli API + hukuki gri alan)
- ❌ **Çok kullanıcılı yetkilendirme, rol yönetimi** (kapalı ekip aracı)
- ❌ **Grafik/görselleştirme** (Maltego tarzı graph view) — v2, önce veri modeli otursun
- ❌ **Zamanlanmış tarama ve değişim tespiti (diff)** — v2'nin ana özelliği
- ❌ **Halka açık deployment**
- ❌ **Self-hosted LLM (Ollama)** — provider soyutlaması var, sonradan eklenir
- ❌ **React/SPA arayüz** — HTMX yeterli
- ❌ **Web arayüzünden tool yükleme / marketplace** — eklenti sistemi dosya bazlı yeterli

Tool sayısını erken şişirme: v1 çekirdeği **7 tool** ile sınırlıdır. Yeni tool ancak
Hafta 3 kriteri ("tool eklemek 1 saatten az sürüyor") sağlandıktan sonra eklenir.

### Kod

- ❌ `normalize()` / `parse()` içinde **ağ, DB, dosya, saat okuma, rastgelelik yok.**
  Bu fonksiyonlar saftır; bozulursa fixture testleri anlamını yitirir.
- ❌ `Observation` dataclass'ına **`entity_id` ekleme.** Eksiklik bilinçlidir;
  parser'ı DB'den bağımsız tutar.
- ❌ **Nokta sayarak** domain/subdomain kararı verme. PSL (`tldextract`) kullanılır —
  `.com.tr`, `.co.uk`, `.gov.tr` nokta sayımıyla her zaman yanlış çıkar.
- ❌ **`www` atma.** Ayrı bir subdomain'dir, farklı sunucuya çözülebilir; atmak veri kaybıdır.
- ❌ **Dedup'ı `if exists` sorgusuyla** çözme. `uq_entity` kısıtı + `ON CONFLICT` kullanılır;
  paralel worker'larda tek doğru yöntem budur.
- ❌ **Zincirleme kuralını elle yazma.** Grafik `kabul_eder`/`uretir` alanlarından kurulur
  (`ToolRegistry.tuketenler()`).
- ❌ **`assessment` satırını güncelleme.** Yalnızca eklenir; eski skorlar durur.
- ❌ **Native PostgreSQL enum** kullanma. `TEXT + CHECK` — enum'a değer eklemek
  migration gerektirir, tool ekledikçe bu sık olacaktır.
- ❌ **Elle SQL ile şema değiştirme.** Alembic; her migration `downgrade` dolu olmalı.
- ❌ **Adapter içinde** timeout / retry / rate limit / kota / diske yazma. Bunlar runner'ın işi.
- ❌ **Fixture'sız tool.** Kabul edilmez.
- ❌ **Yetki kontrolünü arayüzde yapma.** P2/A kontrolü runner'da yapılır —
  arayüz kontrolü atlanabilir (`ToolSpec.yetki_ister()` + `investigation.yetki_onayi`).
- ❌ **Ham tool çıktısını doğrudan modele gönderme.** Ön elemeden geçmiş kompakt liste,
  `<untrusted_data>` sınırlayıcısı, structured output (JSON şema) zorunlu.
  Dönen her `entity_id` DB'de doğrulanır (halüsinasyon filtresi).
- ❌ **Yatay geliştirme.** Dikey dilim önceliklidir.

### Depo ve çalıştırma

- ❌ Repoda **API key veya gerçek hedef/müşteri verisi** yok — ekran görüntüsü ve
  commit mesajı dahil. `.env` commit edilmez, `.env.example` edilir. `gitleaks` temiz kalmalı.
- ❌ Servisleri **`0.0.0.0`'a bağlama.** Portlar `127.0.0.1`'e bağlanır; erişim
  VPN/Tailscale arkasından. Halka açık instance yayınlanmaz.
- ❌ Arayüzdeki zorunlu uyarıyı kaldırma:
  *"AI skorları önceliklendirme amaçlıdır. Doğrulama sorumluluğu analiste aittir."*

---

## Şu anki durum: Hafta 3 — eklenti sisteminin sınanması

**3/7 çekirdek tool tamam. 560 test geçiyor.**

Bu haftanın çıktısı "3 tool eklendi" değil, **"tool eklemek ucuzladı"**dır.
Ölçüm: `crtsh` 68 dakika (50'si bir kerelik altyapı borcu), `dns-resolver`
**15 dakika ve çekirdekte tek satır**. Kriter sağlandı.

### Çekirdek

| Dosya | İçerik |
|-------|--------|
| [app/normalize.py](app/normalize.py) | `EntityType`, `normalize()`, `gecerli_mi()`, `domain_mi()`, `kok_domain()`, `service_parcala()` |
| [app/models.py](app/models.py) | 7 tablo (SQLAlchemy 2.x) + `JobStatus`, `MAX_DERINLIK` |
| [app/tools/_base.py](app/tools/_base.py) | Tool sözleşmesi + `ToolRegistry` (manifest keşfi, yetenek grafiği) |
| [app/runner.py](app/runner.py) | `ContainerRunner`, `ApiRunner`, `ToolRunner`, retry, `HizSinirlayici` |
| [app/ingest.py](app/ingest.py) | `upsert_entity`, `upsert_relationship`, `kuyruga_al`, `ingest()` |
| [app/worker.py](app/worker.py) | Celery görevi: job → runner → parse → ingest |
| [app/main.py](app/main.py) | FastAPI + Jinja2 + HTMX, 6 rota |
| [app/db.py](app/db.py) | Oturum fabrikası |

### Tool'lar

| Tool | Seviye | Çalıştırma | Girdi → Çıktı |
|------|--------|-----------|----------------|
| `subfinder` | P0 | docker | DOMAIN → SUBDOMAIN |
| `crtsh` | P0 | api | DOMAIN → SUBDOMAIN, CERT |
| `dns-resolver` | P1 | api | DOMAIN, SUBDOMAIN → IP, SUBDOMAIN, TECH, ORG |

Sırada: `whois-rdap`, `asn-bgp`, `theharvester`, `shodan-lookup`.
Henüz yazılmadı: `app/ai/provider.py`, rapor dışa aktarımı, ön eleme kuralları.

### Testler — üç ayrı yol

Test seti erişim ihtiyacına göre üçe ayrılır; hepsini tek komutla koşmak
mümkün değildir çünkü veritabanı `osint-data` internal ağındadır.

```bash
python -m pytest tests/ -m "not slow" --ignore=tests/test_ingest.py --ignore=tests/test_e2e.py
```

```bash
docker compose run --rm --no-deps api python -m pytest tests/test_ingest.py -q
```

```bash
docker compose run --rm --no-deps worker python -m pytest tests/test_e2e.py -q
```

Host'takiler hiçbir şeye bağlı değil (runner testleri Docker soketi ister).
`test_ingest.py` veritabanına dokunur. `test_e2e.py` hem veritabanı hem Docker
soketi ister — o yüzden `worker` servisinden koşar.

---

## Ortam notları

- **`crt.sh` sık sık 502 döner.** Dakikalar içinde 200 ve 502 arasında gidip
  gelir. Canlı testler bu yüzden `@pytest.mark.slow` işaretlidir ve servis
  düşükse `pytest.skip` ile **atlanır** — asla `fail` etmezler. Bir testin
  crt.sh'ın o anki keyfine bağlı olması, "kod mu bozuk, sunucu mu düştü"
  sorusunu cevaplanamaz hâle getirir. Aynı sebeple `crtsh` adapter'ı 502'de
  istisna fırlatmaz, `cikis_kodu`'na HTTP durumunu yazar ve runner retry'a düşer.
- **Windows'ta `localhost` kullanma, `127.0.0.1` yaz.** `localhost` önce
  `::1`'e (IPv6) çözülür, docker portları yalnızca IPv4'e yayınlar; her
  bağlantı önce 100+ saniyelik TCP zaman aşımını bekler.
- **Veritabanı host'tan TCP ile erişilemez** (`osint-data` internal ağ).
  Migration ve DB testleri container içinden koşar. Elle SQL için:
  `docker compose exec db psql -U osint -d osint`
- **`pip` ve `alembic` PATH'te olmayabilir** — her zaman `python -m ...` kullan.
- **Veritabanında gerçek araştırma kayıtları olabilir.** Testler
  `investigation_id` ile filtrelemek ZORUNDADIR; filtresiz sorgu başka
  araştırmaların satırlarını toplar ve yanlış sonuç verir. Test temizliği
  yaparken `DELETE FROM investigation` gibi toptan silme KULLANMA.
