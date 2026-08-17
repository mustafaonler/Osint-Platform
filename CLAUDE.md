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

## Şu anki durum: Hafta 1 — temel katman

Mevcut dosyalar:

| Dosya | İçerik |
|-------|--------|
| [app/normalize.py](app/normalize.py) | `EntityType`, `normalize()`, `gecerli_mi()`, `domain_mi()`, `kok_domain()` |
| [app/models.py](app/models.py) | 7 tablo (SQLAlchemy 2.x): investigation, entity, observation, relationship, job, assessment, hypothesis |
| [app/tools/_base.py](app/tools/_base.py) | `ToolSpec`, `ToolConfig`, `RawResult`, `Observation`, `ObservedRelation`, `Passivity`, `RelationType`, `ToolAdapter`, `ToolRegistry` |
| [tests/test_normalize.py](tests/test_normalize.py) | Projenin en yüksek öncelikli test seti |

Test:

```bash
python -m pytest tests/ -v
```

Henüz yazılmadı (yol haritasına göre sırada): `app/main.py`, `app/worker.py`,
`app/ingest.py`, `app/ai/provider.py`, Alembic migration'ları, tool adapter'ları.
