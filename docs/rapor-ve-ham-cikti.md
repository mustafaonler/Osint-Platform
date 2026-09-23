# Ham çıktı ve Markdown raporu

Varlık detayındaki kanıt zincirinde **ham çıktıyı gör** bağlantısı gözleme ait
arşivi açar. Tool, sürüm, zaman, güven ve JSONPath/kaynak yolu birlikte görünür.
Kaynak yolu bilgi olarak gösterilir; JSONPath çalıştırılmaz, dosya yeniden yorumlanmaz.
İlk 256 KiB UTF-8 önizlemesi HTML kaçışından geçirilir. Bozuk UTF-8 baytları
önizlemede değiştirme karakterine dönüşebilir. Büyük dosya açıkça belirtilir;
**tamamını indir** özgün baytları korur ve dosyayı attachment olarak gönderir.

API yalnızca gözlem UUID'sini alır; istemciden dosya yolu kabul etmez.
Gözlem ve işin araştırması eşleşmelidir. DB'deki referans bile güvenilmeyen veri
sayılır: yapılandırılmış arşiv kökü altında tam olarak `{job_id}/output.{format}`
olmalıdır. Başka işin dosyası, `..`, arşiv dışı yol ve symlink yönlendirmesi
reddedilir. Eksik/okunamayan dosyada 404 döner. `nosniff` ve `no-store` kullanılır.
Arşiv dizini sunucunun denetimindedir; bu özellik kimlik doğrulama/çok kullanıcılı
yetkilendirme eklemez. Uygulama mevcut kapalı ekip erişimi sınırında kalır.

Araştırmadaki **Markdown raporunu indir** bağlantısı `.md` dosyası üretir:

- Araştırma kapsamı, kök hedef, yetki durumu ve rapor zamanı (UTC).
- Ön eleme grupları ve gerekçeleriyle tüm varlıklar; UI sayfa limiti uygulanmaz.
- Aynı araştırmadaki ilişki uçları, iş durumları ve hata bilgileri.
- Gözlem kimliği, varlık kimliği, tool/sürüm, zaman ve ham çıktı referansları.
- Varsa her varlığın en son AI değerlendirmesi ve model/prompt bilgileri.
- Doğrulanmış hipotezler ile bekleyen/reddedilen AI hipotezleri ayrı bölümler.

Rapor AI çağrısı yapmaz. Markdown/HTML özel karakterleri kaçışlanır; tool içeriği
resim veya çalıştırılabilir HTML üretemez. Dosya adı araştırma UUID'sinden üretilir.
Ham dosyalar rapora gömülmez; arşiv referansları yerel kurulum içindir.
DB'de olmayan/başka araştırmaya ait hipotez varlık referansları açıkça işaretlenir.

Rapor DB'deki üretim sırasındaki durumu okur; arka planda çalışan işlerin
bitmesini beklemez. Okumalar varsayılan DB transaction izolasyonundadır,
devam eden taramada tablolar arasında eşzamanlı anlık görüntü garantisi yoktur.
Tekrarlanabilir nihai rapor için işlerin tamamlanmasını beklemek gerekir.
Rapor bellekte hazırlanır; çok büyük veri setleri için streaming henüz yoktur.

Testler: `tests/test_raw_output.py`, `tests/test_report_db.py`. Bunlar yol kaçışı,
symlink, eksik dosya, HTML kaçışı, sınırlı önizleme/tam indirme, araştırma
izolasyonu, 100'den fazla varlığın raporda korunması, son AI değerlendirmesi,
hipotezlerin onay ayrımı ve boş araştırmayı kapsar. DB testleri yalnız kendi
transaction'larını rollback eder; mevcut araştırmalara yazmaz.

Hafta 5'in kota ve Redis rate limit çalışması henüz tamamlanmadı.
