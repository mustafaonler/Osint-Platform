# Hafta 4 ADIM 2 — deterministik ön eleme v1

Ön eleme bir görünüm hesabıdır; entity, observation, relationship veya assessment
tablolarına yazmaz. AI çağrısı, silme veya gizli bir üst sınır yoktur.

## Ölçüm ve karar

AGENTS.md Bölüm 6'daki 580 varlıklı ölçüm esas alındı: varlıkların %70,7'si
tek tool kaynaklı, sertifikalar hacmin %34'ü. Tek kaynaklılık subdomain'de %0,
IP'de %49, netblock'ta %13, sertifikada %65. asn-bgp'nin gözlem/varlık oranı
9,1 olduğu için ham gözlem adedi öncelik veya bağlayıcı sıralama sinyali değildir.
`COUNT(DISTINCT tool)` karşılığı olan tekil tool listesi kullanılır. Farklı tool'lar
aynı üçüncü taraf kaynaktan beslenebilir; bu sayı bağımsız doğrulama garantisi değildir.

Bu oranlar kesin eşikleri matematiksel olarak belirlemez. Aşağıdaki eşikler
v1 ürün kararıdır; yeni hedeflerle kalibre edilmelidir:

| Tip | Öncelikli grup için farklı tool eşiği | Gerekçe |
|---|---:|---|
| subdomain, netblock | 2 | Ölçümde çok kaynaklılık yaygın; tek kaynaklılar ayrıca incelenir |
| ip | 1 | IP'lerin yaklaşık yarısı tek kaynaklı; topluca geriye itilmez |
| domain, asn, org, email, service, tech | 1 | Yetersiz/olmayan ölçüm için temkinli başlangıç; tek kaynak dışlanmaz |
| cert | 1 | Kaynak bilgisi açıklanır ama grup her zaman Sertifikalar olur |

## Kurallar ve öncelik sırası

1. **Sertifikalar:** destekleyici kanıt; varsayılan listede en son.
2. **Kök hedef:** doğrudan gözlemi veya ilişkisi olmasa da Öncelikli.
3. **Bağlam / sağlayıcı:** herhangi bir gözlemde ya da entity niteliklerinde
   `hedefe_ait_degil`, `saglayici_olabilir`, `prefiks_sinir_asildi` JSON boolean
   `true` ise. Metin `"true"` / `"false"` işaret değildir. Bir sonraki gözlemin
   `false` değeri önceki uyarıyı gizlemez. Bunlar sahiplik hakkında kesin hüküm değildir.
4. **İncelenecek:** kaynağı tip eşiğinin altında veya aynı araştırmada gelen/giden
   hiçbir ilişkisi bulunmayan varlık. Sıfır gözlemli ilişki varlıkları da korunur.
5. **Öncelikli:** kalan varlıklar.

Ekrandaki sıra: Öncelikli → İncelenecek → Bağlam / sağlayıcı → Sertifikalar.
Grup içinde farklı tool sayısı azalan; tip, normalize değer ve UUID artan sıralanır.
Aynı veri aynı sırayı verir; yeni gözlem veya ilişki geldikçe sıra değişebilir.
Her satırda tüm uygulanabilir gerekçeler ve kanıt zinciri bağlantısı vardır.
Bu gruplar güvenilirlik veya risk skoru değildir.

## Arayüz ve ölçek

Varsayılan **Tüm varlıklar** görünümü bütün grupları içerir. Grup bağlantıları
yalnızca analistin seçtiği görünümü daraltır. Grup adetleri toplam varlık adedini
verir. 100 satırlık sayfalama bütün kayıtlara erişir; sessiz limit yoktur.
Grup ve sayfa URL'de taşınır, iki saniyelik yenilemede korunur. Boş görünüm ve
aralık dışındaki son sayfa ele alınır. Varlıklar iş listesinin önünde gösterilir.

Okuma tek toplu SQL sorgusuyla araştırmaya sınırlandırılır; tool listeleri ve
işaretler DB'de gruplanır, gelen/giden ilişkiler UNION ile tekilleştirilir.
Gözlem × ilişki çarpımı ve N+1 sorgusu yoktur. Sıralama uygulama belleğinde bütün
araştırma için yapılır (O(N log N)); tarayıcıya yalnızca bir sayfa gönderilir.
Çok büyük araştırmalarda iki saniyede bir toplu okuma hâlâ maliyetlidir; bu sürüm
DB sayfalaması veya önbellek iddiasında bulunmaz.

## Doğrulama ve sınırlar

`tests/test_triage.py`: tip eşikleri, kök istisnası, yetimler, üç sağlayıcı
işareti, sertifika sırası, grupların/sayfaların kayıt kaybetmemesi.
`tests/test_triage_db.py`: gerçek PostgreSQL'de tekrarlı gözlemler, işaretlerin
observation'dan okunması, araştırma izolasyonu, deterministik sıra, salt okuma,
HTTP sayfalaması, grup/yenileme URL'leri, HTML kaçışları ve geçersiz parametreler.
Test verileri transaction rollback ile temizlenir; mevcut araştırmalar silinmez.

```powershell
docker compose exec -T api python -m pytest tests/test_triage.py tests/test_triage_db.py -q
```

23 Eylül 2026'da mevcut 580 varlıklı ölçüm araştırması yeniden okundu:
246 Öncelikli + 134 İncelenecek + 3 Bağlam / sağlayıcı + 197 Sertifika = 580.
Toplu sorgu ve sıralama tek denemede yaklaşık 36 ms sürdü (yük testi değildir).
Eski ölçüm notundaki sıfır işaret bulgusunun aksine, observation.veri dahil
okunduğunda 3 ASN'de prefiks sınırı, bunların 2'sinde hedefe ait olmama ve
1'inde sağlayıcı olma işareti bulundu. Entity alanına bakmak yeterli değildir.
Bu bulgu bulut/CDN hedefiyle ayrı kalibrasyonun yerini tutmaz.

Docker worker içinde dış servislere çıkan `slow` testler hariç 771 test geçti;
19 test seçilmedi. Bunlara gerçek PostgreSQL ve HTTP ön eleme testleri dahildir.
İlişki komşularını
gösterme (ADIM 3), rapor, ham çıktı görüntüleyici ve AI bu adımın kapsamı değildir.
