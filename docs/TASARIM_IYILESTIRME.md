# Dashboard İyileştirme Önerileri (Uygulanmadı)

> Bu belge yalnızca **gelecekteki olası çalışmaların** listesi; arayüz veya canlı çalışma dosyaları değiştirilmedi.

## Gözlemler ve öneri ayrımı

| Mevcut eski HTML kanıtı | Önerilen geliştirme (PLANLANDI) | Ölçülebilir kabul kriteri |
|---|---|---|
| CSS içinde birden fazla tema override katmanı | Tek bir monokrom token seti ve komponent stili | Tüm ekranlarda yalnız gri-siyah-beyaz; okunabilir odak/hover |
| `refresh()` 15 sn arayla API'leri yeniden çağırıyor | Sorgu eşzamanlama ve hata/busy göstergeleri | Veri yenileme çakışmaz; son başarılı güncelleme görünür |
| Investigation Graph ilk 80 AD olayına bakıyor | Zaman aralığı seçici + sayfalama | Büyük örneklemde kısmi görünüm etiketi |
| Sysmon Process Tree son 200 olayla sınırlı | Uygun sunucu filtre/sayfalama veya process ID sorgusu | Parent yokluğu telemetri eksiği sanılmaz |
| `eventGroup` tekrarları bir grup anahtarına göre topluyor | Grup ölçütü, tekil akış sayacı ve ham olay sayacı ayrı | 5 ping alarmı 5 saldırı diye gösterilmez |
| Eski UI'da AI notu ve kural kanıtı aynı panelde görülebilir | Kaynak/kanıt, yorum, belirsizlik, analist aksiyonu bölümleri | AI çıktısının kesin hüküm olmadığı açık |
| Identity alarm temizleme ihtiyacı | `Görünenleri temizle` kalıcı dismiss state; **veritabanı olayı silinmez** | Sayfa refresh sonrası gizli kalır, audit korunur |

## Tasarım sistemi

- Renk: `#111111`, `#444444`, `#777777`, `#eeeeee`, `#ffffff` gibi **öneri paleti**; mevcut paletin doğrulaması değil.
- Yazı: tek bir başlık/gövde tipografi hiyerarşisi ve uygun mobil breakpoint.
- Tablo: sticky başlık, yatay taşmayı kontrollü yönetme, event time UTC/görüntülenen timezone bilgisini ayırma.
- Grafik: klavye navigasyonu, focus, alternatif metin ve veri güncelliği uyarısı.
- Modal: role/focus kapanış yönetimi; gerçek uygulamada modal olup olmadığı teyitsiz.

UI iyileştirmesi için önce aktif HTML/CSS/JS sürümü, ekran görüntüsü ve API sözleşmesi doğrulanmalıdır.
