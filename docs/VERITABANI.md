# Veritabanı ve Kayıt Mekanizmaları

## Kanıtlanan API–storage sınırı

Eski `app/main.py` sürümünde aşağıdaki çağrılar görünür:

| Çağrı | Rol | Ne bilinmiyor? |
|---|---|---|
| `storage.insert(item)` | Normalleştirilmiş olayı kaydeder ve boolean döner | Tablo, benzersizlik anahtarı, transaction, indeksler |
| `storage.get_events(limit, offset, mode)` | İstenen olay aralığı / türünü döndürür | Sıralama, maksimum `limit`, retention |
| `storage.stats()` | Toplam/kritik/kaynak istatistiğini üretir | SQL tanımı, gecikme, hesaplama penceresi |

Önceki laboratuvar notları SQLite kullanımına işaret eder, ancak **güncel `storage.py`, DB dosyası ve şema incelenmediği için** tablo/kolon isimleri verilmez.

## Bilinen olay alanları

24.10.2026 örnek Suricata kaydı: `source`, `message`, `severity`, `host`, `raw`, `time`, `parsed`, `event_time`. `parsed` alanında `src_ip`, `dst_ip`, `protocol`, `action`, `signature`, `signature_id`, `flow_id`, `event_timestamp` gibi değerler gözlemlenmiştir.

Bu alanların tüm kaynaklarda zorunlu olduğunu söylemek doğru değildir.

## Bekleyen doğrulama listesi

- Gerçek `sqlite3` bağlantı yolu, WAL/journal modu, timeout ve kilit yönetimi.
- UNIQUE indeks/dedup anahtarı (`flow_id` bazlı mı, olay hash'i mi?).
- Raw olayların tutulma süresi, arşivleme ve silme politikası.
- MITRE V2 `analyses` / `detections` kayıtlarının gerçek tablo ilişkileri; önceki bir defalık koşumda 176 analiz raporu bulunur.
- Kimlik ve komut satırı bilgilerini maskeleme, erişim ve yedek şifreleme.
- Analistin `Görünenleri temizle` etkileşiminin kalıcı veriyi silmeyip sadece kullanıcının görünüm durumunu güncellemesi gerekliliği.

## Güvenli inceleme

Çalışan veritabanına yazma/silme/migrasyon komutu uygulamadan önce bir **kopya** üzerinde şema/indeks doğrulaması yapın. `*.db`, `*.db-wal`, `*.db-shm`, `*.sqlite*` ve yedekleri GitHub'a **eklemeyin**.
