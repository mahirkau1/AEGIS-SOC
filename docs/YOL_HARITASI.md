# Önceliklendirilmiş Yol Haritası

Önce doğrulama ve güvenli yayımlama, sonra özellik geliştirme. Her maddenin kapatılması için kanıt, kod sürümü, test sonucu ve yetkili onayı gerekir.

| Öncelik | İş | Kabul ölçütü | Durum |
|---|---|---|---|
| P0 | Güncel repo envanteri | Aktif `app/`, route, collector, tests, template ve requirements kaydı | AÇIK |
| P0 | Secret / Git history / ingest auth denetimi | Boş tokenla izinsiz ingest mümkün değil; secret sızıntısı yok | AÇIK |
| P0 | Güvenli backup ve yayın kapsamı | DB/log/gerçek veriler public pakette yok | AÇIK |
| P1 | 32 test için ölçülebilir test–kanıt haritası | 32 satır, unique event/flow, telemetry, detection ve MITRE durumu | AÇIK |
| P1 | AEGIS MITRE V2 regresyonu | Güncel 21 unit test + worker sonuçları tarihlenmiş | AÇIK |
| P1 | AD 4729 ve Access Denied 5145/4656 | GPO auditing ve olay/uyarı tetikleme gerçek logla kanıtlandı | AÇIK |
| P1 | `Görünenleri temizle` UI tutarlılığı | SQLite kayıt kalır; dismissed uyarılar refresh sonrası gizli | AÇIK |
| P1 | Güncel endpoint OpenAPI referansı | Tüm method/path/request/response/401/422 kayıtları | AÇIK |
| P2 | Alarm tekrar/dedup penceresi ve false positive | ICMP örneği gibi tekrarlar benzersiz test sayılmaz | AÇIK |
| P2 | Source freshness / collector gözlemi | Son görülme, gecikme, kesinti göstergeleri | AÇIK |
| P2 | AI prompt injection ve yanıt doğrulama | Log içi talimat yürütülmez, kural fallback görünür | AÇIK |
| P2 | Dashboard ekran görüntüsü ve responsive QA | Gerçek, maskeli ve başlıklı ekran görüntüleri | AÇIK |
| P3 | Dokümantasyon bakım otomasyonu | Envanter ve doküman drift testi | PLANLANDI |

## Bilinçli olarak yapılmayanlar

Yeni endpoint ekleme, çalışan collector/worker restart, DB migration, otomatik firewall engeli, lisans seçimi, GitHub push, uydurma ekran görüntüsü. Bu görev **dokümantasyon hazırlığıdır**.
