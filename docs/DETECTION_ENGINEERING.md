# Detection Engineering — Kural ve Kanıt Yönetimi

## Analiz ilkesi

Tespit motoru bir olaya **iddia** eklememelidir; hangi telemetri alanlarının hangi kurala karşılık geldiği, zaman aralığı, eşik, tekrar ve yanlış pozitif ihtimali kayıt altına alınmalıdır. Bir uyarı = gerçek saldırı değildir.

## Şimdilik desteklenen örnekler

| Kural / sinyal | Kaynak / alanlar | Mantık / eşik | Önem | MITRE eşleşmesi | Yanlış pozitif | Test durumu |
|---|---|---|---|---|---|---|
| `GPL ICMP PING` | SURICATA, `src_ip`, `dest_ip`, `signature_id=2100384`, `flow_id` | İmza eşleşmesi; tekrarlar aynı akışta | Olayda `medium` | Bu örnek için **kanıtlanmadı** | Yetkili ping, keşif doğrulaması | **DOĞRULANDI:** 24.10.2026 olay kaydı |
| `GPL ICMP PING *NIX` | SURICATA, `signature_id=2100366`, `flow_id` | İmza eşleşmesi | Olayda `medium` | Kanıtlanmadı | Yetkili ping; aynı akışta mükerrer uyarı | **DOĞRULANDI:** 24.10.2026 |
| AD Event 4720 (hesap oluşturma) | AD, `event_id`, hesap/kullanıcı | Önceki çalışma notlarında uygulandı | Belirsiz | **Doğrulanmadı** | Yetkili hesap açılışı | **KISMEN UYGULANDI:** önceki test raporu; güncel kural kodu yok |
| AD Event 4728 (gruba ekleme) | AD, `event_id`, grup/hesap | Önceki çalışma notlarında uygulandı | Belirsiz | **Doğrulanmadı** | Yetkili yönetim | **KISMEN UYGULANDI** |
| AD Event 4738 (hesap değişikliği) | AD | Önceki çalışma notlarında uygulandı | Belirsiz | **Doğrulanmadı** | Politika/güncelleme | **KISMEN UYGULANDI** |
| AD Event 4724 (parola sıfırlama girişimi) | AD | Önceki çalışma notlarında uygulandı | Belirsiz | **Doğrulanmadı** | Yardım masası işlemi | **KISMEN UYGULANDI** |
| AD Event 4726 (hesap silme) | AD | Önceki çalışma notlarında uygulandı | Belirsiz | **Doğrulanmadı** | Yetkili silme | **KISMEN UYGULANDI** |
| Windows 4776 başarısız NTLM doğrulama | AD, 4776 | Olay alımı görüldü; korelasyon eşiği teyitsiz | Belirsiz | **Doğrulanmadı** | Yanlış parola, servis görevi | **DOĞRULANDI (olay alımı)**; tespit bilinmiyor |
| `powershell.exe` kodlu argümanlar | Sysmon, process command line | Eski kodda `-enc` ve diğer string kontrolleri | Belirsiz | **Doğrulanmadı** | Yönetim scriptleri | **UYGULANDI — TEST EDİLMEDİ** (örnek kod) |
| Olay korelasyonu (`build_incidents`) | SURICATA + FIREWALL alanları | Tam eşikler kaynakta incelenmedi | Kod `risk` alanı üretir | Eski kodda `possible_mitre` alanı | Port denemeleri, lab taraması | **KISMEN UYGULANDI** |

**Özel not:** `alert.severity=3` Suricata'nın IDS kural seviyesi ile SOC'un `severity=medium` map sonucunun farklı kavramlar olduğunu hatırlayın.

## Öncelikli, henüz bitmemiş testler

- **4729** (güvenlik etkin genel gruptan üye çıkarılması): kural/olay çiftinin veritabanına ve UI'ya yansımasını doğrula.
- **5145** (Detailed File Share) ve olası **4656**: yetkili laboratuvar ortamında erişim reddi oluştur, gerekli GPO audit failure/SACL kurallarını kontrol et. Başarılı erişimle karıştırma.
- **4625/4771/4776**: farklı kullanıcı ve kaynak IP'lerden başarısız doğrulamayı tekrar pencere/senaryo bazında grupla; brute force eşiğinin gerçekten oluştuğunu ayrı kanıtla.
- **AEGIS MITRE V2**: geçmişte raporlanan 21/21 testi yeni revizyonda yinele; false positive setini de çalıştır.
- **32 Kali deneyi**: niteliksel test ID, başlama zamanı, hedef, beklenen log, görülen log, kural sonucu, dedup key, karar alanlarını taşıyan eşleştirme tablosu oluştur.

## Örnek tespit değerlendirme formu

| Alan | Doldurulacak içerik |
|---|---|
| Rule ID / kural adı | Kaynaktaki tam kural kimliği |
| Data source | `SURICATA` / `FIREWALL` / `AD` / `SYSMON` |
| Gerekli alanlar | `event_id`, `src_ip`, `user` vb. |
| Filtre ve eşik | Sayı + süre + tekilleştirme anahtarı |
| Kanıt | Ham ve parsed olay referansı, gizli veri maskeleme |
| FP senaryosu | Yetkili tarama, bakım, parola hatası |
| MITRE | ID + kanıt + gerekçe; kanıt yoksa `Belirsiz` |
| Unit / E2E test | Komut, kod sürümü, sonuç, tarih |
| Durum | Altı durumdan tam biri |

## Üretim güvenliği

Otomatik bloklama, AD hesabı değiştirme veya parola sıfırlama eylemleri bu dokümanın kapsamında **uygulanmış özellik değildir**. Analist onayı ve değişiklik yönetimi olmadan tetiklenmemelidir.
