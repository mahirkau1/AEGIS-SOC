# Proje Durumu — 24 Ekim 2026

> **Ana oturum referansı.** Kaynak kod deposunun tamamı bu incelemeye sağlanmadı; doğrulama işaretleri geçmiş oturumlarda sunulan kod parçaları ve SOC laboratuvar çıktılarıyla sınırlıdır. Bu sürüm uygulamaya müdahale etmemiştir.

## 24 Ekim envanter güncellemesi

Kullanıcının 24 Ekim 2026 tarihli `AEGIS_Envanter.zip` raporu incelendi. 67 dosya / 59 Python dosyası / 150 route kaydı (yedekler dahil) tespit edildi; **aktif `app/main.py` içinde 25 route** yer alıyor. `app/network_detection.py`, `app/alert_investigation.py`, `app/event_time.py`, `app/aegis_mitre/`, `app/mitre_worker.py`, `app/ad_selected_analysis_v3.py` ve bunların bazı API bağları statik envanterde var. **Kaynak kod gövdeleri taramaya dahil edilmedi.** Ayrıntılı envanter: [ENVANTER_DOGRULAMA](ENVANTER_DOGRULAMA_2026-10-24.md).

## Kanıt envanteri

| ID | Kanıt | Tarih / sürüm sınırı | Ne doğruluyor? | Ne doğrulamıyor? |
|---|---|---|---|---|
| K1 | `main.py` kullanıcı tarafından önceki oturumda paylaşılan kaynak anlık görüntüsü | Ekim 2026; güncel sürüm belirsiz | FastAPI route'ları, normalizasyon/depolama çağrıları, AI fallback örneği | Güncel çalışan instance'ın kesin bu kodu kullandığı |
| K2 | `index.html` önceki yükleme | Ekim 2026; sürüm belirsiz | Menü, filtreler, graf, process-tree JS/HTML parçaları | Güncel arayüzün aynısı olduğu |
| K3 | PowerShell dosya/route listeleri | 11–18.10.2026 | Dosya adları ve o tarihte route satırları | Dosyanın halen aktif/yükleniyor olduğu |
| K4 | AEGIS V2 test sonucu, önceki oturum raporu | 18.10.2026 | 21/21 birim testi, 176 Sysmon olayının işlendiği, 25 tespit üretildiği raporlandı | Bugünkü çalışan süreç, testlerin hepsinin bağımsızlığı |
| K5 | `/api/events?limit=1000` ve ayrıntılı Suricata olay çıktısı | 24.10.2026 | 725 SURICATA / 230 FIREWALL / 25 SYSMON / 20 AD; ICMP alarmı alanları | Toplam veritabanı büyüklüğü; 32 testin kapsamı |
| K6 | Kullanıcı tarafından paylaşılan AD denemeleri ve çalışma notları | 20–21.10.2026 | 4720/4728/4738/4724/4726 üzerinde çalışma; 4729 ve 5145 planı | Bütün kuralların son sürümde geçtiği |
| K7 | `AEGIS_Envanter.zip` statik AST taraması | 24.10.2026 | 25 aktif API route imzası, Network ve MITRE modül isimleri | İşlem mantığı, test başarıları, erişim güvenliği |

## Mevcut mimari (kanıt kapsamıyla)

- `main.py` anlık görüntüsünde `normalize(item)` ardından `storage.insert(item)` çağrısı bulunuyor. API olay sorguları `storage.get_events(...)` kullanıyor.
- Aynı sürümde `/api/incidents` `build_incidents` fonksiyonuna son 200 alarm olayını aktarıyor.
- AD ve Sysmon için route'lar görülüyor; motor modüllerinin **güncel gerçek içerikleri incelemeye açılmadı**.
- Collector tarafı önceki çalışmalarda Kali üzerinde syslog işleyerek SOC ingest endpoint'ine veri aktardı. Bu pakette collector kodu bulunmuyor.
- Yerel Ollama yolunun `127.0.0.1:11434` olduğu eski kodda görülüyor; aktif erişim için ayrı kontrol gerekir.

## İşlev statüleri

| Bileşen | Sınıflandırma | Temel kanıt | Açık doğrulama işi |
|---|---|---|---|
| API ingest ve sorgu | DOĞRULANDI | K1, K5 | Erişim kontrolü, yük, doğrulama sınırları |
| Firewall/Suricata/AD/Sysmon olay alımı | DOĞRULANDI | K5 | Zaman aralıklı akış sağlığı ve uçtan uca gecikme |
| Normalizasyon | KISMEN UYGULANDI | K1, K5 | Parser sınır durumları, test kapsamı |
| Depolama/dedup | KISMEN UYGULANDI | K1 | SQLite tablo, indeks, veri saklama politikası |
| Incident korelasyonu | KISMEN UYGULANDI | K1, K3 | Eşik, akış bağımsızlığı, false positive testleri |
| Identity/AD Intelligence | KISMEN UYGULANDI | K3, K6 | 4729 ve başarısız dosya erişimi (5145/4656) |
| Sysmon Detection | KISMEN UYGULANDI | K1, K4 | Güncel kurallar ve olay penceresi |
| AEGIS MITRE V2 | KISMEN UYGULANDI | K3, K4 | Güncel 21 test tekrarı ve canlı worker doğrulaması |
| Network Detection V2 | UYGULANDI — TEST EDİLMEDİ | K7: `detect_network_patterns` ve `/api/network/detections` | Kod gövdesi + çıktı eşlemesi |
| AI destekli analiz | KISMEN UYGULANDI | K1 | Güncel fallback, prompt güvenliği, hata/log kaydı |
| Dashboard / Graph | UYGULANDI — TEST EDİLMEDİ | K2 | Canlı görüntü, API eşleşmesi, erişilebilirlik |
| Ayrıntılı kullanıcı yetkileri / RBAC | DURUMU BELİRSİZ | Kanıt yok | Kaynak ve güvenlik denetimi |
| 32 testin tamamının tespiti | DURUMU BELİRSİZ | K5 sadece örnek | Senaryo-telemetri-tespit matrisi |

## Son laboratuvar bulguları

24.10.2026 örnekleminde 1.000 kayıt sayılması `limit=1000` nedeniyle beklenen durumdur. Bu dağılım tüm veritabanını veya 32 testin başarı oranını göstermez. Paylaşılan Suricata ICMP kayıtlarında `GPL ICMP PING` ve `GPL ICMP PING *NIX` aynı `flow_id` üzerinde tekrarlandı; **5 satır ≠ 5 farklı saldırı**. `alert.action=allowed`, güvenlik duvarının PASS kararı olduğu sonucunu tek başına desteklemez.

## Bilinen riskler ve teknik borç

1. **Önceki** `main.py` anlık görüntüsünde `SOC_INGEST_TOKEN=''` olduğunda ingest kimlik doğrulaması zorunlu değildi. **Güncel envanterde** `soc_access_control` fonksiyonu mevcut; güvenlik sorununun giderilip giderilmediği yalnızca fonksiyon adından anlaşılamaz.
2. `GET /api/status` kaynak varlığını online olarak etiketleyebilir; gerçek zamanlı sağlık/son görülme değil.
3. AI örneği `except Exception: pass` kullanıyor; bazı hatalar görünmez kalabilir.
4. `GET /api/incidents` ilk 200 alarm örneğini değerlendiriyor; yoğun tekrarlar pencereden daha anlamlı olayları çıkarabilir.
5. Eski `/dashboard-v2` route'u makineye özel mutlak Windows yolu içeriyor; başka ortamda çalışmayabilir.
6. Eski HTML'de tema stilleri çakışıyor (monokrom katmanının yanında diğer temalar); güncel tasarım doğrulanmalı.
7. Dokümanlar lisans, güvenli varsayılan yapılandırma, gerçek ekran görüntüleri ve bağımlılık kilitleme için nihai değil.

## Şimdi önerilen tek teknik adım

İlk statik envanter oluşturuldu. Sonraki adım kaynak kod gövdeleri ve canlı OpenAPI şemasının güvenlik, route ve işlev açısından ayrı ayrı incelenmesidir. Bu raporda kod gövdesi/secrets yok; yalnızca route adları, fonksiyonlar, modül ilişkileri ve dosya özetleri vardır. Kaynak dosyaların kendisi ayrıca incelenmeden tamamlanmış dokümantasyon ilan edilmez.

## Değişiklik kaydı

Bu dokümantasyon paketi kendi klasöründe oluşturuldu. **Çalışan SOC, OPNsense, Kali collector, SQLite ve AEGIS worker üzerinde değişiklik yapılmadı.**
