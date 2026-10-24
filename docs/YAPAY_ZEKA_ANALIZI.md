# Yapay Zekâ Destekli Analiz

## Kaynak kodda gözlenen mimari (eski `main.py`)

- Varsayılan model adı `OLLAMA_MODEL` ortam değişkeninden, yoksa `qwen3:1.7b` değerinden okunuyor (`/api/incidents/analyze` / `/api/ai/status`).
- Ollama servis kontrolü `http://127.0.0.1:11434/api/tags` yoluna üç saniyelik timeout ile yapılıyor.
- Vaka özeti, `incident_engine.build_incidents` içinden gelen `source_ip`, `destination_ip`, `ports`, `signatures`, `suricata_alerts`, `firewall_blocks` alanlarına dayanıyor.
- Yerel model ilave yorum üretmesi, örnek kodda **`SOC_AI_EXTRA=1`** koşuluna bağlı.
- Aynı eski dosyada Sysmon işlem incelemesi `SOC_OLLAMA_MODEL` ortam değişkenini okuyor; bu **ayrı model değişkeni** uyuşmazlık riski olarak yeniden değerlendirilmeli.

## Analiz çıktı sınırları

| Soru | Eski kodun gösterdiği | Açık iş |
|---|---|---|
| Hangi kanıtlar gönderilir? | Seçilmiş vaka alanları veya Sysmon process/command line/network/DNS | `ad_intelligence` gerçek prompt içeriği ayrıca incelenmeli |
| Yanıt nasıl alınır? | `/api/generate`, `stream:false`, JSON `response` alanı | Güncel model API uyumu |
| Sonuç doğrulanır mı? | Vaka analizinde CJK/uzunluk/kelime sayısı için temel filtre var | Delile dayalı doğruluk garantisi yok |
| Nerede saklanır? | Eski `main.py` örneğinde kalıcı analiz yazımı görülmüyor | Güncel worker/storage bağlantısını incele |
| Hata olursa ne olur? | Bazı yollarda kural tabanlı rapora dönüş | Sessiz exception, hata metriklerinin olmaması |
| İnsan onayı gerekir mi? | Metin analist önerisi olarak sunuluyor | Otomatik aksiyon yetkisi ayrıca denetlenmeli |

## Güvenilirlik ilkeleri

1. **Ham log güvenilmeyen girdidir.** IP, HTTP header, kullanıcı adı veya komut satırı içine yerleştirilmiş talimatların sisteme komut verememesi gerekir. Eski prompt'ta uyarı olması yeterli bir güvenlik garantisi değildir.
2. **Kanıt / yorum ayrımı:** Veritabanından görülen `event_id`, `signature_id`, `flow_id` ayrı; AI değerlendirmesi ayrı sunulmalıdır.
3. **Eksik delil ibaresi:** Model MITRE ID, saldırı başarısı, yetki artışı gibi iddiaları kanıt olmadan kesinleştirmemelidir.
4. **Gizlilik:** Laboratuvar logları bile kullanıcı adı, cihaz adı, IP, dosya yolu, command line ve kimlik bilgisi taşıyabilir. Dış servise aktarım varsa kullanıcıya ve dokümanlara açıkça yansıtılmalıdır. İncelenen Sysmon yolunda loopback Ollama kodu var; **bütün sistemin dışa veri çıkarmadığını kanıtlamaz**.
5. **Güvenli hata yönetimi:** AI çalışmıyorsa olay alımı/kayıt/temel rapor devam etmeli, sessiz başarısızlıklar izlenebilmelidir.

## Doğrulanması gereken testler

- Ollama kapalı, model yüklü değil, yanıt boş, model hatalı JSON, model timeout.
- Loga gömülmüş kötü niyetli talimatı **veri** olarak tutma (prompt-injection dayanıklılığı).
- Hassas kayıtların rapora veya dış loglara gereksiz taşınmaması.
- Aynı olay için tekrarlanabilir temel rapor ve belirsizlikler.
- `SOC_AI_EXTRA` ve `SOC_OLLAMA_MODEL` farklı kombinasyonları.

Bu testler bu dokümantasyon oturumunda **çalıştırılmadı**.
