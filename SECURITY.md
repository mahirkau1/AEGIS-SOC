# AEGIS SOC — Güvenlik Politikası (Taslak)

**Proje laboratuvar/geliştirme aşamasındadır. Güvenlik garantisi, SLA veya üretim desteği beyan edilmez.**

## Güvenlik açığı bildirimi

Bu pakette doğrulanmış güvenlik iletişim adresi yoktur; **herhangi bir kişisel e-posta adresi uydurulmadı**. Depo sahibi güvenli iletişim kanalını belirleyene kadar gerçek zafiyet ayrıntılarını açık GitHub issue'larına koymayın. Ayrıntıları yalnızca sahibinin onayladığı özel kanaldan iletin.

Bir rapor; etkilenen sürümü, yeniden üretme koşulunu, olası etkiyi, yetkili laboratuvarı ve önerilen düzeltmeyi içerebilir. Kimlik bilgilerini ve gerçek kullanıcı loglarını göndermeyin.

## Güvenli varsayılanlar

- Ingest endpoint'inin `SOC_INGEST_TOKEN` boş olduğunda kimlik doğrulamayı atlayabilmesi eski kodda görülmüştür: açık risk, güncel kontrol bekliyor.
- API yalnızca kontrollü ağda erişilebilir olmalı; erişim kontrolü/doğrulama/rate-limit ayrıca test edilmelidir.
- Yerel AI yorumu karar veya otomatik müdahale için tek başına kullanılmamalıdır.
- DB, loglar, `.env`, ekran görüntüleri, system snapshot'ları ve yedekleri public dağıtıma dahil etmeyin.

Ayrıntılı yayım kontrol listesi: [docs/GUVENLIK.md](docs/GUVENLIK.md).
