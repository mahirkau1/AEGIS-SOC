# Testler ve Doğrulama Matrisi

## Kanıtlanan geçmiş testler

| Tarih | Test / koşum | Kaynak | Sonuç | Sınır |
|---|---|---|---|---|
| 10.10.2026 | 10 farklı ağ testi (TCP SYN, UDP, DNS A/NXDOMAIN, SMB, RDP, Kerberos, LDAP, ICMP, çoklu tarama) | Önceki laboratuvar gözlemleri | SOC'a ulaştıkları raporlandı | Her biri bağımsız detection/mapping başarısı değil |
| 11–12.10.2026 | WIN01 Sysmon Event ID 3, DC01 Security 4776 | Önceki API kayıtları | Olay alımı görüldü | Brute-force korelasyonu o aşamada teyitsiz |
| 18.10.2026 | AEGIS MITRE V2 | Önceki worker/birim test raporu | 21/21 birim testi, 176 Sysmon analizi, 25 tespit raporlandı | Bugünkü canlı worker revizyonu kontrol edilmedi |
| 24.10.2026 | Son 1.000 kayıt sorgusu | `/api/events?limit=1000` | 725 SURICATA, 230 FIREWALL, 25 SYSMON, 20 AD | Toplam sistem sayısı değil, yalnızca API örneklemi |
| 24.10.2026 | GPL ICMP imzaları | Suricata parsed olay | 2 farklı ICMP imzası aynı `flow_id` üzerinde görüldü | Birden çok tekrar = birden çok saldırı değil |
| 24.10.2026 | Kali `aegis_diverse_32.sh` denemesi | Kullanıcı "test bitti" dedi | Çalıştırma tamamlandığı bildirildi | 32/32 senaryo, telemetry ve detection eşleşmesi sağlanmadı |

## 32 senaryo için gerçek başarı matrisi

Aşağıdaki **boş şablon** her testin sonuçlarını ayrı toplamak içindir. Gerçek senaryo adları script içeriği görülmediği için **üretilmedi**.

| Test ID | Scriptteki tam ad | Zaman (UTC) | Beklenen event / imza | Gözlenen raw event | Benzersiz akış / olay | Detection / MITRE | Karar |
|---|---|---|---|---|---|---|---|
| 01–32 | **Script incelemesi bekleniyor** | — | — | — | — | — | DOĞRULANMADI |

Dosya: [`TEST_32_SENARYO_SABLONU.csv`](assets/TEST_32_SENARYO_SABLONU.csv). Bu CSV tüm 32 numaralı boş satırı içerir; testlerin başarı durumunu önceden doldurmaz.

## Test seviyeleri

1. **Unit:** Parser/detection logic için sentetik olay ve beklenen field assert'leri.
2. **Entegrasyon:** Bir test event'inin collector → ingest → storage → query zincirinde kaybolmaması.
3. **E2E:** AD/Sysmon/Suricata/Firewall test senaryosu kaynak cihazda ve SOC'da aynı event olarak görünür.
4. **False positive:** Yetkili yönetim, ping, zaman servisleri, normal DNS gibi davranışların riski.
5. **Regresyon:** 21 V2 testi + 32 Kali senaryosuna ait benzersiz kanıt eşlemesi.
6. **Dayanıklılık:** Log kaybı, duplicate, yanlış saat, DB lock, model offline, bozuk syslog.

## Tekrarların tekilleştirilmesi

Örnek Suricata verisinde tek bir `flow_id` ile farklı `signature_id`'ler gözlendi. Raporlama sırasında farklı hesaplar tutulmalıdır: **ham satır**, **benzersiz `flow_id`**, **benzersiz (`flow_id`,`signature_id`)**, **ayrı test senaryosu**. Bunların hiçbirini otomatik olarak "engellenen saldırı" diye adlandırmayın.

## Test komutlarının durumu

Bu doküman hazırlanırken test paketi, canlı SOC ve Windows host bu oturumdan yürütülemedi; **hiçbir test çalıştırılmış gibi işaretlenmedi**.
