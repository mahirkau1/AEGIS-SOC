# Veri Akışı ve Kanıt Zinciri

Bu doküman, bilinen `main.py` ingest kodu ve 24.10.2026 olay örneklerinden çıkarılabilen kapsamı gösterir. Ayrıntılı veritabanı şeması ve collector kodları henüz yoktur.

## Akış tablosu

| Aşama | Girdi | İşlem | Çıktı | İlgili modül | Hata ihtimali | Doğrulama |
|---|---|---|---|---|---|---|
| 1. Kaynak | Firewall/Suricata/AD/Sysmon telemetrisi | Yerel servisler olay üretir | Syslog/Windows olayları | OPNsense, Windows, collector | Kaynakta kayıt kapalı, saat uyuşmazlığı | Kaynak cihazda aynı EventID/signature'ı gör |
| 2. Taşıma | Log akışı | Collector veya ajan API'ye aktarır | HTTP isteği | Collector (ayrı makine) | Port, DNS, yetki, token sorunları | Collector hata kayıtlarını gizli ortamda incele |
| 3. API | `SecurityEvent` JSON | Giriş alanları doğrulanır, opsiyonel token | Pydantic model | `app/main.py` | 401/422, uzun alan, bozuk JSON | Test ortamında kontrollü ingest isteği |
| 4. Normalizasyon | source, raw, message, host | `normalize(item)` | `parsed` alanı | `app/parser.py` | Hatalı syslog ayrıştırma | Raw ve parsed alanlarını karşılaştır |
| 5. Yazma | Normalleştirilmiş olay | `storage.insert` | accepted/duplicate | `app/storage.py` | DB kilidi, duplikasyon anahtarı | Aynı test olayını kontrollü yinele |
| 6. Sorgu | `limit`, `offset`, `mode` | `storage.get_events` | Olay dizisi | `app/main.py` | Pencere/sayfalama yanıltabilir | `mode=all`, tarih ve kaynak karşılaştır |
| 7. Detection | Olay listesi | `build_incidents` ve diğer motorlar | Bulgu/vaka | `app/incident_engine.py` | Tekrarlı alarmlar, false positive | Akış bazlı benzersizlik ve kanıt eşlemesi |
| 8. MITRE | Sysmon vb. kanıt | Engine/worker analizi (tarihsel kayıt) | Teknik eşlemesi | `mitre_engine` / V2 | Kural isabeti / false mapping | Unit test + canlı worker veritabanı |
| 9. AI | Sınırlı vaka kanıtları | Yerel model yorumlaması | Temel rapora ek analiz | `app/main.py` | Timeout, model yok, yanıltıcı yanıt | Fallback ve kanıt kaynakları incele |
| 10. UI | API yanıtları | Liste/graf/filtre | Analist ekranı | `index.html` | Stale veriler, HTML encode, JS hata | Ağ sekmesi + ekran karşılaştırması |

## Örnek bir olayın izlenmesi

24.10.2026 kayıtlarında şu **doğrudan gözlem** vardır: `source=SURICATA`, `signature=GPL ICMP PING`, `src_ip=<KALI_LAB_IP>`, `dst_ip=<DC01_LAB_IP>`, `protocol=ICMP`, `action=allowed`, `flow_id=<ORNEK_AKIS_KIMLIGI>`, `severity=medium`. `GPL ICMP PING *NIX` aynı akışta ek imza olarak görüldü.

**Analitik uyarılar:**
- Beş satır, beş benzersiz saldırı değildir. `flow_id` ve `signature_id` birlikte incelenmelidir.
- `allowed`, Suricata IDS eylemidir; OPNsense firewall PASS kaydıyla eşleşmedikçe izinli geçiş kanıtı olarak kullanılamaz.
- `limit=1000` yalnızca API penceresidir, test kümesi değildir.
- Olay zamanı ve işleme zamanı farklı zaman dilimleri taşıyabilir; UTC'ye normalize ederek kıyaslayın.

## Operasyonel hata ayıklama

1. Kaynak olay gerçekten oluşmuş mu?
2. Collector'u yeniden başlatmadan önce alım zaman damgası güncel mi?
3. `GET /api/events?limit=20&mode=all` yanıtında source/time/parsed alanları var mı?
4. Aynı kaynak/hedef/protokol için fazladan kaç tekrar var?
5. Gerçek alarm listesi ile MITRE/AI bulgusu arasında kanıt ilişkisi var mı?

Bulgular yalnızca gözleme göre kayıt edilir; otomatik engelleme kararı önerilmez.
