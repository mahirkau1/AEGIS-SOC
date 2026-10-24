# Güvenlik ve GitHub'a Yayımlama Kontrolü

## Yayın durumu: ONAY BEKLİYOR

Aşağıdaki kontroller tamamlanmadan depo **public** yapılmamalıdır. Bu pakete uygulama kodu, gerçek log, kimlik bilgisi, DB veya anahtar **eklenmedi**.

## Yayımlama kontrol listesi

- [ ] Kaynak kodun aktif sürümü ve işlem/servis giriş noktası belirlendi.
- [ ] `.gitignore` mevcut dosyalarla birleştirildi; `.env`, `.venv`, `*.db*`, `*.sqlite*`, `*.log`, `__pycache__`, yedekler ve derleme çıktıları dışlandı.
- [ ] Gizli değerler ve hassas veriler **çalışma ağacında ve Git geçmişinde** kontrol edildi; gerekirse sırlar döndürüldü.
- [ ] İncelenen sürümde `SOC_INGEST_TOKEN` boşken auth atlandığı için erişim tasarımı teyit edildi/düzeltildi.
- [ ] FastAPI / dashboard bind adresleri ve reverse proxy / LAN sınırları kontrol edildi.
- [ ] `X-SOC-Token` doğrulaması, hata yanıtları, loglama ve brute-force dayanıklılığı kontrollü test edildi.
- [ ] Yetkisiz olay alımı, sahte log enjeksiyonu, aşırı uzun raw input ve DoS riskleri değerlendirildi.
- [ ] SQL sorguları parametreli, DB yedekleri korumalı, retention ve maskeleme kuralları tanımlı.
- [ ] UI'da `innerHTML` kullanım yollarındaki kullanıcı kaynaklı alanlar escape ve DOM güvenliği açısından incelendi.
- [ ] AI prompt injection, kişisel veri, komut yürütme ve dış sağlayıcı/veri sızıntısı riskleri incelendi.
- [ ] Ekran görüntülerinde kimlik, kullanıcı adı, cihaz/alan adı, IP, özel yollar ve zaman damgaları gerektiğinde maskelendi.
- [ ] MITRE ve saldırı testi çıktıları "laboratuvar simülasyonu" olarak etiketlendi.
- [ ] SBOM/bağımlılık listesi, lisanslar ve üçüncü taraf kural kaynakları gözden geçirildi.
- [ ] Depo lisansı sahibi tarafından seçildi (otomatik lisans atanmamıştır).
- [ ] Yeni dosyalarla var olan `README`/`.gitignore` farkı gözden geçirildi; yedekler silinmedi.

## Öne çıkan risk: ingest kimlik doğrulaması

Önceki `main.py` anlık görüntüsündeki mantık: `if TOKEN and request.headers.get('X-SOC-Token') != TOKEN: raise 401`. `TOKEN` boşsa koşul çalışmaz. Sonuç: **Erişim kontrolü sadece dış ağ politikalarına kalabilir.** Bunun güncel serviste de sürüp sürmediği test edilmeden güvenli varsaymayın.

**Öncelikli ayrı geliştirme önerisi:** Varsayılanı kapalı/korumalı alım, secret rotation, doğrulama metrikleri ve gizli dizinin güvenli yüklenmesi. Bu görevde **kod değiştirilmedi**.

## Tehdit modeli için başlangıç senaryoları

| Yüzey | Tehdit | Tavsiye edilen kontrol (mevcut özellik olduğu iddia edilmez) |
|---|---|---|
| Ingest API | Sahte olay enjeksiyonu | Zorunlu auth, TLS/izole ağ, IP/rate sınırı, imzalı/ayrık collector kimliği |
| Syslog | Kaynak taklidi, packet loss | Güvenli tünel/izinli ağ, kayıp sayacı, cihaz saati normalizasyonu |
| SQLite/AI logs | Hassas telemetri sızıntısı | Dosya izinleri, retention, maskeleme, şifreli yedek |
| Dashboard | XSS, unauthenticated browse | DOM-safe rendering, authz, CSP incelemesi |
| MITRE/LLM | Hatalı kategorileme, prompt injection | Kanıt bağlama, kullanıcı onayı, denetlenebilir fallback |
| GitHub | Secret/özel IP/şirket verisi | History taraması, maskeleme, secret rotation |

## Lisans

Lisans sahibi onayı bekleniyor. MIT/BSD-3/Apache-2.0 gibi seçenekler telif, patent ve yükümlülük bakımından farklıdır. **Bir `LICENSE` dosyası bilerek üretilmedi.**
