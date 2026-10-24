# OPNsense Firewall ve Suricata IDS/IPS çalışmaları

## Amaç

Ağ güvenliğinde hem **erişim kontrolünün uygulanması** hem de **alarm/log kanıtının merkeze taşınması** hedeflendi. Projede firewall kararı ile IDS uyarısı birbirinden ayrı yorumlanır.

## Segmentasyon ve firewall politikası

- `em2/USERS` (`10.10.20.0/24`): WIN01 ve domain istemcileri.
- `em3/SERVERS` (`10.10.30.0/24`): DC01 ve AD/DNS altyapısı.
- `em4/DMZ` (`10.10.40.0/24`): izole servis/test alanı.
- `em5/SECURITY` (`10.10.50.0/24`): Kali ve kontrollü test trafiği.

**Uygulanan yaklaşım:** Domain'in çalışması için gerekli DNS, Kerberos, SMB ve RPC bileşenlerinin USERS → DC01 trafiği üzerinde erişilebilir kalması; DMZ/SECURITY gibi farklı iç bölgelerin doğrudan erişime kapatılması. Önceki laboratuvar testlerinde gerekli domain iletişimi başarılı, sınırlandırılan erişim denemeleri başarısızdı. **Bu özet güncel firewall kural dökümünün yerine geçmez.**

### Kaydedilen örnek firewall olayları

| Kaynak → hedef | Protokol | Karar | Gözlemin anlamı |
|---|---|---|---|
| WIN01 → DC01 | UDP/123 | `BLOCK` | Zaman servisi trafiği için engelleme örneği; politika uyumu ayrıca değerlendirilir |
| DC01 → sunucu ağı broadcast | UDP/138 | `BLOCK` | Broadcast engelleme örneği |
| Kali → Windows test hedefleri | Farklı TCP/UDP portları | `PASS` / `BLOCK` olayları testlerde görüldü | Tekil kararlardır, bütün izin politikasını temsil etmez |

**Dikkat:** DC01'e NTP/123 engeli görülmesi otomatik olarak olumlu sıkılaştırma sonucu sayılmaz; zaman senkronizasyonunun domain açısından gerekli olup olmadığı kontrol edilmelidir.

## Suricata yapılandırma / kurallar

- OPNsense'de Suricata etkinleştirildi ve kurallar ile HOME_NET kapsamı üzerinde testler yapıldı.
- ET Open imza paketinin başlangıçta kurulu olmadığı görüldü; sonraki laboratuvar kayıtlarında GPL ICMP ve özel test alarmları mevcuttu. **Tüm ET Open kurallarının en son güncel/yüklü durumu ayrı kontrol edilmelidir.**
- Suricata EVE/JSON `alert` verisinden `signature`, `signature_id`, `category`, `action`, `severity`, `flow_id`, `src_ip`, `dest_ip` gibi alanlar SOC'a işlendi.
- Özel `KALI SECURITY TEST` imzaları Kali → DC01 SMB/445, RDP/3389, DNS/53, Kerberos/88 ve diğer laboratuvar servislerine yönelik olaylarda gözlendi.

### Örnek doğrulanmış imzalar

| İmza | SID | Durum |
|---|---|---|
| GPL ICMP PING | `2100384` | 24.10.2026 Suricata → SOC loglarında görüldü |
| GPL ICMP PING *NIX | `2100366` | Aynı ICMP akışında görüldü |
| KALI SECURITY TEST | Yerel test imzası | 10.10.2026 servis testlerinde görüldü |

ICMP için farklı imzaların **aynı `flow_id`** üzerinde tekrarlanması çok sayıda bağımsız saldırı olduğu anlamına gelmez.

## IDS ile IPS arasındaki ayrım

| Gözlem | Söylenebilecek doğru sonuç |
|---|---|
| `event_type=alert` | Suricata alarm üretti |
| `action=allowed` | Suricata kaydındaki akışa izin verildi; **IPS tarafından bloklandığı kanıtlanmaz** |
| Firewall `BLOCK` | İlgili paket/trafik kararı firewall tarafından engellendi |
| Nmap testi sonrası ICMP alarmı | ICMP görünürlüğü doğrulandı; **ET SCAN/Nmap signature tespiti kanıtlanmadı** |

## Syslog ve SOC'a iletim

Geçmiş laboratuvar düzeninde Kali üzerinde rsyslog UDP/514 dinleniyor, `/opt/ad-opnsense-soc/collector.py` OPNsense `filterlog` ve Suricata JSON mesajlarını normalleştirip SOC `/api/events/ingest` endpoint'ine iletiyordu. Firewall ve Suricata kaynaklı olayların dashboard'a ulaştığı test edildi. Bu mimari günlük çalışma için servis durumu, kuyruklama ve log kaybı bakımından ayrıca sınanmalıdır.

## Önerilen güvenlik kanıtı ve sonraki testler

1. Kural sırasını hassas bilgiler temizlenmiş ekran görüntüsü ya da anonimleştirilmiş export ile belgele.
2. İzinli AD servislerini, diğer bölgelere retleri ve internet erişimini kaynak/hedef/port/test sonucu matrisiyle doğrula.
3. Suricata'nın gerçekten **blokladığı** trafiği üretim dışı testte ayrı kaydet; alarm sayısını engelleme sayısı olarak gösterme.
4. 32 Kali senaryosunun her birini Suricata SID, firewall eylemi, zaman damgası ve SOC event'iyle eşleştir.
