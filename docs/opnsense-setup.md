# OPNsense kurulumu, ağ bölümlendirmesi ve doğrulama

> Bu belge, AEGIS laboratuvarında kullanılan OPNsense katmanını anlatır. **[LAB]** kurulum/test bulgusu, **[KOD]** SOC yazılımında doğrulanan davranıştır. **Trafiği engelleyen OPNsense'tir; AEGIS yalnızca kayıtları okuyup analiz eder.**

## 1. Sanal makinenin oluşturulması

1. **[LAB]** VirtualBox içinde OPNsense için ayrı bir sanal makine kullanıldı. WAN/yönetim ve dahili ağlar ayrı sanal adaptörlere bağlandı.
2. **[LAB]** Dahili arayüzlerde USERS, SERVERS, DMZ ve SECURITY bölgeleri oluşturuldu. Bu ağları tek sanal anahtarda birleştirmek yerine, bölge başına ayrı VirtualBox ağı kullanıldı.
3. **[LAB]** Gözlemlenen arayüz eşlemesi `em2=USERS`, `em3=SERVERS`, `em4=DMZ`, `em5=SECURITY` biçimindedir. Tam WAN / `em0` / `em1` eşlemesi ve OPNsense sürümü mevcut kanıtlarla kesinleştirilemiyor.

| Sanal makine adaptörleri | Arayüzler | Genel görünüm |
|---|---|---|
| ![VirtualBox ağ ayarları](screenshots/virtualbox-opnsense-network.png) | ![OPNsense arayüz menüsü](screenshots/opnsense-interface-assignments.png) | ![OPNsense genel görünümü](screenshots/opnsense-overview.png) |

**Doğrulama:** OPNsense arayüzünde **Interfaces → Assignments / Overview**; konsolda `ifconfig` ile arayüz adları ve gerçek IP bilgileri kontrol edilir.

```sh
# OPNsense konsolunda salt-okunur inceleme
ifconfig
netstat -rn
```

## 2. Subnet ve ağ geçitlerinin ayrılması

| Bölge | Arayüz | Ağ | Ağ geçidi |
|---|---|---|---|
| USERS | `em2` | `10.10.20.0/24` | [LAB] `10.10.20.1` |
| SERVERS | `em3` | `10.10.30.0/24` | [LAB] `10.10.30.1` |
| DMZ | `em4` | `10.10.40.0/24` | [LAB] `10.10.40.1` |
| SECURITY | `em5` | `10.10.50.0/24` | [LAB] `10.10.50.1` |

[LAB] DC01 `10.10.30.10` adresine, Kali `10.10.50.100` adresine konumlandırıldı. WIN01, USERS ağında çalıştı; geçmiş kayıtlarda `.100` ve `.101` kullanımları var. DMZ bölgesi ayrılmış olmasına karşın son laboratuvar durumunda kalıcı bir DMZ sunucusu bulunmuyordu.

**Neden bu şekilde?** [LAB] Her iki makine arasındaki geçiş OPNsense üzerinden izlenebilsin; kullanıcı, sunucu ve saldırı testi trafiği birbirinden ayrı politikalarla yönetilsin diye.

![Ağ topolojisi](screenshots/network-lab-topology.png)

## 3. KEA DHCP ve DNS sorunlarının giderilmesi

[LAB] İlk ağ kurulumunda **KEA DHCP** için `em3` (`10.10.30.1:67`) ve `em4` (`10.10.40.1:67`) adreslerinde bind/port çakışması görüldü. DNSMasq servisinin kapatılması ve KEA'nın doğru arayüzlerde dinleyecek biçimde düzenlenmesiyle DHCP tarafı toparlandı. Sonrasında segmentlerin erişimi ve DHCP kontrol edildi.

1. **Services → KEA DHCP** ekranında etkin subnet ve arayüzleri incele.
2. Servisler arasında port 67'ye rakip bir DHCP dinleyicisi bulunmadığını kontrol et.
3. AD istemcisinde DNS sunucusunun DC01 (`10.10.30.10`) olduğundan emin ol.
4. **Services → Unbound DNS** tarafında çözümleme / blocklist seçeneklerini ayrıca incele.

```powershell
# WIN01: yalnızca mevcut yapılandırmayı okur
ipconfig /all
Resolve-DnsName corp.local -Server 10.10.30.10
```

```bash
# Kali: mevcut rotalar ve DNS sorgusu
ip route
dig @10.10.30.10 corp.local A +noall +answer
```

[LAB] OPNsense'in tam DHCP havuzları, rezervasyonları, Unbound feed kaynakları ve güncelleme aralıkları paylaşılmadığı için tahmin edilmedi.

![OPNsense servis görünümü](screenshots/opnsense-services-status.png)

## 4. Bölgelere özel firewall politikası

[LAB] Her subnet'e serbest ve kontrolsüz erişim vermek yerine, OPNsense'te arayüz ve trafik amacına göre kurallar yazıldı. Özellikle Windows istemcisinin AD servislerine erişebilmesi ile Kali'nin tarama/test trafiğinin izlenmesi ayrı değerlendirildi.

**Kural değerlendirmesinde bakılan alanlar:** arayüz, yön, eylem (`PASS` / `BLOCK`), kaynak, hedef, protokol, port ve eşleşen kural kimliği. OPNsense'in gerçek kural sırası önemlidir; burada elimizde olmayan tam sırayı uydurmuyoruz.

[KOD] AEGIS, genel firewall engelini otomatik olarak "tehdit istihbaratı engeli" saymaz. Böyle bir etiket için onaylı **PF kural UUID** eşleşmesi gerekir.

| Bölge | Bilinen politika adı | Kapsam |
|---|---|---|
| USERS / `em2` | `AEGIS TI - Malicious IP Block` | [LAB] USERS için TI blok kuralı |
| SERVERS / `em3` | `AEGIS TI - DC01 Malicious IP Block` | [LAB] DC01/SERVERS tarafı |
| SECURITY / `em5` | `AEGIS TI - Kali Malicious IP Block` | [LAB] Kali çıkış testlerinde kullanılan blok kuralı |

| Firewall kural ekranı | Canlı firewall kayıtları | Tek kayıt ayrıntısı |
|---|---|---|
| ![Kural ayarı](screenshots/opnsense-rule-config.png) | ![Live View](screenshots/opnsense-firewall-liveview.png) | ![Firewall log ayrıntısı](screenshots/opnsense-firewall-log-detail.png) |

### Kuralın doğru çalıştığını nasıl anlarız?

1. [LAB] **Firewall → Log Files → Live View** ekranını aç.
2. Kaynak olarak `10.10.50.100`, hedef olarak `198.51.100.77` arat.
3. `SECURITY/em5`, giriş yönü, `BLOCK`, uygun protokol/port ve doğru PF kural kimliğini karşılaştır.
4. [KOD] SOC'ta `/api/events?mode=all&source=FIREWALL&limit=100` üzerinden aynı olayın kaynak/hedef/eylem bilgisini incele.

[LAB] OPNsense üzerinde görülen her `BLOCK` olayı saldırı anlamına gelmez. Örneğin DC01'in yayın (`.255`) trafiği veya bazı UDP/123 blokları ayrı ve düşük riskli değerlendirilmiştir.

## 5. Suricata IDS

[LAB] Suricata ile Nmap, ICMP ve benzeri laboratuvar trafiğinin ürettiği imzalar izlendi. ET Open ve `KALI SECURITY TEST` imzası ile GPL ICMP, Nmap kaynaklı alarmlar önceki çalışmalarda görüldü. Kesin kurallar listesi ve aktif IDS/IPS modu için kurulumdan alınmış döküm gereklidir.

[KOD] Parser, Suricata EVE JSON içindeki `alert.signature`, `signature_id`, `severity` ve IP/port/akış alanlarını okuyabilir. Severity 1/2/3 sırasıyla critical/high/medium olarak eşlenir. `KALI SECURITY TEST` laboratuvar imzası kasıtlı olarak low riskte tutulur.

```bash
# Yalnızca izinli laboratuvar ağı için örnek trafik
nmap -sS -Pn -n -p 53,88,135,389,445 --max-retries 1 10.10.30.10
```

![Network tespitleri](screenshots/soc-network-detail.png)

**Doğrulama:** Aynı zaman aralığında Suricata EVE kaydını, OPNsense Live View bilgisini ve AEGIS'teki `SURICATA` olayını karşılaştır. Her Nmap taraması aynı imzaları üretmeyebilir.

## 6. Unbound DNS ve kara liste

[LAB] OPNsense **Unbound DNS blocklist** üzerinden alan adı engelleme izlendi. Kararın gerçek yerel karşılığı **Reporting → Unbound DNS → Details** ekranından kontrol edildi.

[KOD] SOC'ta **NXDOMAIN artışı** ile **Unbound tarafından doğrulanmış kara liste engeli** ayrı kavramlardır. Mevcut collector, Unbound'un açık blok karar alanını SOC'a tam iletmediği için kesin DNS block sayacı üretilmez.

| Unbound izleme | Sorgu ayrıntıları |
|---|---|
| ![Unbound istatistikleri](screenshots/opnsense-unbound-monitoring.png) | ![Unbound sorgu ayrıntıları](screenshots/opnsense-unbound-details.png) |

## 7. Syslog yönlendirme ve Kali collector

[LAB] OPNsense filterlog ve Suricata kayıtlarının ağ tarafında toplanması için Kali'de rsyslog kullanıldı. Daha önceki laboratuvar kurulumunda UDP `514`, `/var/log/opnsense/firewall.log`, `/var/log/opnsense/dns.log`, `/var/log/opnsense/suricata.log` yolları ve `/opt/ad-opnsense-soc/collector.py` dosyası kullanılmıştı. SOC alıcı adresi `192.168.1.111:8088` idi.

[LAB] Güncel çalıştırmada `aegis-collector.service` ile `aegis-dns-reader.timer` hizmetleri kullanıldı. Bu hizmetlerin canlı durumunu doğrulamak için:

```bash
systemctl is-active rsyslog aegis-collector.service aegis-dns-reader.timer
sudo systemctl status aegis-collector.service --no-pager
sudo journalctl -u aegis-collector.service -n 30 --no-pager
```

[KOD] Collector kaydı `POST /api/events/ingest` ile SOC'a gönderir; asıl güvenlik kontrolü, aynı ham kaydın olay listesinde ve Network görünümünde bulunmasıdır.

## 8. Kurulumun tamamlandığını nasıl anlarız?

- [LAB] Arayüzler kendi IP adresleriyle görünür; iki makine yanlışlıkla aynı subnet'te değildir.
- [LAB] Domain DNS çalışır; WIN01, DC01'i DNS olarak görür.
- [LAB] Engellenmesi beklenen trafik `BLOCK`, izin verilen trafik `PASS` olarak görünür.
- [LAB] Suricata etkin kurallarla ilgili EVE JSON kayıtlarını üretir.
- [KOD] AEGIS API, `FIREWALL`, `SURICATA` ve `DNS` olaylarını ayrı kaynak adıyla saklar.
- [LAB] OPNsense güvenlik politikaları çalışırken AEGIS herhangi bir firewall kuralını değiştirmez.

<!-- TODO: OPNsense sürümü, WAN / em0 / em1 kesin eşlemesi -->
<!-- TODO: DHCP havuzları, Unbound feed listesi ve güncelleme sıklığı -->
<!-- TODO: tüm firewall kurallarının gerçek sırası, alanları ve UUID dökümü -->
<!-- TODO: Suricata'nın kesin IDS/IPS modu ve etkin kategori listesi -->
