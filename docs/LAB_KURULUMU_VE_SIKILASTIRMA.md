# Laboratuvarın kurulumu ve güvenlik sıkılaştırma çalışmaları

> **Kapsam:** Bu belge önceki kullanıcı test kayıtlarına ve proje çalışmalarına dayalı bir **uygulama özeti** sunar. Eksiksiz uygulama kılavuzu veya sistemden alınmış son konfigürasyon export'u değildir. Doğrulanan işlevlerle gelecekte tamamlanacak kontroller ayrılmıştır.

## 1. Kurum benzeri ağ tasarımı

OPNsense, ağ geçidi ve merkezi firewall olarak kullanıldı. Ağlar aşağıdaki şekilde ayrıldı:

| Arayüz | Ağ | Kullanım |
|---|---|---|
| em2 | USERS / 10.10.20.0/24 | Windows istemcileri |
| em3 | SERVERS / 10.10.30.0/24 | DC01 / AD DS / DNS |
| em4 | DMZ / 10.10.40.0/24 | Ayrı test bölgesi |
| em5 | SECURITY / 10.10.50.0/24 | Kali güvenlik test sistemi |

**Yapılan kontrol:** USERS ağının domain için gerekli servislere erişimi korunurken DMZ ve SECURITY erişimi kısıtlandı. DNS, domain secure channel, GPO ve SMB testlerinin çalışması, segmentasyon nedeniyle domain hizmetlerinin bozulmadığını gösterdi. Test edilmiş bağlantılar dışındaki izinli/engelli portlar için güncel kural dökümü gerekir.

## 2. Domain Controller kurma

- Windows Server 2019 üzerinde `DC01` kuruldu ve `corp.local` domain controller'a yükseltildi.
- DNS ve Active Directory hizmetlerinin istemciye hizmet verebilmesi için ağ/isim çözümleme testleri yapıldı.
- DHCP servisleri arasında yaşanan port 67 çakışması düzeltildi.
- Domain bazlı loglar (Kerberos ve NTLM dahil) Windows Security olaylarından incelendi.

## 3. Windows 11 domain istemcisi

- `WIN01` kuruldu ve `corp.local` domain'ine katıldı.
- Domain hesabıyla oturum açma, `Test-ComputerSecureChannel`, `gpupdate` ve DC'ye SMB/445 bağlantısı geçmiş oturumlarda doğrulandı.
- `Workstation-Security-Policy` GPO kapsamında Windows Firewall Domain/Private/Public profilleri açık olarak yapılandırıldı; tüm güvenlik kontrollerinin güncel etkinliği yeniden ölçülmelidir.
- Sysmon üzerinde process ve network/DNS telemetrisi gözlemlendi; merkezi SOC'a gönderildi.

## 4. AD hesap, GPO ve erişim sıkılaştırması

- `CORP-Users` test hesapları ve oturum açma kısıtları çalışıldı. Dokuz test hesabının `LogonWorkstations=WIN01` ayarı denetlendi.
- Grup yönetimi ve hesap değişiklikleri için denetim ve SOC tarafı tespitler geliştirildi (4720, 4728, 4738, 4724, 4726).
- `Finance-Users` test kaynağında NTFS izinleri incelendi. Önceki çıktıda `BUILTIN\\Users` izni de bulunduğundan "yetkilendirme tamamen kilitlendi" iddiası doğru değildir.
- `5145` ve gerektiğinde `4656` ile başarısız dosya erişimi, Audit Detailed File Share / File System ve SACL doğrulaması **bekleyen iş** olarak tutulmalıdır.

## 5. IDS / SOC entegrasyonu

- OPNsense firewall ve Suricata alarmları rsyslog UDP/514 + Python collector hattından SOC API'ye iletildi.
- Kali üzerinden servis/port, DNS ve ICMP testleri yapıldı; en azından seçili olayların SOC'a ulaştığı görüldü.
- DC01 Security ve WIN01 Sysmon olayları dashboard'da görüldü.
- MITRE V2 birim testleri ve bir kere çalıştırılmış worker analizi raporlandı; güncel sürekli çalışma durumu ayrıca test gerektirir.

## 6. İşlevsel doğrulama örnekleri

| Senaryo | Gözlem | Sonuç sınırı |
|---|---|---|
| WIN01 → DC01 domain secure channel | Başarılı | Domain iletişimini gösterir |
| WIN01 → DC01 DNS/SMB | Başarılı | Gerekli domain trafiğine izin verildiğini gösterir |
| WIN01 → DMZ / SECURITY | Test edilen erişimler başarısız | Tüm portlarda kapsamlı pentest yerine geçmez |
| OPNsense BLOCK logu | SOC'a ulaştı | Güvenlik politikasının bütünlüğü ayrıca denetlenmeli |
| Suricata alarmı | SOC'a ulaştı | `allowed` alarmı IPS engellemesi değildir |
| Windows AD / Sysmon | SOC'ta olay görüldü | Tüm event ID'ler için kapsama garantisi değildir |

## 7. Repo için kanıt önerisi

Paylaşılabilir artefaktlar: maskelenmiş OPNsense arayüz/kural ekranı, `gpresult` özeti, domain üyeliği kanıtı, Suricata alarm detayının hassas alanları temizlenmiş görüntüsü, SOC event ekranı, test ID–tespit matrisi. Gerçek parolalar, kullanıcı listeleri, sertifikalar, özel anahtarlar, ham loglar ve yedekler **paylaşılmamalıdır**.
