# Active Directory kurulumu, domain join ve güvenlik sıkılaştırması

## Kurulum

- **DC01:** Windows Server 2019, `corp.local` domain controller, AD DS ve DNS.
- **WIN01:** Windows 11, `corp.local` domain üyesi, Sysmon telemetrisi.
- `WIN01` domaine alındı; domain hesabıyla oturum, secure channel, `gpupdate`, DC01 isim çözümleme ve SMB testi geçmiş oturumlarda doğrulandı.

## Hesaplar, gruplar ve oturum açma kısıtları

`CORP-Users` kullanıcı organizasyonu üzerinde çalışıldı. **Dokuz test hesabının** `LogonWorkstations` alanında `WIN01` kısıtı geçmiş denetimde doğrulandı. Bu işlem, hesabın hangi iş istasyonunda oturum açabileceğine ilişkin AD kontrolüdür; bu ayarın her tür ağ kimlik doğrulamasını engellediği iddia edilmemelidir.

**Yetkilendirme çalışması:** `Finance-Users` için dosya kaynağı ACL'leri incelendi. Bir önceki ACL dökümünde `BUILTIN\\Users` girdisinin hâlâ bulunması nedeniyle *least privilege* çalışması tamamlanmış olarak raporlanmıyor; izinlerin kapsamı yeniden denetlenmelidir.

## GPO ve Windows güvenliği

`Workstation-Security-Policy` GPO kapsamında Windows Defender Firewall'un Domain/Private/Public profillerinde **açık** olması yapılandırıldı. Defender gerçek zamanlı korumasının etkinliği için yeniden ölçüm gerekir. Kullanıcı/grup yönetimi denetimi ve Windows Security logları üzerinde GPO/Advanced Audit Policy çalışmaları yürütüldü.

## AD olayları ve SOC tespitleri

| Event ID | Önem | Proje çalışmasının durumu |
|---|---|---|
| 4768 / 4769 | Kerberos bilet işlemleri | DC01 üzerinde geçmiş log kanıtı var |
| 4776 | NTLM credential validation | Başarısız kimlik doğrulama olayı SOC'a ulaştı |
| 4625 / 4771 | Başarısız oturum / Kerberos pre-auth failure | Laboratuvar kayıtlarında görüldü; brute-force korelasyonunun her senaryosu doğrulanmadı |
| 4720 | AD hesabı oluşturma | SOC tespit çalışması/testleri yapıldı; son sürüm regresyonu gerekli |
| 4728 | Güvenlik grubuna üye ekleme | SOC tespit çalışması/testleri yapıldı; son sürüm regresyonu gerekli |
| 4738 | AD hesabı değişikliği | SOC tespit çalışması/testleri yapıldı; son sürüm regresyonu gerekli |
| 4724 | Parola sıfırlama girişimi | SOC tespit çalışması/testleri yapıldı; son sürüm regresyonu gerekli |
| 4726 | AD hesabı silme | SOC tespit çalışması/testleri yapıldı; son sürüm regresyonu gerekli |
| 4729 | Güvenlik grubundan üye çıkarma | **Uçtan uca doğrulama bekliyor** |
| 5145 / 4656 | Paylaşım/dosya erişimi ve erişim reddi | **Denetim/SACL/ACL ve Access Denied testi bekliyor** |

### Kimlik doğrulama gözlemleri

Geçmiş Windows kayıtlarında Kerberos `cifs/DC01` bileti için AES-256 ve SMB oturumu için NTLMv2 görüldü. Bu kanıtlar **o bağlantı örneklerini** doğrular; domain düzeyinde yalnızca AES-256 kullanıldığı veya NTLM'nin bütünüyle yasaklandığı anlamına gelmez.

## Dosya/paylaşım denetimi — açık iş

Hedef: Yetkisiz test hesabı bir paylaşıma erişim denediğinde Windows Security 5145 (Detailed File Share) ve gerekiyorsa 4656 (Object Access) başarısızlık olaylarını üretmek ve SOC'ta anlamlandırmak.

Bu testin doğru yapılabilmesi için **Audit Detailed File Share / Audit File System (Failure)** ayarları, klasör üzerindeki **SACL**, paylaşım ve NTFS izinleri ve aktarılan Event ID filtresi birlikte kontrol edilmelidir. Bu zincirin uçtan uca tamamlandığına ilişkin son kanıt bulunmadığından **tamamlandı** yazılmaz.

## Kanıtların güvenli paylaşımı

Gerçek kullanıcı isimlerini, domain/parola export'unu, SID listelerini, grup üyelerini, Kerberos biletlerini veya ham güvenlik loglarını doğrudan GitHub'a koyma. Ekran görüntülerinde hassas kimlikleri maskele; paylaşım için izole laboratuvarda üretilmiş örnek olayları tercih et.
