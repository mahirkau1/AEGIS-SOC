# AEGIS SOC

**Active Directory · OPNsense · Suricata · Sysmon · Identity Intelligence · MITRE ATT&CK · Yerel AI**

> Sanal makinelerle kurulan, ağ segmentasyonu yapılan, log toplayan, tespit üreten ve analiste tek ekranda görünürlük sağlayan uçtan uca SOC laboratuvarı. **AEGIS salt-okunur izleme ve analiz platformudur; otomatik engelleme veya müdahale yapmaz.**

![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white) ![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?logo=fastapi&logoColor=white) ![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white) ![OPNsense](https://img.shields.io/badge/Firewall-OPNsense-E95420) ![Suricata](https://img.shields.io/badge/IDS-Suricata-C73532) ![Sysmon](https://img.shields.io/badge/Endpoint-Sysmon-0A66C2) ![Durum](https://img.shields.io/badge/Proje-Lab%20Tamamland%C4%B1-286E4F)

**[Sıfırdan kurulum](docs/lab-build-walkthrough.md) · [Mimari](docs/architecture.md) · [Tespitler](docs/detections.md) · [Veri akışı](docs/data-flow.md) · [Tüm ekran görüntüleri](docs/screenshots/README.md)**

![Komuta merkezi](docs/screenshots/soc-security-command-center.png)

## Belgelendirme yöntemi

Bu depoda **[LAB]** gerçek laboratuvar kurulumu, ekran görüntüsü veya test çıktısına dayanan bilgileri; **[KOD]** kaynak kodunda incelenen davranışları ifade eder. IP adresleri özel laboratuvar ağlarına aittir. Belgeler, olay tespitini doğrudan saldırının başarıyla gerçekleştiği şeklinde yorumlamaz.

## Proje neyi amaçlıyor?

[LAB] Bu proje, bir olayın sadece tek bir log kaynağında değil; **güvenlik duvarı, IDS, DNS, Windows Security, Sysmon ve kimlik bağlamında** nasıl iz bıraktığını göstermek için kuruldu. [KOD] FastAPI + Uvicorn ile çalışan arka uç, gelen olayları normalize ediyor, SQLite içinde saklıyor, SHA-256 tabanlı tekilleştirme uyguluyor, sonra ağ / AD / Sysmon / kimlik tespit motorlarıyla analiste anlamlı hale getiriyor. [LAB] Son durumda SOC, Windows ana makinede `192.168.1.111:8088` üzerinde çalışıyordu.

## Laboratuvarın kuruluşu ve geliştirme aşamaları

### 1) Sanal makineler kuruldu

[LAB] Laboratuvar tek bir makinede her şeyi karışık kurmak yerine ayrı roller halinde tasarlandı:

- **OPNsense**: ağ geçidi, segmentasyon, firewall ve DNS/Unbound tarafı
- **DC01**: `corp.local` etki alanı denetleyicisi
- **WIN01**: etki alanına katılmış kullanıcı istemcisi
- **Kali**: test, saldırı simülasyonu ve ağ tarafı log toplama noktası
- **Windows SOC ana makinesi**: AEGIS API + dashboard

Aşağıdaki VirtualBox ekran görüntüleri gerçekten kullanılan makine ağ ayarlarını gösterir:

| OPNsense | DC01 | WIN01 | Kali |
|---|---|---|---|
| ![OPNsense VM](docs/screenshots/virtualbox-dc01-network.png) | ![DC01 VM](docs/screenshots/virtualbox-opnsense-network.png) | ![WIN01 VM](docs/screenshots/virtualbox-win01-network.png) | ![Kali VM](docs/screenshots/virtualbox-kali-network.png) |

### 2) Ağ subnet’lere bölündü

[LAB] OPNsense üzerinden düz bir ağ yerine ayrı zonelar tanımlandı. Böylece hem kural yazmak hem de olayları anlamlandırmak kolaylaştı.

| Bölge | Arayüz | Ağ | Sistem | Amaç |
|---|---|---|---|---|
| USERS | [LAB] `em2` | [LAB] `10.10.20.0/24` | [LAB] WIN01 (`10.10.20.101`, bazı eski kayıtlarda `.100`) | Kullanıcı ağı |
| SERVERS | [LAB] `em3` | [LAB] `10.10.30.0/24` | [LAB] DC01 `10.10.30.10` | Domain / sunucu ağı |
| DMZ | [LAB] `em4` | [LAB] `10.10.40.0/24` | [LAB] Son durumda kalıcı servis yok | İzole ağ |
| SECURITY | [LAB] `em5` | [LAB] `10.10.50.0/24` | [LAB] OPNsense `10.10.50.1`, Kali `10.10.50.100` | Test / izleme ağı |
| Yönetim | ayrı ağ | [LAB] `192.168.1.x` | [LAB] SOC host `192.168.1.111` | Dashboard/API |

![Topoloji](docs/screenshots/network-lab-topology.png)

WIN01 DNS istekleri DC01 üzerinden gittiği için bazı DNS loglarında kaynak olarak DC01 görünmesi normaldir; bu dokümantasyonda özellikle belirtilmiştir.

![DC01 ipconfig](docs/screenshots/dc01-ipconfig.png)

![Kali yönlendirme tablosu](docs/screenshots/kali-routing-table.png)

### 3) OPNsense tarafı kuruldu ve kurallar yazıldı

[LAB] OPNsense tarafında önce arayüz eşlemeleri ve IP’ler tanımlandı, ardından DHCP/DNS tarafı kontrol edildi, daha sonra aralarındaki geçişler için firewall kuralları yazıldı. En kritik amaçlardan biri ağların birbirine kontrolsüz erişmemesiydi.

| Arayüzler | Servis durumu | Kural görünümü |
|---|---|---|
| ![OPNsense arayüzleri](docs/screenshots/opnsense-interface-assignments.png) | ![Servisler](docs/screenshots/opnsense-services-status.png) | ![Firewall kuralları](docs/screenshots/opnsense-rule-config.png) |

| Genel görünüm | Firewall Live View | Firewall log detay |
|---|---|---|
| ![Genel görünüm](docs/screenshots/opnsense-overview.png) | ![Canlı olay kayıtları](docs/screenshots/opnsense-firewall-liveview.png) | ![Olay ayrıntısı](docs/screenshots/opnsense-firewall-log-detail.png) |

| Unbound izleme | Unbound detay | OPNsense son ekranı |
|---|---|---|
| ![Unbound izleme](docs/screenshots/opnsense-unbound-monitoring.png) | ![Unbound ayrıntılar](docs/screenshots/opnsense-unbound-details.png) | ![OPNsense son ekranı](docs/screenshots/opnsense-dashboard-final.png) |

[KOD] AEGIS tarafında firewall `BLOCK` logları körlemesine “zararlı IP block” diye işaretlenmez. Kural UUID’si ile onaylı kural eşleştirilirse o zaman blocklist/TI bağlamı verilir. [LAB] Doğrulanan örneklerden biri Kali `10.10.50.100` adresinden `198.51.100.77` test IP’sine çıkan ve OPNsense tarafından engellenen trafikti.

### 4) Active Directory kuruldu

[LAB] DC01 üzerinde `corp.local` domain’i ayağa kaldırıldı. Sonra kullanıcılar, OU’lar ve gruplar oluşturuldu. Amaç sadece domain çalışsın değil; **grup üyeliği değişiklikleri, yeni kullanıcı, yetkili grup, parola ve oturum olayları** gibi SOC açısından anlamlı kayıtlar üretmekti.

Kurulan yapı içinde şunlar vardı:

- **Finance-Users**
- **HR-Users**
- **IT-Users**
- **Management-Users**
- **Sales-Users**
- yerleşik yetkili gruplar: **Domain Admins, Enterprise Admins, Schema Admins, Administrators**

| OU yapısı | Finance | HR |
|---|---|---|
| ![OU yapısı](docs/screenshots/ad-ou-structure.png) | ![Finance](docs/screenshots/ad-finance-ou.png) | ![HR](docs/screenshots/ad-hr-ou.png) |

| IT | Management | Sales |
|---|---|---|
| ![IT](docs/screenshots/ad-it-ou.png) | ![Management](docs/screenshots/ad-management-ou.png) | ![Sales](docs/screenshots/ad-sales-ou.png) |

### 5) Collector yapısı kuruldu

[LAB] Windows tarafında Windows Security ve Sysmon kayıtları collector ile SOC’a gönderildi. Ağ tarafında Kali üzerinden OPNsense filterlog, Suricata EVE JSON ve ilgili ağ logları SOC ingest noktasına aktarıldı.

[KOD] Veri akışı şu şekilde işler:

1. Collector -> `POST /api/events/ingest`
2. `parser.py` ile normalize etme
3. Olay zamanını işleme
4. SHA-256 ile tekilleştirme
5. SQLite (WAL) içine kaydetme
6. Tespit motorları
7. Dashboard + opsiyonel Ollama

```mermaid
flowchart LR
    A[OPNsense filterlog] --> C[Kali collector]
    B[Suricata EVE JSON] --> C
    D[Windows Security] --> E[Windows collector]
    F[Sysmon] --> E
    C --> G[POST /api/events/ingest]
    E --> G
    G --> H[Normalizasyon / zaman / tekilleştirme]
    H --> I[(SQLite)]
    I --> J[Ağ tespitleri]
    I --> K[AD tespitleri]
    I --> L[Sysmon tespitleri]
    I --> M[Kimlik analizleri]
    I --> N[MITRE eşleştirmesi]
    J --> O[Dashboard]
    K --> O
    L --> O
    M --> O
    N --> O
    O -. opsiyonel .-> P[Ollama qwen3:4b-instruct]
```

### 6) Sysmon tarafı geliştirildi

[LAB] Sysmon tarafında önce temel kurallar çalıştırıldı, sonra collector ve config düzenlenerek daha geniş kapsama geçildi. Özellikle Event ID `11` ve `13` (startup file / autorun registry) için canlı testler yapıldı. WIN01’de canlı alarmlar dashboard’a başarıyla düştü.

| Genel görünüm | Süreç incelemesi | Analiz paneli |
|---|---|---|
| ![Sysmon genel görünüm](docs/screenshots/sysmon-endpoint-overview.png) | ![Süreç incelemesi](docs/screenshots/sysmon-process-investigation.png) | ![Olay analiz ayrıntısı](docs/screenshots/sysmon-analysis-detail.png) |

WIN01 üzerinde gerçek olaylarla doğrulanan sekiz tespit kuralı şunlardı:

- `SYSMON-SUSPICIOUS-DNS`
- `SYSMON-AUTORUN-REGISTRY`
- `SYSMON-STARTUP-FILE`
- `SYSMON-OFFICE-SHELL`
- `SYSMON-SCRIPT-SHELL`
- `SYSMON-POWERSHELL-EXECUTION`
- `SYSMON-ENCODED-POWERSHELL`
- `SYSMON-UNUSUAL-OUTBOUND-PORT`

### 7) Identity · AD Intelligence bölümü büyütüldü

[LAB] Projenin en güçlü yanlarından biri ham AD olayından daha ileri gidip **identity bağlamı** eklemesiydi. Bu bölümde envanter, yetki ilişkileri, kritik grup eşleşmesi, User 360, risk bağlamı ve davranış zaman çizelgesi üretildi.

| AD Intelligence | Kullanıcı listesi | Güvenlik incelemesi |
|---|---|---|
| ![AD Intelligence](docs/screenshots/identity-ad-intelligence.png) | ![Kullanıcılar](docs/screenshots/identity-users-list.png) | ![Çalışma ekranı](docs/screenshots/identity-security-intelligence.png) |

| Yetki üyelikleri | User360 profil | Risk analizi |
|---|---|---|
| ![Yetki üyelikleri](docs/screenshots/identity-privilege-memberships.png) | ![Kullanıcı profili](docs/screenshots/identity-user360-profile.png) | ![Risk görünümü](docs/screenshots/identity-user360-risk-analysis.png) |

| User360 özet | Kimlik detay ekranı |
|---|---|
| ![Kullanıcı 360 özeti](docs/screenshots/soc-identity-user360-summary.png) | ![Kimlik ayrıntıları](docs/screenshots/soc-identity-details.png) |

[KOD] Bu kısımda artık:

- AD envanter yan veri katmanı
- yetki yan veri katmanı
- kritik grup tespiti
- kimlik doğrulamalı yetki API uçları
- User 360
- risk bağlamı
- davranış zaman çizelgesi

çalışır durumda.

### 8) Dashboard’da bugün neler var?

| Güvenlik komuta merkezi | Tüm loglar |
|---|---|
| ![Komuta merkezi](docs/screenshots/soc-security-command-center.png) | ![Tüm loglar](docs/screenshots/soc-all-logs.png) |

| Ağ tespiti | Ağ logları | Ağ özeti |
|---|---|---|
| ![Ağ tespit ayrıntısı](docs/screenshots/soc-network-detail.png) | ![Ağ logları](docs/screenshots/soc-network-logs.png) | ![Ağ tespit özeti](docs/screenshots/soc-network-detection-summary.png) |

| Terminal doğrulama kaydı |
|---|
| ![Terminal doğrulama](docs/screenshots/soc-cli-validation-output.png) |

### 9) Güncel tespit kapsamı

#### Ağ

[KOD]
- dikey port tarama adayı
- yatay tarama adayı
- 5 dakikalık korelasyon
- Suricata severity eşleme
- laboratuvar imzalarını düşük riskte tutma
- yayın paketleri / gürültü ayıklama

#### AD / Windows Security

[KOD]
- `4624, 4625, 4672, 4719, 4720, 4724, 4726, 4728, 4729, 4732, 4738, 4740, 4756, 4768, 4769, 4771, 4776, 1102, 5145`
- `brute_force`, `success_after_fail`, `password_spray`, `user_enum`, `lockout`, `kerberoast`, `asrep_roast`, `log_cleared`, `priv_group`, `new_account`

#### Sysmon

[KOD]
- Office kaynaklı komut kabuğu
- Betik yorumlayıcısından komut kabuğu
- kodlanmış PowerShell
- şüpheli PowerShell komutları
- şüpheli DNS sorguları / `.onion`
- başlangıç klasöründe dosya oluşturma
- otomatik başlatma kayıt anahtarı değişikliği
- LSASS erişimi / uzak iş parçacığı / süreç manipülasyonu

#### Identity

[KOD]
- envanter içe aktarma
- yetki ilişkileri modeli
- doğrulanmış grup üyeliği kanıtları
- User 360
- risk bağlamı
- davranış zaman çizelgesi

### 10) Kısa doğrulama özeti

[LAB]
- OPNsense engel testleri Dashboard’da görüldü.
- AD grup üyeliği değişiklikleri kimlik bölümünde görüldü.
- WIN01 Sysmon kuralları canlı alarm üretti.
- User 360 ve risk bağlamı doğrulandı.
- DNS akışında kaynak bilgisayar yorumu dikkatli şekilde ele alındı.

## Hızlı başlangıç (gerçek repo içinde)

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:SOC_DASHBOARD_USER = "<ornek-kullanici>"
$env:SOC_DASHBOARD_PASSWORD = "<ornek-parola>"
$env:SOC_INGEST_TOKEN = "<ornek-token>"
$env:AEGIS_MITRE_V2 = "1"
$env:SOC_OLLAMA_MODEL = "qwen3:4b-instruct"

uvicorn app.main:app --host 0.0.0.0 --port 8088 --log-level info --access-log
```

## Bilinen kısıtlar

- [KOD] AEGIS otomatik müdahale yapmaz; sadece izler, ilişkilendirir ve gösterir.
- [KOD] Unbound blocklist kararı mevcut collector ile henüz tam “verified DNS block” olarak taşınmıyor.
- [LAB] WIN01 bazı eski kayıtlarda `.100`, bazı kayıtlarda `.101` olarak geçti; yeniden kurulumda güncel lease kontrol edilmelidir.
- [LAB] OPNsense’in tam sürümü, tüm WAN eşlemeleri ve tam kural exportu ayrıca güncel config’ten çıkarılmalıdır.

## Repo içeriği

- `README.md` / `README.tr.md`
- `docs/lab-build-walkthrough.md`
- `docs/architecture.md`
- `docs/opnsense-setup.md`
- `docs/active-directory-setup.md`
- `docs/blocklists.md`
- `docs/detections.md`
- `docs/data-flow.md`
- `docs/screenshots/README.md`

## Lisans ve proje notu

<!-- TODO: varsa mevcut depo lisans dosyasının adını ve koşullarını belirt. -->

[LAB] Bu proje kişisel SOC laboratuvarı olarak geliştirildi; amaç hem teknik doğrulama hem de portföy düzeyinde somut güvenlik mühendisliği çıktısı ortaya koymaktı.
