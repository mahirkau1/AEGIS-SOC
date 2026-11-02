# AEGIS SOC — GitHub yayın öncesi kontrol listesi

> Bu belge paketi **yalnızca dokümantasyon ve kullanıcı tarafından sağlanan görselleri** içerir. Uygulama kodunu, Windows collector'larını, Kali servislerini, `.gitignore` veya `requirements.txt` dosyalarını otomatik olarak değiştirmez.

## 1. Pakette bulunanlar

- [x] `README.md`: tamamen Türkçe ana GitHub vitrini
- [x] `README.tr.md`: Türkçe alternatif giriş dosyası
- [x] `docs/lab-build-walkthrough.md`: VirtualBox'tan Dashboard'a ayrıntılı kurulum hikâyesi
- [x] `docs/architecture.md`: ağ ve güven sınırları
- [x] `docs/opnsense-setup.md`: OPNsense, firewall, Suricata, Unbound ve collector
- [x] `docs/active-directory-setup.md`: DC01, WIN01, GPO, Sysmon ve Identity
- [x] `docs/blocklists.md`: IP ve DNS kara listeleri
- [x] `docs/detections.md`: network, AD, Sysmon ve Identity kuralları
- [x] `docs/data-flow.md`: olay alımı, depolama ve API
- [x] `docs/screenshots/README.md`: **39 görselin tamamının** Türkçe kataloğu
- [x] `scripts/Publish-AegisDocs.ps1`: sınırlı ve yedeklemeli GitHub yayın betiği

## 2. `.gitignore` denetimi

[KOD] Uygulama yerel SQLite ve ortam değişkenleri kullandığından kişisel loglar, tokenlar ve veritabanı dosyaları genel repoya konulmamalıdır. Mevcut `.gitignore` üzerine düşünmeden yazmayın; aşağıdaki kalıpların eksik olup olmadığını kontrol edin.

```gitignore
# Ortam değişkenleri ve sırlar
.env
.env.*
!.env.example
*.key
*.pem
*.pfx
*.p12

# Python ve geliştirme ortamı
.venv/
venv/
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.vscode/
.idea/

# Çalışma zamanı verileri ve özel yedekler
*.sqlite
*.sqlite3
*.sqlite3-wal
*.sqlite3-shm
*.db
*.log
logs/
backups/
data/
output/
*.bak
*.bak_*
```

[LAB] Resmî `.env.example` kullanılıyorsa sadece örnek değerler içermelidir. `git add -f` ile gizlenmiş sırları zorla depoya eklemeyin.

## 3. Bağımlılık kontrolü

[LAB] Proje için belirtilmiş başlıca Python paketleri:

```text
fastapi
uvicorn
pydantic
requests
pyyaml
psutil
python-dotenv
python-multipart
```

Bu bir inceleme listesidir; kurulu sürüm ya da her paketin her dosyada kullanıldığı iddiası değildir. Mevcut `requirements.txt`, uygulamanın kullanılan son kaynak koduyla karşılaştırılmalıdır.

```powershell
# Var olan Git deposunda salt-okunur kontrol
Get-Content .gitignore
Get-Content requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## 4. Gizli bilgileri koruma

```powershell
# Yayın öncesi dosyaları ve boşluk hatalarını denetle
git status --short
git diff --cached --stat
git diff --cached --check

# İncelenmesi gereken şüpheli dosya adlarını listele
Get-ChildItem -Recurse -File -Force |
  Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' -and $_.Name -match '(?i)\.env|token|secret|password|credential|\.sqlite|\.pfx|\.pem' } |
  Select-Object -First 30 FullName
```

[LAB] Gerçek parola/token, özel kimlik SID'leri, ham kullanıcı olay günlükleri veya tam güvenlik duvarı yedeği depoya konulmamalıdır. `198.51.100.77` ayrılmış TEST-NET-2 test adresidir; 10.x ve 192.168.x adresleri laboratuvar özel ağlarını anlatır.

## 5. GitHub görünüm kontrolü

- [ ] `README.md` tamamen Türkçe okunuyor.
- [ ] Mermaid diyagramları GitHub üzerinde hatasız görünüyor.
- [ ] OPNsense, VirtualBox, AD, Sysmon, Identity ve SOC görselleri açılıyor.
- [ ] `docs/screenshots` altında 39 PNG bulunuyor.
- [ ] README ve teknik dokümanlardaki göreli bağlantılar çalışıyor.
- [ ] Son commit yalnızca belgeleri/görselleri güncelliyor; çalışan uygulama dosyalarına dokunmuyor.
- [ ] `LICENSE` dosyası varsa gerçek lisansla uyuşuyor. Yoksa rastgele lisans iddia edilmiyor.

## 6. Proje doğrulama sınırı

| Durum | Açıklama |
|---|---|
| [KOD] Kaynak kodunda görüldü | FastAPI ingest, SQLite WAL, SHA-256, ağ eşikleri, Sysmon V3 kuralları, AD/Identity analizleri |
| [LAB] Canlı laboratuvarda görüldü | Subnet ayrımı, OPNsense engelleri, Kali/Suricata logları, WIN01 Sysmon'un 8 alarmı |
| [LAB] Canlı olarak ayrıca doğrulanmadı | Sysmon ID 8, 10, 25 için yüksek riskli saldırı temelli alarmlar |
| [KOD] Bilinen veri sınırı | Unbound blocklist'in açık karar alanı SOC collector'ından tam gelmiyor |
| TODO | Tam WAN eşlemesi, son firewall UUID dökümü, Suricata modu, DHCP havuzu, feed listesi ve GPO exportu |

## 7. Yeniden kurulum için ek kanıt gerektiren bilgiler

1. OPNsense'in güncel sürümü ve WAN/em0/em1 adaptör eşlemesi.
2. KEA DHCP adres havuzları ve Unbound yönlendirme ayarları.
3. Firewall kurallarının sıralı dökümü, alias adları ve PF UUID listesi.
4. IP/DNS blocklist besleme kaynakları ve güncelleme periyotları.
5. Suricata'nın IDS/IPS modu, aktif arayüz ve kural kategorileri.
6. GPO denetim alt kategorileri ve grup yetkilerinin gizli bilgilerden arındırılmış dökümü.
7. Host başına güncel Sysmon XML ve collector çalışma şekli.
8. Yayınlanan kod sürümüyle `requirements.txt`, `LICENSE` ve son test raporunun eşleşmesi.

**Bu liste, laboratuvarın çalışmadığını değil, aynı ortamı bağımsız biçimde birebir yeniden kurmak için hangi ek kanıtlara ihtiyaç duyulduğunu gösterir.**
