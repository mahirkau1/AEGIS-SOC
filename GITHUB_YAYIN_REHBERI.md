# AEGIS SOC — GitHub'a Güvenli İlk Yayın

> **Bu arşiv yalnızca belgedir.** AEGIS kaynak kodunu, SQLite veritabanını, ham logları, olay envanterini, yerel ekran görüntülerini veya API anahtarlarını içermez. Bu paket için otomatik kaynak kodu yüklemesi yapılmaz.

## 1. Önce özel (Private) bir GitHub repository oluştur

1. https://github.com/new bağlantısını aç.
2. Repository adı: `AEGIS-SOC` (aynı ad mevcutsa başka bir ad).
3. **Private** seç. Başlangıç README / .gitignore / LICENSE kutularını boş bırak; belgeler pakette zaten bulunuyor.
4. `Create repository` düğmesine bas.
5. Yeni deponun `https://github.com/<HESAP>/<DEPO>.git` bağlantısını al.

## 2. Sadece bu dokümanları yükle

Bu ZIP dosyasının içindekileri Masaüstünde temiz bir klasöre çıkart. Sonra PowerShell'de (Git kuruluysa):

```powershell
$release = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AEGIS_SOC_GitHub_Yayin_Hazir_Dokumanlar'
Set-Location $release
git init -b main
git add README.md README_TR.md CONTRIBUTING.md SECURITY.md .gitignore .env.example GITHUB_YAYIN_REHBERI.md docs scripts
git status --short
git diff --cached --name-only
# LISTEYI KONTROL ET: hiçbir gizli veri, kod yedeği, log veya DB olmamalı.
git commit -m 'docs: initial evidence-based AEGIS SOC documentation'
git remote add origin 'https://github.com/<HESAP>/<DEPO>.git'
git push -u origin main
```

> `<HESAP>` ve `<DEPO>` yer tutucularını gerçekten oluşturduğunuz depo bilgileriyle değiştirin. `git` kurulu değilse GitHub web arayüzündeki **Add file → Upload files** aracına, çıkarılmış paketin içeriğini yükleyebilirsiniz; ZIP'i tek dosya olarak yüklemeyin.

## 3. Public yayına geçmeden önce

- [ ] Projenin gerçek kodu secret scanner + elle incelemeden geçti.
- [ ] `SOC_INGEST_TOKEN` ve güncel `soc_access_control` akışı doğrulandı.
- [ ] Log, DB, `.env`, private key ve makineye özel veri Git geçmişinde yok.
- [ ] Hedef IP ve kullanıcı bilgileri maskelendi.
- [ ] Lisans kararı depo sahibince verildi; bu paket lisans seçmez.
- [ ] Kaynak kodu ve README'de iddia edilen test sonuçları ayrılmış test ortamında doğrulandı.

> **Önemli:** Depo Private olarak yayınlandığında kod güvenlik denetimini atlamış olmaz. Public yapmak için GitHub repository **Settings → General → Danger Zone → Change repository visibility** yolunu ancak kontrol listesini tamamladıktan sonra kullanın.
