# Kurulum ve Çalıştırma (Windows / PowerShell)

> Bu doküman, **kurulu AEGIS SOC kaynak kodunun** bulunduğu makinede güvenli doğrulama içindir. İnceleme paketi uygulamanın kendisini içermez. Güncel Python sürümü, sanal ortam yapısı, doğru başlatma komutu ve bağımlılık dosyasının içeriği görülmediğinden **çalıştırılmamış komutlar doğrulanmış sayılmaz**.

## 1. Ön kontroller (sisteme müdahale etmez)

```powershell
$root = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AD-OPNsense-SOC'
Test-Path $root
Get-ChildItem $root -File | Select-Object Name,Length
Get-ChildItem (Join-Path $root 'app') -File | Select-Object Name,Length
python --version
Get-Command python,py -ErrorAction SilentlyContinue | Select-Object Name,Source
```

Bu yol, varsayılan Masaüstü klasörünü temel alır; gerçek proje konumu farklıysa `$root` güncellenmelidir.

## 2. Giriş noktası ve gereksinimler

```powershell
Get-ChildItem $root -File -Include 'requirements*.txt','pyproject.toml','Pipfile','uv.lock' -Recurse |
  Where-Object { $_.FullName -notmatch '\\.venv\\|\\__pycache__\\' } |
  Select-Object FullName
Select-String -Path (Join-Path $root 'app\main.py') -Pattern 'FastAPI\(|@app\.|uvicorn|app =' |
  Select-Object -First 30 LineNumber,Line
```

Projenin kökündeki doğru bağımlılık dosyası belirlendikten sonra, **yalnızca boş/yeni bir test ortamında** örneğin şu genel Python işlemleri uygulanabilir:

```powershell
# Taslak komutlar — bu kaynak sürümünde ÇALIŞTIRILMADI
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

`requirements.txt` gerçekten mevcut değilse bu son komutu kullanmayın. Çalışan uygulamanın paket ortamı üzerine otomatik yeniden kurulum yapmayın.

## 3. Ortam değişkenleri

Eski `main.py` kodunda `SOC_INGEST_TOKEN`, `OLLAMA_MODEL`, `SOC_AI_EXTRA` ve `SOC_OLLAMA_MODEL` kullanılıyor. Gerçek parolaları, token'ları ve dış bağlantı uçlarını buraya yazmayın. Örnek değerler [.env.example](../.env.example) dosyasındadır; **uygulamanın `.env` dosyasını otomatik okuyup okumadığı doğrulanmadı**.

Örnek varsayılan `SOC_INGEST_TOKEN=''` güvenli değildir; gizli anahtar yapılandırmasını canlı sisteme taşıma şekli ayrıca belirlenmelidir.

## 4. Çalışan hizmeti doğrulama

```powershell
Get-NetTCPConnection -LocalPort 8088 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress,LocalPort,OwningProcess
Invoke-RestMethod 'http://127.0.0.1:8088/api/status'
Invoke-RestMethod 'http://127.0.0.1:8088/api/ai/status'
Invoke-RestMethod 'http://127.0.0.1:8088/api/events?limit=5&mode=all'
```

Bunlar **okuma** istekleridir. Ollama'nın `model_ready=true` olması modelin doğru sonuç verdiğini kanıtlamaz. `GET /api/health` eski listede yer almıyor.

## 5. Uygulamanın başlatılması/durdurulması

Eski `main.py` içinde `app = FastAPI(...)` nesnesi bulunuyor, dolayısıyla genel ASGI örneği `uvicorn app.main:app` olabilir; **gerçek başlangıç betiği/port/host ayarları bilinmediği için burada kopyala-çalıştır komutu verilmez**. Önce mevcut `*.bat`, `*.ps1`, servis tanımları ve süreç komut satırını belirleyin. Daha sonra kontrollü test ortamında doğrulayın.

Çalışan Windows sürecini, Kali collector'ı, Ollama'yı veya MITRE worker'ı durdurmayın. Durdurma yöntemi, gerçek process ownership / service manager doğrulanana kadar `DURUMU BELİRSİZ`.

## 6. Veritabanı hazırlığı

Veritabanı dosyası/şema/migrasyon henüz görülmedi. `sqlite3` oluşturma/migrasyon komutları **verilmez**. İlk iş mevcut yedeği alın ve [Veritabanı](VERITABANI.md) kontrol tablosunu tamamlayın.

## 7. Sık karşılaşılan hatalar

| Belirti | İlk güvenli kontrol | Olası neden (kanıt gerektirir) |
|---|---|---|
| HTTP 404 `/api/health` | `/api/status` sorgulayın | Endpoint yok (eski kod) |
| HTTP 401 ingest | `SOC_INGEST_TOKEN` ve `X-SOC-Token` uygun mu? | Anahtar uyuşmazlığı |
| Gösterge boş | `/api/events?mode=all` ve `limit` | Alarm filtresi, veri gecikmesi |
| AI offline | `/api/ai/status`, Ollama port 11434 | Servis/model yok |
| Sysmon graph boş | Son 200 olayda Sysmon var mı? | Pencere yetersizliği |
| `/dashboard-v2` 500 | Dosya yolu taşınabilir mi? | Eski mutlak Windows yolu |
| Türkçe bozulmuş | Dosya encoding ve HTTP `charset` | Eski dosyalarda mojibake izleri |

## 8. Son durum

Kurulum bu oturumda **çalıştırılmadı**, servis yeniden başlatılmadı. Kanıt toplamak için `python scripts/proje_envanteri.py --root <PROJE_YOLU> --output <CIKTI_KLASORU>` kullanılabilir.
