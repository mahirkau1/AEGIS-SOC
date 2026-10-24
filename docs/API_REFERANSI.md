# FastAPI Referansı — Kaynak İmzaları ve İlk Kod Anlık Görüntüsü

> **Sürüm:** Önceki kod anlık görüntüsü ve 24.10.2026 AST tabanlı dosya envanteri. **Aktif servisin güncel OpenAPI şeması değildir.** Route'lar, metodlar ve kodda açıkça görülen parametreler aşağıdadır. Yanıt alanları görülemeyen modüller için uydurulmamıştır.

## Genel bilgiler

- Örnek yerel adres: `http://127.0.0.1:8088` (önceki laboratuvar kurulumu).
- `POST /api/events/ingest` için eski kodda **yalnızca** `SOC_INGEST_TOKEN` dolu olduğunda `X-SOC-Token` başlığı kontrol edilir; boş anahtar güvenli kabul edilmemelidir.
- İstemci arayüz route'ları için kullanıcı girişi/RBAC varlığı incelenen kodda görülmedi. Reverse proxy veya ağ sınırı gerekiyorsa ayrıca doğrulanmalı.
- `GET /api/health` incelenen route listesinde **yok**.
- Bu referans yeni route oluşturmaz.

## Route envanteri

| HTTP | Yol | Amaç | Parametre / istek | Kanıtlanan yanıt veya önemli durum |
|---|---|---|---|---|
| POST | `/api/events/ingest` | Olay kabulü | `SecurityEvent` JSON; opsiyonel `X-SOC-Token` | `status=accepted|duplicate`; yanlış tanımlı token için 401 |
| GET | `/api/events` | Kayıt sorgu | `limit=100`, `offset=0`, `mode=alerts` | `storage.get_events` çıktı dizisi; mode `alerts|all|blocks` |
| GET | `/api/status` | Kaynak durumu | Parametre yok | `status`, `time`, `components`; Ollama `check-separately` |
| GET | `/api/summary` | Dashboard sayaçları | Parametre yok | `total_events`, `total_alerts`, `critical_alerts`; bazı skor alanları `null` |
| GET | `/api/incidents` | Vaka listesi | Parametre yok | `count`, `incidents`; son 200 alarm üzerinden örnek kod |
| GET | `/api/ai/status` | Ollama modeli kontrolü | Parametre yok | `online`, `model_ready`, `model` |
| POST | `/api/incidents/analyze` | Vaka inceleme | `incident_id` isteğe bağlı JSON | `status`, `analysis`; bilinmeyen ID için 404 |
| POST | `/api/ai/analyze` | Eski AI route | Parametre yok | Eski kodda vaka analizi çağrısına köprü |
| GET | `/` | Ana dashboard | Parametre yok | `templates/index.html`, `text/html` |
| GET | `/api/ad/overview` | AD özet | `limit=1000` | `ad_security.overview(limit)`; yapı kodda görülmedi |
| GET | `/api/ad/intelligence` | AD intelligence | `limit=2000` | `ad_intelligence.overview(limit)`; yapı kodda görülmedi |
| POST | `/api/ad/analyze` | AD AI inceleme | Gövde parametresi kodda yok | `analyze_with_ai(overview(2000), MODEL)` |
| GET | `/api/ad/report` | AD raporu | Parametre yok | `text/markdown; charset=utf-8` |
| GET | `/api/sysmon/investigation` | Sysmon Process Tree | `limit=200`, kod içinde 1–200 ile sınır | `processes`, `network`, `dns`, `scanned_events`, `sysmon_events` (kısmen kodda görünür) |
| POST | `/api/sysmon/analyze` | Seçili process AI/rules | JSON: `host`, `process_guid` | 400 eksik alan; 404 process yok; `mode=local_llm|rules` |
| GET | `/dashboard-v2` | Eski dashboard | Parametre yok | HTML `FileResponse`; eski sürümde hard-coded mutlak yol |

**Güncelleme:** Statik envanterde yeni MITRE, Network, Investigation ve Identity rotaları görülmüştür; aşağıdaki ek tabloda listelenmiştir. Parametre ve yanıt şemaları kaynak gövdelerden doğrulanmamıştır. Gerçek OpenAPI: çalışan serviste `GET /openapi.json` çağrısı ve güncel `app/` kodu ile karşılaştırılmalı.

## `SecurityEvent` istek modeli (koddan)

```json
{
  "source": "SURICATA",
  "message": "Ornek imza / ozet",
  "severity": "medium",
  "host": "opnsense",
  "raw": "Ornek test verisi"
}
```

- `source`: metin, en fazla 40 karakter, zorunlu.
- `message`: metin, en fazla 8.000 karakter, zorunlu.
- `severity`: metin, varsayılan `info`.
- `host`: metin, varsayılan `unknown`.
- `raw`: metin, varsayılan boş, en fazla 20.000 karakter.
- `time`, `parsed` alanlarını API oluşturur (eski kod sürümünde).
- Genel FastAPI/Pydantic doğrulama hataları için 422 beklenebilir; **gerçek davranış canlı sürümde sınanmadı**.

## Örnek yanıtlar (kodun gösterdiği düzeyde)

`POST /api/events/ingest`:

```json
{"status":"accepted"}
```

Aynı eski kayıt yeniden eklenirse `{"status":"duplicate"}` dönebilir. Bu sonuç, dedup anahtarını açıklamaz.

`GET /api/incidents`:

```json
{"count":0,"incidents":[]}
```

Bu yalnızca mümkün **boş sonuç biçimidir**, üretim ölçümü değildir.

## Endpoint doğrulama kontrolü

| Kontrol | Beklenen işlem | Sonuç |
|---|---|---|
| `/openapi.json` ile route diff | Sadece okuma, güncel route'ları doğrula | ÇALIŞTIRILMADI |
| `/api/status` | HTTP erişimi, stale source uyarısı | ÖNCEKİ KODDAN İNCELENDİ |
| `/api/events?limit=5&mode=all` | Dönen alanları incele | OLAY AKIŞI LABDA GÖRÜLDÜ |
| Giriş token testi | Yetkisiz istek 401 mi? | YAPILMADI; üretim öncesi gerekli |
| AI response validation | Zaman aşımı/fallback | KOD ANLIK GÖRÜNTÜSÜ VAR, CANLI TEST YOK |

## 24 Ekim 2026'da statik envanterde görülen ek rotalar

> **Statü:** Sadece AST ile metod/yol/fonksiyon adı doğrulandı. Aşağıdaki amaçlar **fonksiyon adından çıkarımdır**; parametreler, authorization ve yanıt formatı için kanıt yoktur.

| Metot | Yol | Handler | Parametre / yanıt |
|---|---|---|---|
| GET | `/api/investigation/alerts` | `aegis_investigation_alerts` | Doğrulanmadı |
| POST | `/api/investigation/alerts/analyze` | `aegis_investigation_analyze` | Doğrulanmadı |
| GET | `/api/network/detections` | `aegis_network_detections` | Doğrulanmadı |
| GET | `/api/source-health` | `source_health` | Doğrulanmadı |
| GET | `/api/mitre/summary` | `aegis_mitre_summary` | Doğrulanmadı |
| GET | `/api/mitre/detections` | `aegis_mitre_detections` | Doğrulanmadı |
| POST | `/api/sysmon/correlation` | `aegis_sysmon_correlation` | Doğrulanmadı |
| POST | `/api/sysmon/correlation-ai` | `aegis_correlation_ai_v2` | Doğrulanmadı |
| POST | `/api/ad/analyze-selected` | `ad_analyze_selected_v3` | Doğrulanmadı |

Ayrıntılı modül ve route imzaları: [24 Ekim statik envanter özeti](ENVANTER_DOGRULAMA_2026-10-24.md).
