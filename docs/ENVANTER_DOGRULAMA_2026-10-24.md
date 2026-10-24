# AEGIS SOC — Güncel Statik Envanter (24 Ekim 2026)

> **Kaynak:** Kullanıcının `AEGIS_Envanter.zip` arşivindeki `envanter.json`. Raporda kaynak kod gövdeleri, environment değişkeni değerleri, test sonuçları veya canlı API OpenAPI çıktısı yok. **Bu, kodun düzgün çalıştığının onayı değildir.**

- Envanter zaman damgası (UTC): `2026-10-24T03:33:42.545788+00:00`
- Tarama kapsamındaki dosya sayısı: **67**
- Python dosyası: **59**
- Çeşitli sürümler ve yedekler dahil route kayıtları: **150**
- `app/main.py` içinde benzersiz tanımlar: **25**
- `data/soc.sqlite3-wal` büyük dosya olduğu için taranmamıştır; kesinlikle GitHub'a eklenmemelidir.

## Aktif proje altındaki modüller (AST gözlemi)

| Dosya | Fonksiyon/sınıf örnekleri | Kanıt seviyesi |
|---|---|---|
| `app/ad_intelligence.py` | `dt`, `hit`, `load`, `detect`… | AST okunabildi |
| `app/ad_security.py` | `_date`, `overview` | AST okunabildi |
| `app/ad_selected_analysis_v3.py` | `identity`, `analyze_selected` | AST okunabildi |
| `app/aegis_mitre/__init__.py` |  | AST okunabildi |
| `app/aegis_mitre/context.py` | `basename`, `norm_path`, `_d`, `lineage_detections`… | AST okunabildi |
| `app/aegis_mitre/engine.py` | `_hit`, `calculate_risk`, `verdict_for`, `_analyze`, `_Fields`, `ProcessTracker`… | AST okunabildi |
| `app/aegis_mitre/normalize.py` | `light_clean`, `normalize`, `shannon_entropy`, `prefixes`, `Layer`, `Deobfuscation`… | AST okunabildi |
| `app/aegis_mitre/rules.py` | `_r`, `Rule` | AST okunabildi |
| `app/aegis_mitre/test_engine.py` | `ev`, `enc`, `ids`, `T` | AST okunabildi |
| `app/alert_investigation.py` | `_parsed`, `_alert_id`, `list_alerts`, `analyze_selected` | AST okunabildi |
| `app/event_time.py` | `parse_time`, `_guard_clock`, `occurred_at` | AST okunabildi |
| `app/incident_engine.py` | `_aegis_risk_v2`, `_aegis_grouping_key`, `build_incidents` | AST okunabildi |
| `app/main.py` | `soc_access_control`, `ingest`, `events`, `status`, `SecurityEvent`… | AST okunabildi |
| `app/mitre_adapter.py` | `analyze_process` | AST okunabildi |
| `app/mitre_engine.py` | `analyze_process`, `_decode_encoded_command`, `analyze_process` | AST okunabildi |
| `app/mitre_worker.py` | `initialize`, `process_batch`, `run` | AST okunabildi |
| `app/network_detection.py` | `_networks`, `_event_parsed`, `_port`, `detect_network_patterns` | AST okunabildi |
| `app/parser.py` | `normalize` | AST okunabildi |
| `app/storage.py` | `connect`, `init`, `fingerprint`, `is_alert`… | AST okunabildi |
| `app/sysmon_detection.py` | `detect_sysmon` | AST okunabildi |
| `app/sysmon_engine.py` | `parse_sysmon`, `build_process_tree` | AST okunabildi |

## Aktif `app/main.py` API rotaları

| Metot | Yol | Handler |
|---|---|---|
| POST | `/api/events/ingest` | `ingest` |
| GET | `/api/events` | `events` |
| GET | `/api/status` | `status` |
| GET | `/api/summary` | `summary` |
| GET | `/api/incidents` | `incidents` |
| GET | `/api/ai/status` | `ai_status` |
| GET | `/api/investigation/alerts` | `aegis_investigation_alerts` |
| POST | `/api/investigation/alerts/analyze` | `aegis_investigation_analyze` |
| GET | `/api/network/detections` | `aegis_network_detections` |
| POST | `/api/incidents/analyze` | `analyze_incident` |
| POST | `/api/ai/analyze` | `legacy_ai` |
| GET | `/` | `dashboard` |
| GET | `/api/ad/overview` | `ad_overview` |
| GET | `/api/ad/intelligence` | `ad_intelligence_overview` |
| POST | `/api/ad/analyze` | `ad_intelligence_analyze` |
| GET | `/api/ad/report` | `ad_report` |
| GET | `/api/sysmon/investigation` | `sysmon_investigation` |
| POST | `/api/sysmon/analyze` | `sysmon_ai_analyze` |
| GET | `/dashboard-v2` | `dashboard_v2` |
| GET | `/api/source-health` | `source_health` |
| GET | `/api/mitre/summary` | `aegis_mitre_summary` |
| GET | `/api/mitre/detections` | `aegis_mitre_detections` |
| POST | `/api/sysmon/correlation` | `aegis_sysmon_correlation` |
| POST | `/api/sysmon/correlation-ai` | `aegis_correlation_ai_v2` |
| POST | `/api/ad/analyze-selected` | `ad_analyze_selected_v3` |

## Dikkat edilmesi gerekenler

- Önceki dokümanlarda yalnızca 16 API rotası vardı. Bu envanter artık Investigation, Network, MITRE, Source Health, Correlation ve Selected AD Analysis rotalarının **kaynakta tanımlı** olduğunu gösteriyor.
- `soc_access_control` adlı fonksiyonun AST imzası var. Güncel yetkilendirme güvenliği, decorator/middleware akışı ve istek kontrolleri kodun tamamı incelenmeden doğrulanamaz.
- `app/aegis_mitre/test_engine.py` mevcut; bu dosyanın varlığı güncel testlerin başarılı olduğu anlamına gelmez.
- `app/storage.py` içinde `fingerprint` ve `get_sysmon_chain` gibi isimler var; işleyiş ve güvenlik için kaynak kodu gerekir.
- Yedekler (`.aegis_patch_backups/`, `rollback_safety_*`, `backups/`, `dashboard_backup_*`, `main_turkce_yedek.py`) aktif sürümün yerine kullanılmamalı; GitHub dağıtımına eklenmemeli.
- 32 saldırı senaryosunun tamamı doğrulanmadı. ICMP alarm satırları tek akışta tekrar ediyor olabilir.
- Envanterden üretilen SHA-256 özetleri kaynak dosyaların hash'leridir; yazılım tedarik zinciri doğrulaması veya güvenlik taraması yerine geçmez.

## Kaynak doğrulaması için sıradaki testler

1. Çalışan servisten **salt-okunur** `GET /openapi.json` ile aktif route listesi alın.
2. Ana modüllerin kod gövdelerinde güvenlik ve secret taraması yapın.
3. `SOC_INGEST_TOKEN` ve `soc_access_control` etkileşimini yetkisiz istekler gönderilmeden önce yerel test ortamında inceleyin.
4. Ayrılmış test ortamında birim testleri ve 32 senaryoyu tekrar çalıştırın.
5. Yalnızca maskelenmiş gerçek ekran görüntülerini ve doğrulanmış sonuçları genel README'ye taşıyın.
