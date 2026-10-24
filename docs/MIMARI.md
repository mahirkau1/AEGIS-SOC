# AEGIS SOC — Mimari

> İşaretler: **Gözlendi (K1/K5)**, **Kodda var (K1/K2)**, **Teyit bekliyor**. Kanıt referansları için [Proje Durumu](PROJE_DURUMU.md).

## 1. Mevcut laboratuvar mimarisinin izlenebilen kısmı

```mermaid
flowchart LR
  subgraph Kaynaklar["Telemetri kaynakları"]
    O["OPNsense Firewall"]
    S["Suricata IDS"]
    A["Active Directory Security"]
    W["Windows Sysmon"]
  end
  O --> COL["Syslog / collector"]
  S --> COL
  COL --> ING["FastAPI: /api/events/ingest"]
  A -. "aktarım yöntemi tam incelenmedi" .-> ING
  W -. "aktarım yöntemi tam incelenmedi" .-> ING
  ING --> P["app.parser.normalize"]
  P --> ST["app.storage.insert"]
  ST --> DB[("Olay deposu: SQLite olarak raporlandı")]
  DB --> R["API sorguları"]
  R --> UI["Dashboard"]
  R --> IN["app.incident_engine.build_incidents"]
  IN -. "opsiyonel ek yorum" .-> LLM["Local Ollama"]
```

**Açıklama:** Firewall ve Suricata'nın collector yoluyla geldiği laboratuvar testlerinde gözlendi. AD/Sysmon endpoint'e ulaşmış olsa da her iletim ayağının güncel konfigürasyonu burada teyit edilmedi. Depolama motorunun gerçek DDL'i henüz okunamadı.

## 2. Bilinen modül bağımlılıkları

```mermaid
flowchart TD
  M["app/main.py"] --> PA["app/parser.py: normalize"]
  M --> ST["app/storage.py"]
  M --> IE["app/incident_engine.py"]
  M --> ADS["app/ad_security.py: overview"]
  M --> ADI["app/ad_intelligence.py: overview / AI / report"]
  M --> SY["app/sysmon_engine.py: build_process_tree"]
  M --> H["app/templates/index.html"]
  M -. "daha yeni sürüm, doğrulanmalı" .-> MT["app/mitre_engine.py"]
  MT -. "entegrasyon incelemesi bekliyor" .-> V2["app/aegis_mitre/"]
  WD["app/mitre_worker.py"] -. "aktif worker durumu belirsiz" .-> V2
```

**Açıklama:** Düz çizgiler eski `main.py` içinde görülebilen import/çağrıları, kesikli çizgiler daha sonraki dosya taramalarından raporlanan fakat **bu oturumda dosya içerikleri incelenemeyen** bağlantıları gösterir. `network_detection.py`, `mitre_adapter.py`, `alert_investigation.py` ve `aegis_ux_v3.*` için güncel import zinciri belirsiz.

## 3. Olay işleme (kod anlık görüntüsü)

```mermaid
flowchart TD
  X["SecurityEvent isteği"] --> TK{"SOC_INGEST_TOKEN dolu mu?"}
  TK -->|Evet| CH{"X-SOC-Token eşleşiyor mu?"}
  CH -->|Hayır| ERR["401"]
  CH -->|Evet| N["Kaynak/seviye normalizasyonu"]
  TK -->|Hayır| N
  N --> PA["normalize(item)"]
  PA --> DB["storage.insert(item)"]
  DB --> D{"Kayıt yeni mi?"}
  D -->|Evet| OK["status: accepted"]
  D -->|Hayır| DUP["status: duplicate"]
```

**Açıklama:** Buradaki kimlik doğrulama kapısının token boş olduğunda atlanması **güvenlik değerlendirmesi gerektirir**. Veritabanında dedup anahtarının ne olduğu `storage.py` incelenmeden yazılamaz.

## 4. Olay inceleme

```mermaid
flowchart LR
  EVT["Olaylar"] --> CR["build_incidents: korelasyon örneği"]
  CR --> CH["Analist vaka seçer"]
  CH --> EV["Kayıtlar ve kanıtlı temel rapor"]
  EV --> OPT{"SOC_AI_EXTRA=1?"}
  OPT -->|Hayır| REP["Temel rapor"]
  OPT -->|Evet| O["Ollama ek yorum denemesi"]
  O --> REP
  REP --> HUM["Analist karar / doğrulama"]
```

**Açıklama:** AI sonucunun temel rapordan ayrı tutulması eski `main.py` sürümünde düşünülmüştür. Bu akış, nihai insan onayı veya resmi vaka yönetimi otomasyonunun uygulanmış olduğunu göstermez.

## 5. Laboratuvar ağ görünümü (adresler genelleştirildi)

```mermaid
flowchart TD
  F["OPNsense: ağ geçidi, filtreleme, Suricata"]
  U["USERS VLAN / WIN01"] --> F
  D["SERVERS VLAN / DC01"] --> F
  K["KALI VLAN / kontrollü test makinesi"] --> F
  F --> C["Collector / Syslog"]
  C --> S["SOC FastAPI / Dashboard"]
  U -. "Sysmon olayları" .-> S
  D -. "AD olayları" .-> S
```

**Açıklama:** Geçmiş laboratuvar notlarında em2 USERS, em3 SERVERS, em5 KALI olarak geçiyor. IP'ler GitHub belgelerinde isteğe bağlı olarak maskelenmeli. Bağlantılar ayrıntılı paket topolojisi değil, işlevsel veri akışı şemasıdır.

## 6. Tespit ve korelasyon (onaylanan kod parçaları)

```mermaid
flowchart LR
  N["Normalleştirilmiş olaylar"] --> F{"Suricata / Firewall sinyali"}
  F --> G["build_incidents()"]
  G --> EV["İmza, port, eylem, kaynak/hedef kanıtları"]
  EV --> RS["Başlangıç risk sınıfı"]
  RS --> O["Vaka özeti"]
  N -. "V2 entegrasyon kontrolü gerekli" .-> M["MITRE analizi"]
```

**Açıklama:** Kod parçaları `suricata_alerts`, `firewall_blocks`, `ports`, `signatures` alanlarına işaret ediyor. Tam eşikler ve MITRE eşleştirmeleri okunamadığı için diyagramda algoritma ayrıntısı icat edilmedi.

## 7. Bileşen düzeyinde inceleme bekleyenler

| Dosya | Tahmini sorumluluk (adına göre; **kanıt değildir**) | Durum |
|---|---|---|
| `app/parser.py` | Olay normalizasyonu (`normalize` çağrısı kanıtlandı) | KISMEN UYGULANDI |
| `app/storage.py` | Yazma/sorgu/stats (`insert`, `get_events`, `stats` çağrısı kanıtlandı) | KISMEN UYGULANDI |
| `app/incident_engine.py` | Vaka çıkarımı (`build_incidents` çağrısı kanıtlandı) | KISMEN UYGULANDI |
| `app/ad_security.py` | AD overview (route import'u mevcut) | UYGULANDI — TEST EDİLMEDİ |
| `app/ad_intelligence.py` | AD analiz/AI/rapor (route import'ları mevcut) | KISMEN UYGULANDI |
| `app/sysmon_engine.py` | Process Tree (route import'u mevcut) | UYGULANDI — TEST EDİLMEDİ |
| `app/sysmon_detection.py` | Ek Sysmon tespitleri | DURUMU BELİRSİZ |
| `app/network_detection.py` | Ağ tespitleri | DURUMU BELİRSİZ |
| `app/alert_investigation.py` | Alarm inceleme | DURUMU BELİRSİZ |
| `app/mitre_adapter.py` | MITRE bağlayıcı | DURUMU BELİRSİZ |
| `app/mitre_engine.py`, `app/mitre_worker.py`, `app/aegis_mitre/` | MITRE V2 | KISMEN UYGULANDI |
| `aegis_ux_v3.css`, `aegis_ux_v3.js` | Ayrık UI assetleri | DURUMU BELİRSİZ |

Tam fonksiyon/sınıf imza envanteri, gerçek güncel repo üzerinden üretilen `proje_envanteri.py` raporu ile tamamlanmalıdır.
