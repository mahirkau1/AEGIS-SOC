# Dashboard Kullanım Kılavuzu — Önceki HTML Sürümü

> Kullanım adımları önceki oturumda erişilebilen `index.html` kaynak anlık görüntüsündeki menü/JS fonksiyonlarına dayanır. Güncel `aegis_ux_v3.*` dosyaları ve aktif tarayıcı ekranı incelenemedi. **Ekranların bu biçimde çalıştığı henüz canlı UI testi değildir.**

## Genel akış

1. Yerel SOC adresini yalnızca yetkili laboratuvar ağında açın.
2. `API ONLINE` göstergesini ve kaynak durumunu kontrol edin; bu göstergenin son log tazeliği ile aynı olmadığını unutmayın.
3. Olay akışında kaynak, host ve EventID filtreleriyle kanıtı bulun.
4. Gerekirse Suricata/Firewall vaka listesi veya AD/Sysmon grafiği üzerinden ilişkiyi inceleyin.
5. AI yorumlarını ayrı değerlendirin; gerçek işlem sonucu için host ve ağ kaydını doğrulayın.

## Ekranlar (eski HTML'den)

| Ekran | Amaç ve gösterilen veri | API / fonksiyon | Kullanıcı etkileşimi | Açık inceleme |
|---|---|---|---|---|
| Security Command Center (`overview`) | Toplam olay, alarm, kaynak durumu | `/api/summary`, `/api/status`; `refresh()` | Yenile | Gerçek health freshness, skor alanları |
| Unified Event Explorer (`events`) | Olay akışı, severity, kaynak/hedef, EventID | `/api/events?limit=200&mode=...`; `renderEvents()` | Metin arama, mode, host, Sysmon ID, tekrar gruplama | Grup anahtarının false merge riski |
| Identity Threat Intelligence (`ad`) | AD başarısız/başarılı giriş, tespit, MITRE etiketleri | `/api/ad/intelligence`; `renderAD()`, `renderV5()` | Hesap/olay arama, filtre, AI raporu indir | Güncel GPO/rule/AI kapsamı |
| Investigation Graph (`investigate`) | AD source–user–DC–Event bağlantı grafı | `ad.events`; `graphData()`, `draw()`, `showNode()` | Düğüm seç, event türüne göre filtrele | Grafik sadece seçilmiş kayıtlar ve üst limitler |
| Incident Investigation (`incidents`) | İlişkilendirilmiş vakalar ve kanıt raporu | `/api/incidents`, `/api/incidents/analyze`; `renderCases()` | Vaka seç, analiz iste | Kanıt penceresi son 200 alarm |
| Sysmon Process Tree (`sysmon`) | Process parent/child, network ve DNS ilişkisi | `/api/sysmon/investigation`, `/api/sysmon/analyze`; HTML içi `draw()`, `choose()` | Host/sorgu/limit; process seç/analiz | Son 200 olay nedeniyle parent kaydı eksik kalabilir |

## Kimlik olaylarında kontrol sırası

AD olayında kullanıcı/host/kaynak/timestamp üzerinde filtre yapın. Eski UI `renderADRows()` olayları metin ve `kind` filtresine göre gösterir. `renderV5()` tespitleri, MITRE verilerini ve önerilen playbook'ları listeler. **Bir playbook'un UI'da görünmesi otomatik müdahale yürütüldüğü anlamına gelmez.**

## Grafikler ve kullanılabilirlik

- Investigation Graph eski scriptte ilk 80 AD olayını filtreler, ardından kaynak/hesap/DC/Event düğümlerine üst limit uygular. Grafiğin eksik olması telemetri eksikliği kanıtı değildir.
- Sysmon grafiği kullanıcı, komut satırı ve üst işlem ilişkisini gösterir; parent verisi sorgu penceresi dışında kalabilir.
- UI eski HTML'de `innerHTML` kullanan alanlara sahip; escape fonksiyonları vardır, fakat XSS güvenlik incelemesi tamamlanmadı.
- Önceki HTML'de mobil breakpoints var; gerçek ekran boyutlarında tarayıcı testi yapılmadı.

## Tasarım sistemi — sürüm belirsizliği

Geçmiş taleplerde **yalnız siyah-beyaz-gri** palet istenmiştir. İncelenen HTML sürümünde hem monokrom override'ları hem eski renkli tasarım blokları bulunuyor; daha sonrasında referans tarzı farklı stiller de görülebiliyor. Güncel paleti kesinleştirmek için aktif HTML/CSS sıralaması ve tarayıcı computed style incelenmeli. Bu görev arayüzü **değiştirmedi**.

## Gerçek ekran görüntüleri

Bu oturumda canlı dashboard'a tarayıcı erişimi yoktu; **hiçbir yapay/sahte ekran görüntüsü eklenmedi**. Gerekli ekran/başlık/alt metin listesi için [assets/README.md](assets/README.md) sayfasına bakın.
