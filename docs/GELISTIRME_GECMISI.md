# Geliştirme Geçmişi (Kanıtla Sınırlı)

Buradaki tarihler geçmiş sohbet/PowerShell çıktılarında raporlanan çalışma zamanlarıdır; **Git commit geçmişi yerine geçmez**. Tam değişiklik dosyası listesi ve rollback için gerçek repository diff/commit geçmişi incelenmelidir.

| Dönem | Raporlanan çalışma | Kaynak / etkilenen modüller | Test kanıtı | Bilinen sorun / geri dönüş |
|---|---|---|---|---|
| Eylül 2026 | DC01 Active Directory, WIN01 domain join, OPNsense ağ segmentleri | Windows/OPNsense konfigürasyonları | Domain login ve ping gözlemleri | VM snapshot / sistem yedeği geçmişi teyitsiz |
| 10.10.2026 | Kali → OPNsense → Suricata/Firewall → SOC aktarımı ve 10 ağ testi | Kali collector, parser, API | Çeşitli testlerin SOC'a ulaştığı raporu | Kural tespiti ile log alımı ayrı |
| 11–12.10.2026 | WIN01 Sysmon Event 3 ve DC01 4776 | Sysmon/AD, SOC UI | Olay kayıtları görüldü | Brute-force korelasyonu o aşamada teyitsiz |
| 15–18.10.2026 | Dashboard, AD Intelligence, MITRE V2 iterasyonları | `main.py`, `index.html`, ilgili Python modülleri | Route ve modül taraması; 21/21 MITRE V2 test raporu | Güncel kaynak diff'i eksik; çok sayıda tarihli yedek var |
| 20–21.10.2026 | AD yönetim olayları ve görünüm gereksinimleri | AD kuralları, UI | 4720/4728/4738/4724/4726 üzerine çalışma bildirildi | 4729, 5145/4656, görünür alarm temizleme davranışı tamamlanmadı |
| 24.10.2026 | 32 Kali testi sonrası olay örneklemi | Suricata, Firewall, Sysmon, AD | 1.000 kayıt dağılımı ve ICMP imzaları | 32/32 algılama sonucu bilinmiyor |
| 24.10.2026 | **Bu belge paketi** | Yalnız Markdown, güvenli örnek yapılandırma ve okuma amaçlı audit scripti | Paket içi link/şema statik kontrolü | Kaynak kod ve canlı UI erişimi yok |

## Rollback / değişiklik sınırı

Bu belge görevi sırasında uygulama dosyaları veya veri tabanı değiştirilmedi. Geri alma, bu oluşturulan ayrı dokümantasyon klasörünü kaldırmaktan ibarettir. Mevcut tarihli `main_before_*`, `*_backup*` dosyalarını **silme/taşıma önerilmedi**; önce hangi sürümün aktif olduğu doğrulanmalı.

## Devralma notu

Yeni geliştirme oturumuna başlamadan [Proje Durumu](PROJE_DURUMU.md), [Yol Haritası](YOL_HARITASI.md) ve gerçek repo envanterini birlikte okuyun. Özellikle **Identity · AD Intelligence** için 4729, yetkisiz paylaşıma erişim testleri ve görünümden gizlenen olayların SQLite'da korunması başlıkları unutulmamalıdır.
