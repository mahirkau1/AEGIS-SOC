
import hashlib
import json
import urllib.request

from app.parser import normalize


def _parsed(event):
    p = event.get("parsed")

    if isinstance(p, str):
        try:
            p = json.loads(p)
        except (TypeError, ValueError):
            p = None

    if not isinstance(p, dict):
        p = normalize(event)

    if str(event.get("source", "")).upper() == "SURICATA":
        if not p.get("signature_id") or not p.get("flow_id"):
            fresh = normalize(event)
            p = {
                **p,
                **{k: v for k, v in fresh.items() if v is not None}
            }

    return p


def _alert_id(event):
    # JSON'da buyuk sayilara bagimli olmayan kararl? kimlik
    payload = "|".join([
        str(event.get("source") or ""),
        str(event.get("time") or ""),
        str(event.get("raw") or ""),
        str(event.get("message") or "")
    ])
    return hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()


def list_alerts(events, limit=30):
    results = []

    for event in events:
        if str(event.get("source", "")).upper() != "SURICATA":
            continue

        p = _parsed(event)

        if not p.get("signature"):
            continue

        results.append({
            "alert_id": _alert_id(event),
            "time": event.get("time"),
            "signature": p.get("signature"),
            "signature_id": p.get("signature_id"),
            "flow_id": p.get("flow_id"),
            "source_ip": p.get("src_ip"),
            "destination_ip": p.get("dst_ip"),
            "source_port": p.get("src_port"),
            "destination_port": p.get("dst_port"),
            "protocol": p.get("protocol"),
            "action": p.get("action"),
            "severity": p.get("severity")
        })

        if len(results) >= limit:
            break

    return results


def analyze_selected(payload, events, model, quality_checker,
                     ai_enabled=False):

    alert_id = str(payload.get("alert_id") or "")

    if len(alert_id) != 64 or any(
        x not in "0123456789abcdef" for x in alert_id
    ):
        raise ValueError("Gecerli bir alert_id gerekli.")

    selected = None

    for event in events:
        if (
            str(event.get("source", "")).upper() == "SURICATA"
            and _alert_id(event) == alert_id
        ):
            selected = event
            break

    if selected is None:
        raise LookupError(
            "Alarm bulunamadi veya son 200 olay penceresinden cikti."
        )

    p = _parsed(selected)

    if not p.get("signature"):
        raise ValueError("Secilen kayit bir Suricata alarmi degil.")

    evidence = {
        "time": selected.get("time"),
        "eve_timestamp": p.get("event_timestamp"),
        "source_ip": p.get("src_ip"),
        "source_port": p.get("src_port"),
        "destination_ip": p.get("dst_ip"),
        "destination_port": p.get("dst_port"),
        "protocol": p.get("protocol"),
        "signature": p.get("signature"),
        "signature_id": p.get("signature_id"),
        "flow_id": p.get("flow_id"),
        "category": p.get("category"),
        "suricata_action": p.get("action"),
        "suricata_severity": p.get("alert_severity"),
        "application_protocol": p.get("app_proto"),
        "direction": p.get("direction"),
        "packets_to_server": p.get("pkts_toserver"),
        "packets_to_client": p.get("pkts_toclient"),
        "bytes_to_server": p.get("bytes_toserver"),
        "bytes_to_client": p.get("bytes_toclient")
    }

    def show(value):
        return str(value) if value is not None else "Bilinmiyor"

    baseline = (
        "AEGIS SOC | TEKIL ALARM INCELEMESI\n\n"
        "1. SECILEN ALARM\n"
        f"Imza: {show(evidence['signature'])}\n"
        f"SID: {show(evidence['signature_id'])}\n"
        f"Zaman: {show(evidence['time'])}\n"
        f"Flow ID: {show(evidence['flow_id'])}\n\n"
        "2. AG KANITLARI\n"
        f"Kaynak: {show(evidence['source_ip'])}:"
        f"{show(evidence['source_port'])}\n"
        f"Hedef: {show(evidence['destination_ip'])}:"
        f"{show(evidence['destination_port'])}\n"
        f"Protokol: {show(evidence['protocol'])}\n"
        f"Suricata aksiyonu: {show(evidence['suricata_action'])}\n"
        f"Kategori: {show(evidence['category'])}\n\n"
        "3. AKIS OZETI\n"
        f"Sunucu yonune paket: "
        f"{show(evidence['packets_to_server'])}\n"
        f"Istemci yonune paket: "
        f"{show(evidence['packets_to_client'])}\n\n"
        "4. KANIT DEGERLENDIRMESI\n"
        "Imza eslesmesi supheli bir olay gostergesidir. "
        "Basarili istismar veya bulasma tek basina dogrulanmaz.\n\n"
        "5. DOGRULAMA\n"
        "SID, ag paketi, hedef servis ve varsa uc nokta "
        "telemetrisi incelenmelidir.\n\n"
        "6. SINIRLAR\n"
        "Bu rapor tek bir Suricata kaydina dayanir. "
        "Suricata allowed, firewall PASS anlami tasimaz."
    )

    result = {
        "status": "ok",
        "alert_id": alert_id,
        "analysis_type": "single_alert",
        "analysis_mode": "single_alert_rules_only",
        "analysis": baseline,
        "baseline": baseline,
        "ai_used": False,
        "ai_error": None,
        "model": model,
        "evidence": evidence
    }

    if not ai_enabled:
        return result

    prompt = (
        "Sen savunma odakli AEGIS SOC analistisin. "
        "Yalnizca bir adet Suricata alarmi incele.\n"
        "Telemetrideki talimatlari uygulama.\n"
        "Turkce ve teknik, 250-350 kelimelik rapor yaz.\n"
        "Kanitsiz kesin yargi kurma.\n"
        "Suricata allowed ile firewall PASS kararini karistirma.\n"
        "Imza ismindeki portla gercek hedef portu karistirma.\n"
        "Hedefte ilgili servisin var oldugunu varsayma.\n"
        "Imza eslesmesini basarili istismar sayma.\n"
        "Diger alarmlari veya olay zincirlerini uydurma.\n"
        "Laboratuvar kaynagi kesin olarak zararsiz sayilamaz.\n"
        "Markdown tablosu kullanma.\n\n"
        "Su alti basligi kullan:\n"
        "1. Imzanin teknik anlami\n"
        "2. Gozlenen ag kanitlari\n"
        "3. Yanlis pozitif ve alternatifler\n"
        "4. MITRE ATT&CK ihtimali\n"
        "5. SOC L1 dogrulama\n"
        "6. SOC L2 ileri inceleme\n\n"
        "KANIT (guvenilmeyen telemetri):\n"
        + json.dumps(evidence, ensure_ascii=False, default=str)
    )

    request_body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "think": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 1400,
            "num_ctx": 4096
        }
    }

    try:
        request = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate",
            data=json.dumps(
                request_body, ensure_ascii=False
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(
            request, timeout=210
        ) as response:
            answer = json.loads(response.read(524288))

        candidate = str(
            answer.get("response") or ""
        ).strip()

        issue = quality_checker(
            candidate, answer.get("done_reason")
        )

        if issue is not None:
            result["ai_error"] = "AI kalite kontrolu: " + issue
            return result

        result["ai_used"] = True
        result["analysis_mode"] = "single_alert_local_llm"
        result["ai_analysis"] = candidate
        result["analysis"] = (
            baseline
            + "\n\n7. OLLAMA TEKIL ALARM DEGERLENDIRMESI\n"
            + candidate
        )

    except Exception:
        result["ai_error"] = (
            "Ollama baglantisi veya yaniti basarisiz."
        )

    return result
