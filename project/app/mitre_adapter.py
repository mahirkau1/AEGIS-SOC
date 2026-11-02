import os
import logging

from app.mitre_engine import analyze_process as legacy_analyze

LOG = logging.getLogger(__name__)


def analyze_process(event):
    # Varsayilan: mevcut ve calisan eski motor
    if os.getenv("AEGIS_MITRE_V2", "0") != "1":
        return legacy_analyze(event)

    try:
        from app.aegis_mitre import analyze_process as new_analyze

        result = new_analyze(event)

        if not isinstance(result, dict):
            raise TypeError("New MITRE engine returned invalid result")

        if result.get("verdict") == "error" or result.get("error"):
            raise RuntimeError(result.get("error") or "Engine error")

        if "risk_score" not in result or "detections" not in result:
            raise ValueError("Missing required MITRE result fields")

        # Existing dashboard compatibility
        if result.get("verdict") == "critical":
            result["original_verdict"] = "critical"
            result["verdict"] = "high"

        return result

    except Exception:
        LOG.exception("MITRE V2 failed; using legacy engine")
        return legacy_analyze(event)
