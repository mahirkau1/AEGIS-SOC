"""AEGIS SOC - MITRE ATT&CK behavior detection."""

import re

RULES = [
    {
        "id": "AEGIS-PS-001",
        "technique": "T1059.001",
        "name": "PowerShell Encoded Command",
        "pattern": r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?:\s|:|$)",
        "score": 65,
        "confidence": "medium",
    },
    {
        "id": "AEGIS-LOL-001",
        "technique": "T1218.011",
        "name": "Suspicious Rundll32 Execution",
        "pattern": r"(?i)\brundll32(?:\.exe)?\b.*(?:https?://|javascript:|mshtml|comsvcs\.dll)",
        "score": 70,
        "confidence": "medium",
    },
    {
        "id": "AEGIS-LOL-002",
        "technique": "T1218.010",
        "name": "Suspicious Regsvr32 Execution",
        "pattern": r"(?i)\bregsvr32(?:\.exe)?\b.*(?:/i:https?://|scrobj\.dll)",
        "score": 75,
        "confidence": "high",
    },
    {
        "id": "AEGIS-TASK-001",
        "technique": "T1053.005",
        "name": "Scheduled Task Creation",
        "pattern": r"(?i)\bschtasks(?:\.exe)?\b.*(?:/create\b)",
        "score": 35,
        "confidence": "medium",
    },
    {
        "id": "AEGIS-DOWNLOAD-001",
        "technique": "T1105",
        "name": "Suspicious Download Command",
        "pattern": r"(?i)(?:downloadstring|downloadfile|invoke-webrequest|iwr\s+https?://|curl(?:\.exe)?\s+https?://)",
        "score": 40,
        "confidence": "low",
    },
]


def analyze_process(event):
    parsed = event.get("parsed") or {}

    if str(parsed.get("event_id") or "") != "1":
        return {
            "risk_score": 0,
            "detections": [],
            "analyzed": False,
        }

    command = str(parsed.get("command_line") or "")
    image = str(parsed.get("image") or "")
    parent = str(parsed.get("parent_image") or "")

    evidence = f"{image} {command}"
    detections = []

    for rule in RULES:
        if re.search(rule["pattern"], evidence):
            detections.append({
                "rule_id": rule["id"],
                "technique": rule["technique"],
                "name": rule["name"],
                "score": rule["score"],
                "confidence": rule["confidence"],
                "evidence": command[:500],
            })

    scores = sorted(
        (d["score"] for d in detections),
        reverse=True
    )

    risk = (
        min(100, scores[0] + min(20, 10 * (len(scores) - 1)))
        if scores else 0
    )

    return {
        "analyzed": True,
        "host": event.get("host"),
        "process_guid": parsed.get("process_guid"),
        "image": image,
        "parent_image": parent,
        "command_line": command,
        "risk_score": risk,
        "detections": detections,
        "verdict": (
            "high" if risk >= 70 else
            "medium" if risk >= 40 else
            "low" if risk > 0 else
            "none"
        ),
    }

# AEGIS_ENCODED_TRIAGE_V1
import base64
import binascii
import functools

_original_analyze_process = analyze_process


def _decode_encoded_command(command):
    match = re.search(
        r"(?i)(?:^|\s)-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]+)(?=\s|$)",
        command,
    )

    if not match:
        return None

    try:
        raw = base64.b64decode(match.group(1), validate=True)

        if len(raw) > 65536:
            return None

        return raw.decode("utf-16-le")

    except (ValueError, UnicodeError, binascii.Error):
        return None


@functools.wraps(_original_analyze_process)
def analyze_process(event):
    result = _original_analyze_process(event)

    if not result.get("analyzed"):
        return result

    command = str(
        (event.get("parsed") or {}).get("command_line") or ""
    )

    decoded = _decode_encoded_command(command)

    if decoded is None:
        return result

    result["decoded_command"] = decoded[:2000]

    # Only this exact previously verified lab command is allowlisted.
    if decoded.strip() == 'Write-Output "SYSMON-SOC-TEST-2026"':
        result["risk_score"] = 5
        result["verdict"] = "low"
        result["triage"] = "known_benign_lab_test"
        result["triage_reason"] = (
            "Previously verified Sysmon SOC lab test command"
        )

    return result
