"""AEGIS SOC - MITRE ATT&CK behaviour detection engine (v2)."""
from __future__ import annotations

import re
import threading
from collections import OrderedDict
from typing import Dict, List, Optional

from .context import (basename, chain_detections, heuristic_detections,
                      lineage_detections, masquerade_detections, path_detections)
from .normalize import deobfuscate, extract_iocs, normalize
from .rules import RULES, Rule

VERSION = "2.0.0"
MAX_CMD = 32_768
CONF_WEIGHT = {"high": 1.0, "medium": 0.95, "low": 0.85}

# Exact decoded payloads verified as benign. Each entry may be pinned to hosts.
# Triage never hides OTHER detections found on the same command line.
KNOWN_BENIGN_DECODED: Dict[str, dict] = {
    'Write-Output "SYSMON-SOC-TEST-2026"': {
        "reason": "Previously verified Sysmon SOC lab test command",
        "hosts": None,   # e.g. {"lab-win10-01"} to pin
    },
}

_PS_CTX = re.compile(r"\b(?:powershell(?:_ise)?|pwsh)(?:\.exe)?\b", re.I)


class _Fields:
    """Case/underscore-insensitive accessor: command_line == CommandLine."""

    def __init__(self, parsed: dict):
        self._d = {str(k).lower().replace("_", ""): v for k, v in parsed.items()}

    def get(self, name: str) -> str:
        v = self._d.get(name)
        return "" if v is None else str(v)


def _hit(rule: Rule, evidence: str, source: str) -> dict:
    return {"rule_id": rule.id, "technique": rule.technique, "tactic": rule.tactic,
            "name": rule.name, "score": rule.score, "confidence": rule.confidence,
            "evidence": evidence[:500], "source": source}


def calculate_risk(detections: List[dict]) -> int:
    active = sorted(
        (round(d["score"] * CONF_WEIGHT.get(d["confidence"], 0.9))
         for d in detections if not d.get("suppressed_by_triage")),
        reverse=True)
    if not active:
        return 0
    corroboration = min(25, sum(round(0.15 * s) for s in active[1:5]))
    tactics = {d["tactic"] for d in detections if not d.get("suppressed_by_triage")}
    diversity = min(12, 4 * (len(tactics) - 1))
    return min(100, active[0] + corroboration + diversity)


def verdict_for(risk: int) -> str:
    return ("critical" if risk >= 85 else "high" if risk >= 70 else
            "medium" if risk >= 40 else "low" if risk > 0 else "none")


def _analyze(event: dict, ancestors: Optional[List[dict]]) -> dict:
    f = _Fields(event.get("parsed") or {})
    if f.get("eventid") != "1":
        return {"risk_score": 0, "detections": [], "analyzed": False}

    raw_full = f.get("commandline")
    raw = raw_full[:MAX_CMD]
    image, parent = f.get("image"), f.get("parentimage")
    host = event.get("host")

    norm_cmd = normalize(raw)
    norm_image = normalize(image)
    ps_ctx = bool(_PS_CTX.search(f"{image} {raw}"))

    deob = deobfuscate(raw)
    targets = [("command", f"{norm_image} {norm_cmd}")] + [
        (f"decoded:L{l.depth}", normalize(l.text)) for l in deob.layers if l.text]
    img_names = {basename(image), basename(f.get("originalfilename"))} - {""}

    detections: List[dict] = []
    for rule in RULES:
        try:
            if rule.scope == "image":
                if any(rule.pattern.search(n) for n in img_names):
                    detections.append(_hit(rule, image, "image"))
                continue
            for source, text in targets:
                is_main = source == "command"
                if rule.cli_flag and not (is_main and ps_ctx):
                    continue
                if rule.pattern.search(text):
                    detections.append(_hit(rule, raw if is_main else text, source))
                    break
        except Exception:        # one bad rule must never blind the engine
            continue

    detections += lineage_detections(image, parent, norm_cmd)
    detections += masquerade_detections(image, parent, f.get("originalfilename"))
    detections += path_detections(image)
    detections += heuristic_detections(raw, norm_cmd, bool(deob.layers), ps_ctx)
    detections += chain_detections(image, ancestors)

    for layer in deob.layers:
        if layer.embedded_pe:
            detections.append({"rule_id": "AEGIS-HEUR-008", "technique": "T1620",
                               "tactic": "Defense Evasion", "confidence": "high", "score": 90,
                               "name": "Embedded PE in Encoded Payload",
                               "evidence": layer.kind, "source": "decoded"})
    if max((l.depth for l in deob.layers), default=0) >= 2:
        detections.append({"rule_id": "AEGIS-HEUR-009", "technique": "T1027",
                           "tactic": "Defense Evasion", "confidence": "high", "score": 70,
                           "name": "Nested Multi-Layer Encoding", "evidence": raw[:500],
                           "source": "decoded"})
    for note in deob.failed:
        detections.append({"rule_id": "AEGIS-HEUR-011", "technique": "T1027",
                           "tactic": "Defense Evasion", "confidence": "low", "score": 35,
                           "name": "Undecodable Obfuscated Payload", "evidence": note,
                           "source": "decoded"})

    result = {
        "analyzed": True, "engine_version": VERSION, "host": host,
        "process_guid": f.get("processguid"), "image": image, "parent_image": parent,
        "command_line": raw, "truncated": len(raw_full) > MAX_CMD,
        "detections": detections,
    }

    # -------- triage (suppresses only the encoded-command finding, never others)
    if deob.layers:
        first = deob.layers[0].text
        result["decoded_command"] = first[:2000]
        result["decoded_layers"] = [{"kind": l.kind, "depth": l.depth,
                                     "text": l.text[:2000]} for l in deob.layers]
        entry = KNOWN_BENIGN_DECODED.get(first.strip())
        if entry and (entry["hosts"] is None or host in entry["hosts"]) \
                and len(deob.layers) == 1:
            for d in detections:
                if d["rule_id"] == "AEGIS-PS-001":
                    d["suppressed_by_triage"] = True
            result.update(triage="known_benign_lab_test", triage_reason=entry["reason"])

    risk = calculate_risk(detections)
    if result.get("triage") and risk == 0:
        risk = 5                                   # keep lab test visible, but low
    result["risk_score"] = risk
    result["verdict"] = verdict_for(risk)

    active = [d for d in detections if not d.get("suppressed_by_triage")]
    result["techniques"] = sorted({d["technique"] for d in active})
    result["tactics"] = sorted({d["tactic"] for d in active})
    result["iocs"] = extract_iocs(raw, *(l.text for l in deob.layers))
    return result


def analyze_process(event: dict) -> dict:
    """Backward-compatible entry point. Never raises; fails LOUD, not silent."""
    try:
        return _analyze(event, None)
    except Exception as exc:                        # noqa: BLE001
        return {"analyzed": False, "risk_score": 0, "verdict": "error",
                "detections": [], "error": f"{type(exc).__name__}: {exc}"}


class ProcessTracker:
    """Stateful analyser: keeps a bounded process tree for lineage correlation."""

    def __init__(self, max_entries: int = 200_000, depth: int = 6):
        self._tree: "OrderedDict[tuple, dict]" = OrderedDict()
        self._max, self._depth = max_entries, depth
        self._lock = threading.Lock()

    def _ancestors(self, host, parent_guid) -> List[dict]:
        out, guid = [], parent_guid
        for _ in range(self._depth):
            node = self._tree.get((host, guid)) if guid else None
            if not node:
                break
            out.append(node)
            guid = node["parent_guid"]
        return out

    def analyze(self, event: dict) -> dict:
        f = _Fields(event.get("parsed") or {})
        host, guid, pguid = event.get("host"), f.get("processguid"), f.get("parentprocessguid")
        try:
            with self._lock:
                ancestors = self._ancestors(host, pguid)
            result = _analyze(event, ancestors)
        except Exception as exc:                    # noqa: BLE001
            return {"analyzed": False, "risk_score": 0, "verdict": "error",
                    "detections": [], "error": f"{type(exc).__name__}: {exc}"}
        if result.get("analyzed") and guid:
            with self._lock:
                self._tree[(host, guid)] = {
                    "image": result["image"], "risk": result["risk_score"],
                    "parent_guid": pguid, "guid": guid}
                while len(self._tree) > self._max:
                    self._tree.popitem(last=False)
            result["lineage"] = [a["image"] for a in ancestors]
        return result
