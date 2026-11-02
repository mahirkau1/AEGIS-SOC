"""Context-aware detections: lineage, masquerading, path and heuristic anomalies."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .normalize import shannon_entropy

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe",
          "mspub.exe", "visio.exe", "msaccess.exe", "acrord32.exe", "acrobat.exe"}
WEBSERVERS = {"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe",
              "php-cgi.exe", "sqlservr.exe", "java.exe", "node.exe"}
INTERPRETERS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
                "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe",
                "cmstp.exe", "msiexec.exe", "forfiles.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe"}
SCRIPT_HOSTS = {"mshta.exe", "wscript.exe", "cscript.exe"}
LOLBIN_ORIGINALS = {"powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
                    "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe",
                    "bitsadmin.exe", "wmic.exe", "msbuild.exe", "schtasks.exe",
                    "net.exe", "reg.exe", "sc.exe", "installutil.exe", "cmstp.exe"}

_SYS32 = ("\\windows\\system32\\",)
_SYSWOW = ("\\windows\\syswow64\\",)
CRITICAL: Dict[str, tuple] = {
    "svchost.exe": (_SYS32 + _SYSWOW, {"services.exe"}),
    "lsass.exe": (_SYS32, {"wininit.exe"}),
    "services.exe": (_SYS32, {"wininit.exe"}),
    "wininit.exe": (_SYS32, {"smss.exe"}),
    "winlogon.exe": (_SYS32, {"smss.exe"}),
    "csrss.exe": (_SYS32, {"smss.exe"}),
    "smss.exe": (_SYS32, {"smss.exe", "system"}),
    "spoolsv.exe": (_SYS32, {"services.exe"}),
    "taskhostw.exe": (_SYS32, {"svchost.exe"}),
    "conhost.exe": (_SYS32, None),
    "dllhost.exe": (_SYS32 + _SYSWOW, None),
    "runtimebroker.exe": (_SYS32, {"svchost.exe"}),
}

SUSPICIOUS_DIRS = ("\\users\\public\\", "\\programdata\\", "\\appdata\\local\\temp\\",
                   "\\windows\\temp\\", "\\temp\\", "\\downloads\\", "\\$recycle.bin\\",
                   "\\perflogs\\", "\\windows\\tasks\\", "\\windows\\debug\\",
                   "\\windows\\fonts\\", "\\windows\\help\\")
DOUBLE_EXT = re.compile(r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|zip|rtf)\.(?:exe|scr|com|bat|cmd|js|vbs)$", re.I)


def basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def norm_path(path: str) -> str:
    p = path.replace("/", "\\").lower()
    return re.sub(r"^(?:\\\\\?\\)?[a-z]:", "", p)


def _d(rule_id, tech, tactic, name, score, conf, evidence):
    return {"rule_id": rule_id, "technique": tech, "tactic": tactic, "name": name,
            "score": score, "confidence": conf, "evidence": evidence[:500],
            "source": "context"}


def lineage_detections(image: str, parent: str, cmd_norm: str) -> List[dict]:
    out: List[dict] = []
    child, par = basename(image), basename(parent) if parent else ""
    pair = f"{parent} -> {image}"

    if par in OFFICE and child in INTERPRETERS:
        out.append(_d("AEGIS-CTX-001", "T1204.002", "Execution",
                      "Office Application Spawned Script/LOLBin", 85, "high", pair))
    if par in WEBSERVERS and (child in SHELLS or child in {"whoami.exe", "net.exe", "net1.exe", "certutil.exe", "cscript.exe", "wscript.exe"}):
        out.append(_d("AEGIS-CTX-002", "T1505.003", "Persistence",
                      "Web Server Spawned Shell (Possible Web Shell)", 90, "high", pair))
    if par == "wmiprvse.exe" and child in SHELLS | {"mshta.exe", "rundll32.exe"}:
        out.append(_d("AEGIS-CTX-003", "T1047", "Execution",
                      "WMI Provider Spawned Shell", 65, "medium", pair))
    if par == "services.exe" and child in SHELLS:
        out.append(_d("AEGIS-CTX-004", "T1569.002", "Execution",
                      "Service Control Manager Spawned Shell", 60, "medium", pair))
    if par in SCRIPT_HOSTS and child in SHELLS:
        out.append(_d("AEGIS-CTX-005", "T1059", "Execution",
                      "Script Host Spawned Shell", 70, "medium", pair))
    if par == "spoolsv.exe" and child in SHELLS:
        out.append(_d("AEGIS-CTX-006", "T1068", "Privilege Escalation",
                      "Print Spooler Spawned Shell", 75, "medium", pair))
    if par == "lsass.exe":
        out.append(_d("AEGIS-CTX-007", "T1003.001", "Credential Access",
                      "Process Spawned by LSASS", 95, "high", pair))
    if child == "svchost.exe" and re.search(r"svchost(?:\.exe)?\s*$", cmd_norm):
        out.append(_d("AEGIS-CTX-008", "T1055.012", "Defense Evasion",
                      "svchost.exe Without -k (Hollowing/Masquerade)", 80, "high", image))
    return out


def masquerade_detections(image: str, parent: str, original_name: str) -> List[dict]:
    out: List[dict] = []
    child, par = basename(image), basename(parent) if parent else ""
    ipath = norm_path(image)

    if child in CRITICAL:
        dirs, parents = CRITICAL[child]
        if image and not any(ipath.startswith(d) for d in dirs) and ipath.startswith("\\"):
            out.append(_d("AEGIS-MASQ-001", "T1036.005", "Defense Evasion",
                          f"{child} Running From Unexpected Path", 90, "high", image))
        if parents and par and par not in parents:
            out.append(_d("AEGIS-MASQ-002", "T1036.005", "Defense Evasion",
                          f"{child} With Unexpected Parent", 80, "high", f"{parent} -> {image}"))

    orig = original_name.lower().strip()
    if orig and orig in LOLBIN_ORIGINALS and child != orig and child not in {"pwsh.exe"}:
        out.append(_d("AEGIS-MASQ-003", "T1036.003", "Defense Evasion",
                      "Renamed System Binary (OriginalFileName Mismatch)", 70, "high",
                      f"{image} (original: {original_name})"))
    if DOUBLE_EXT.search(child):
        out.append(_d("AEGIS-MASQ-004", "T1036.007", "Defense Evasion",
                      "Double-Extension Executable", 70, "medium", image))
    return out


def path_detections(image: str) -> List[dict]:
    out: List[dict] = []
    ipath = norm_path(image)
    if image.startswith("\\\\"):
        out.append(_d("AEGIS-PATH-002", "T1021.002", "Lateral Movement",
                      "Execution From Network Share", 35, "low", image))
    elif any(s in ipath for s in SUSPICIOUS_DIRS):
        out.append(_d("AEGIS-PATH-001", "T1204.002", "Execution",
                      "Execution From User-Writable/Staging Directory", 30, "low", image))
    return out


def heuristic_detections(raw: str, cmd_norm: str, has_layers: bool, ps_ctx: bool) -> List[dict]:
    out: List[dict] = []
    if raw.count("^") >= 4:
        out.append(_d("AEGIS-HEUR-001", "T1027.010", "Defense Evasion",
                      "Caret Escape Obfuscation (cmd)", 50, "medium", raw))
    if ps_ctx and raw.count("`") >= 4:
        out.append(_d("AEGIS-HEUR-002", "T1027.010", "Defense Evasion",
                      "Backtick Obfuscation (PowerShell)", 50, "medium", raw))
    if len(re.findall(r"[\"']\s*\+\s*[\"']", raw)) >= 3:
        out.append(_d("AEGIS-HEUR-003", "T1027.010", "Defense Evasion",
                      "String Concatenation Obfuscation", 55, "medium", raw))
    if len(re.findall(r"%[^%\s]{1,30}:~-?\d+(?:,-?\d+)?%", raw)) >= 2:
        out.append(_d("AEGIS-HEUR-004", "T1027.010", "Defense Evasion",
                      "Environment-Variable Substring Obfuscation", 60, "medium", raw))
    if len(re.findall(r"\[char\]\s*(?:0x[0-9a-f]+|\d+)", cmd_norm)) >= 4:
        out.append(_d("AEGIS-HEUR-005", "T1027", "Defense Evasion",
                      "Char-Code Assembly Obfuscation", 55, "medium", raw))
    if len(raw) > 4000:
        out.append(_d("AEGIS-HEUR-006", "T1027", "Defense Evasion",
                      "Unusually Long Command Line", 25, "low", raw))
    if not has_layers:
        for tok in raw.split():
            if len(tok) >= 80 and shannon_entropy(tok) >= 5.0:
                out.append(_d("AEGIS-HEUR-007", "T1027", "Defense Evasion",
                              "High-Entropy Opaque Token", 40, "low", tok))
                break
    if re.search(r"[\uff00-\uffef\u200b-\u200f\u2060\ufeff]", raw):
        out.append(_d("AEGIS-HEUR-010", "T1027", "Defense Evasion",
                      "Unicode/Invisible Character Obfuscation", 55, "medium", raw))
    return out


def chain_detections(image: str, ancestors: Optional[List[dict]]) -> List[dict]:
    """ancestors: nearest-first list of {image, risk, guid}."""
    out: List[dict] = []
    if not ancestors:
        return out
    child = basename(image)
    names = [basename(a.get("image", "")) for a in ancestors]

    worst = max(ancestors, key=lambda a: a.get("risk", 0))
    if worst.get("risk", 0) >= 70:
        out.append(_d("AEGIS-CHAIN-001", "T1059", "Execution",
                      "Descendant of High-Risk Process", min(65, worst["risk"] - 15), "medium",
                      f"ancestor {worst.get('image')} risk={worst['risk']}"))
    if len(ancestors) >= 2 and child in INTERPRETERS and any(n in OFFICE for n in names[1:]):
        out.append(_d("AEGIS-CHAIN-002", "T1204.002", "Execution",
                      "Interpreter Deep in Office Process Tree", 80, "high",
                      " <- ".join([child] + names[:4])))
    if child in INTERPRETERS and any(n in WEBSERVERS for n in names[1:]):
        out.append(_d("AEGIS-CHAIN-003", "T1505.003", "Persistence",
                      "Interpreter Deep in Web Server Process Tree", 80, "high",
                      " <- ".join([child] + names[:4])))
    return out
