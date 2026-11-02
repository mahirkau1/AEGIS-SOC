"""Declarative detection rules. Adding a rule = adding one _r(...) line."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from .normalize import ENC_FLAG, prefixes


@dataclass(frozen=True)
class Rule:
    id: str
    technique: str
    tactic: str
    name: str
    pattern: Pattern
    score: int
    confidence: str          # high | medium | low
    scope: str = "cmd"       # cmd | image
    cli_flag: bool = False   # PowerShell switch: needs PS context, skipped on decoded text


RULES: List[Rule] = []


def _r(id, tech, tactic, name, pattern, score, conf, scope="cmd", cli_flag=False):
    RULES.append(Rule(id, tech, tactic, name, re.compile(pattern, re.I), score, conf,
                      scope, cli_flag))


# Patterns run against NORMALISED text (lowercase, no ^ ` quotes, unicode dashes unified).
# --------------------------------------------------------------- PowerShell CLI
_r("AEGIS-PS-001", "T1059.001", "Execution", "PowerShell Encoded Command",
   rf"(?:^|\s)[-/](?:{ENC_FLAG})(?=[\s:]|$)", 65, "medium", cli_flag=True)
_r("AEGIS-PS-002", "T1564.003", "Defense Evasion", "PowerShell Hidden Window",
   rf"(?:^|\s)[-/](?:{prefixes('windowstyle', 1)})[\s:]+(?:h|hi|hid|hidd|hidde|hidden|1)(?=\s|$)",
   30, "low", cli_flag=True)
_r("AEGIS-PS-003", "T1562.001", "Defense Evasion", "PowerShell Execution Policy Bypass",
   rf"(?:^|\s)[-/](?:ep|{prefixes('executionpolicy', 2)})[\s:]+(?:bypass|unrestricted)(?=\s|$)",
   25, "low", cli_flag=True)
_r("AEGIS-PS-004", "T1059.001", "Execution", "PowerShell NoProfile/NonInteractive",
   rf"(?:^|\s)[-/](?:{prefixes('noprofile', 3)}|{prefixes('noninteractive', 4)})(?=\s|$)",
   10, "low", cli_flag=True)

# --------------------------------------------------------------- PowerShell content
_r("AEGIS-PS-010", "T1105", "Command and Control", "PowerShell Download Cradle",
   r"(?:\b(?:iex|invoke-expression)\b.{0,2000}\b(?:downloadstring|invoke-webrequest|iwr|invoke-restmethod|irm|net\.webclient)\b"
   r"|\b(?:downloadstring|net\.webclient|invoke-webrequest|iwr|irm)\b.{0,2000}\b(?:iex|invoke-expression)\b)", 85, "high")
_r("AEGIS-DOWNLOAD-001", "T1105", "Command and Control", "Suspicious Download Command",
   r"(?:downloadstring|downloadfile|downloaddata|invoke-webrequest|start-bitstransfer|\biwr\s+https?://|\birm\s+https?://|\bcurl(?:\.exe)?\s+(?:-\S+\s+)*https?://|\bwget(?:\.exe)?\s+https?://)",
   40, "low")
_r("AEGIS-PS-011", "T1562.001", "Defense Evasion", "AMSI Bypass Indicators",
   r"(?:amsiutils|amsiinitfailed|amsicontext|amsiscanbuffer|amsi\.dll)", 85, "high")
_r("AEGIS-PS-012", "T1620", "Defense Evasion", "Reflective .NET Assembly Load",
   r"(?:\[reflection\.assembly\]::load|reflection\.assembly\]::loadfile|assembly\.load\(|\[system\.reflection\.assembly\])", 70, "medium")
_r("AEGIS-PS-013", "T1027.010", "Defense Evasion", "Compressed Base64 Payload",
   r"(?:frombase64string.{0,2000}(?:gzipstream|deflatestream)|(?:gzipstream|deflatestream).{0,2000}frombase64string)", 75, "medium")
_r("AEGIS-PS-014", "T1055", "Defense Evasion", "In-Memory Injection API Usage",
   r"(?:virtualalloc(?:ex)?|writeprocessmemory|createremotethread|ntcreatethreadex|queueuserapc|add-type.{0,300}dllimport)", 75, "medium")
_r("AEGIS-PS-015", "T1059.001", "Execution", "PowerShell TCP Client (Reverse Shell)",
   r"(?:net\.sockets\.tcpclient|new-object\s+net\.sockets\.tcpclient|system\.net\.sockets\.tcplistener)", 80, "medium")
_r("AEGIS-PS-016", "T1562.001", "Defense Evasion", "Defender Tampering",
   r"(?:set-mppreference.{0,200}-disable\w+\s+\$?true|add-mppreference.{0,100}-exclusion\w+|disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring)", 85, "high")

# --------------------------------------------------------------- Credential access
_r("AEGIS-CRED-001", "T1003.001", "Credential Access", "LSASS Memory Dump / Credential Tool Keywords",
   r"(?:sekurlsa|invoke-mimikatz|lsadump::|privilege::debug|kerberos::|comsvcs(?:\.dll)?.{0,40}minidump|procdump.{0,60}lsass|lsass.{0,60}(?:\.dmp|minidump|-ma\b))", 95, "high")
_r("AEGIS-CRED-002", "T1003.002", "Credential Access", "Registry Hive Export (SAM/SYSTEM/SECURITY)",
   r"\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)", 90, "high")
_r("AEGIS-CRED-003", "T1003.003", "Credential Access", "NTDS.dit Access",
   r"(?:ntdsutil.{0,100}(?:ifm|ntds)|\bvssadmin(?:\.exe)?\s+create\s+shadow|\bdiskshadow(?:\.exe)?|ntds\.dit)", 80, "medium")
_r("AEGIS-CRED-004", "T1555", "Credential Access", "Credential Store Enumeration",
   r"(?:\bcmdkey(?:\.exe)?\s+/list|\bvaultcmd(?:\.exe)?\s+/list|netsh\s+wlan\s+show\s+profiles?.{0,60}key=clear)", 55, "medium")
_r("AEGIS-CRED-005", "T1558.003", "Credential Access", "Kerberoasting / Ticket Tooling Keywords",
   r"(?:invoke-kerberoast|\brubeus\b|asktgt|asktgs|kerberoast)", 90, "high")

# --------------------------------------------------------------- Living-off-the-land
_r("AEGIS-LOL-001", "T1218.011", "Defense Evasion", "Suspicious Rundll32 Execution",
   r"\brundll32(?:\.exe)?\b.{0,1000}(?:https?://|javascript:|vbscript:|mshtml|comsvcs\.dll|\.dll,\s*#\d+|appdata|\\temp\\|\\public\\)", 70, "medium")
_r("AEGIS-LOL-002", "T1218.010", "Defense Evasion", "Suspicious Regsvr32 Execution",
   r"\bregsvr32(?:\.exe)?\b.{0,1000}(?:/i:\s*https?://|scrobj\.dll|/u\s+/s\s+/i)", 75, "high")
_r("AEGIS-LOL-003", "T1218.005", "Defense Evasion", "Suspicious Mshta Execution",
   r"\bmshta(?:\.exe)?\b.{0,1000}(?:https?://|javascript:|vbscript:|\.hta\b)", 80, "high")
_r("AEGIS-LOL-004", "T1105", "Command and Control", "Certutil Download/Decode",
   r"\bcertutil(?:\.exe)?\b.{0,300}(?:-urlcache|-verifyctl|-decode\b|-decodehex|-encode\b)", 75, "high")
_r("AEGIS-LOL-005", "T1197", "Persistence", "BITS Job Abuse",
   r"\bbitsadmin(?:\.exe)?\b.{0,300}(?:/transfer|/addfile|/setnotifycmdline|/resume)", 75, "high")
_r("AEGIS-LOL-006", "T1218.007", "Defense Evasion", "Msiexec Remote Package",
   r"\bmsiexec(?:\.exe)?\b.{0,300}https?://", 70, "medium")
_r("AEGIS-LOL-007", "T1047", "Execution", "WMIC Process Creation / Remote Node / XSL",
   r"\bwmic(?:\.exe)?\b.{0,300}(?:process\s+call\s+create|/node:|/format:\s*\S*\.xsl|/format:\s*https?://)", 70, "medium")
_r("AEGIS-LOL-008", "T1059.005", "Execution", "Script Host Executing Script from Writable Path",
   r"\b(?:wscript|cscript)(?:\.exe)?\b.{0,300}\.(?:js|jse|vbs|vbe|wsf)\b.{0,300}", 40, "low")
_r("AEGIS-LOL-009", "T1218.004", "Defense Evasion", "InstallUtil/RegAsm/RegSvcs Proxy Execution",
   r"\b(?:installutil|regasm|regsvcs)(?:\.exe)?\b.{0,300}(?:/u\b|/logfile=|\.dll\b|\.exe\b)", 60, "medium")
_r("AEGIS-LOL-010", "T1127.001", "Defense Evasion", "MSBuild Executing Project/Inline Task",
   r"\bmsbuild(?:\.exe)?\s.{0,300}\.(?:xml|csproj|proj|tmp|txt)\b", 60, "medium")
_r("AEGIS-LOL-011", "T1218.003", "Defense Evasion", "CMSTP INF Execution",
   r"\bcmstp(?:\.exe)?\b.{0,200}/(?:s|au)\b.{0,200}\.inf", 75, "high")
_r("AEGIS-LOL-012", "T1202", "Defense Evasion", "Indirect Command Execution",
   r"(?:\bforfiles(?:\.exe)?\b.{0,200}/c\b|\bpcalua(?:\.exe)?\b.{0,100}-a\b|\bscriptrunner(?:\.exe)?\b.{0,100}-appvscript)", 55, "medium")
_r("AEGIS-LOL-013", "T1218.008", "Defense Evasion", "Odbcconf Response-File/Regsvr",
   r"\bodbcconf(?:\.exe)?\b.{0,200}(?:-a\s*\{?regsvr|/a\s*\{?regsvr|-f\s)", 75, "high")
_r("AEGIS-LOL-014", "T1218.013", "Defense Evasion", "Mavinject DLL Injection",
   r"\bmavinject(?:\.exe)?\b.{0,200}/injectrunning", 85, "high")
_r("AEGIS-LOL-015", "T1105", "Command and Control", "Esentutl/Expand/Extrac32 File Transfer",
   r"(?:\besentutl(?:\.exe)?\b.{0,100}/y\b.{0,200}/d\b|\bextrac32(?:\.exe)?\b.{0,100}/c\b.{0,200}\\\\)", 55, "medium")

# --------------------------------------------------------------- Persistence / privilege
_r("AEGIS-TASK-001", "T1053.005", "Persistence", "Scheduled Task Creation",
   r"\bschtasks(?:\.exe)?\b.{0,1000}/create\b", 35, "medium")
_r("AEGIS-TASK-002", "T1053.005", "Persistence", "Scheduled Task Running Suspicious Payload",
   r"\bschtasks(?:\.exe)?\b.{0,1000}/create\b.{0,1000}(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|cmd(?:\.exe)?\s+/c|appdata|\\temp\\|programdata|\\users\\public)", 75, "high")
_r("AEGIS-PERS-001", "T1547.001", "Persistence", "Registry Run Key Modification",
   r"\breg(?:\.exe)?\s+add\s+.{0,100}\\currentversion\\(?:run|runonce)\b", 65, "medium")
_r("AEGIS-PERS-002", "T1546.012", "Persistence", "Image File Execution Options Hijack",
   r"image file execution options.{0,100}(?:debugger|globalflag)", 85, "high")
_r("AEGIS-PERS-003", "T1547.004", "Persistence", "Winlogon Helper Modification",
   r"\breg(?:\.exe)?\s+add\s+.{0,100}\\winlogon\b.{0,50}(?:shell|userinit)", 80, "high")
_r("AEGIS-PERS-004", "T1543.003", "Persistence", "Service Creation",
   r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b", 50, "medium")
_r("AEGIS-PERS-005", "T1543.003", "Persistence", "Service With Suspicious BinPath",
   r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:create|config)\b.{0,300}binpath=?\s*.{0,200}(?:cmd(?:\.exe)?\s+/c|powershell|pwsh|appdata|\\temp\\|\\users\\public|rundll32|mshta)", 80, "high")
_r("AEGIS-PERS-006", "T1136.001", "Persistence", "Local Account Creation / Admin Group Add",
   r"\bnet1?(?:\.exe)?\s+(?:user\s+\S+\s+\S*\s*/add|localgroup\s+administrators?\s+\S+\s+/add)", 65, "medium")
_r("AEGIS-PERS-007", "T1546.003", "Persistence", "WMI Event Subscription Persistence",
   r"(?:__eventfilter|commandlineeventconsumer|activescripteventconsumer|__filtertoconsumerbinding)", 80, "high")

# --------------------------------------------------------------- Defense evasion / impact
_r("AEGIS-EVADE-001", "T1070.001", "Defense Evasion", "Event Log Clearing",
   r"(?:\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|clear-eventlog|remove-eventlog)", 85, "high")
_r("AEGIS-EVADE-002", "T1070.004", "Defense Evasion", "USN Journal Deletion",
   r"\bfsutil(?:\.exe)?\s+usn\s+deletejournal", 80, "high")
_r("AEGIS-EVADE-003", "T1562.002", "Defense Evasion", "Audit Policy Tampering",
   r"\bauditpol(?:\.exe)?\b.{0,100}(?:/clear|/remove|/disable)", 75, "high")
_r("AEGIS-EVADE-004", "T1562.004", "Defense Evasion", "Firewall Disabled / Port Proxy",
   r"(?:netsh\b.{0,100}advfirewall.{0,100}state\s+off|netsh\s+(?:firewall\s+set\s+opmode\s+disable|.{0,40}portproxy\s+add)|set-netfirewallprofile.{0,100}-enabled\s+false)", 70, "medium")
_r("AEGIS-EVADE-005", "T1562.001", "Defense Evasion", "Security Tool Stop/Unload",
   r"(?:\b(?:sc(?:\.exe)?|net1?(?:\.exe)?)\s+(?:stop|config|delete)\s+(?:windefend|sense|wdnissvc|wdfilter|sysmon\d*|sysmondrv|mpssvc)|\bfltmc(?:\.exe)?\s+unload\s+sysmon|sysmon\d*(?:\.exe)?\s+-u\b|taskkill.{0,80}(?:msmpeng|sysmon|msseces|sense))", 90, "high")
_r("AEGIS-EVADE-006", "T1562.001", "Defense Evasion", "Boot Config Weakening",
   r"\bbcdedit(?:\.exe)?\b.{0,100}(?:testsigning\s+on|nointegritychecks\s+on|recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", 70, "medium")
_r("AEGIS-EVADE-007", "T1564.001", "Defense Evasion", "Hidden+System File Attributes",
   r"\battrib(?:\.exe)?\b.{0,100}\+h.{0,50}\+s", 35, "low")
_r("AEGIS-IMPACT-001", "T1490", "Impact", "Backup / Shadow Copy Destruction",
   r"(?:vssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)|wmic.{0,60}shadowcopy.{0,40}delete|wbadmin(?:\.exe)?\s+delete\s+(?:catalog|backup|systemstatebackup)|get-wmiobject.{0,60}shadowcopy.{0,60}delete)", 95, "high")
_r("AEGIS-IMPACT-002", "T1485", "Impact", "Secure Wipe of Free Space",
   r"\bcipher(?:\.exe)?\s+/w:", 60, "medium")

# --------------------------------------------------------------- Discovery / lateral / exfil
_r("AEGIS-DISC-001", "T1087.002", "Discovery", "Domain Account/Group Discovery",
   r"(?:\bnet1?(?:\.exe)?\s+(?:group|user|accounts|localgroup)\b.{0,80}(?:/domain|domain admins|enterprise admins)|\bnltest(?:\.exe)?\b.{0,60}(?:/dclist|/domain_trusts|/trusted_domains)|\bdsquery(?:\.exe)?\b|\badfind(?:\.exe)?\s)", 45, "medium")
_r("AEGIS-DISC-002", "T1033", "Discovery", "Privilege/Group Enumeration",
   r"\bwhoami(?:\.exe)?\s+/(?:priv|all|groups)\b", 25, "low")
_r("AEGIS-LAT-001", "T1021.002", "Lateral Movement", "PsExec-Style Remote Execution",
   r"(?:\bpsexec(?:64)?(?:\.exe)?\s.{0,200}\\\\\S+|\bpaexec(?:\.exe)?\s.{0,200}\\\\\S+|\bsc(?:\.exe)?\s+\\\\\S+\s+(?:create|start))", 70, "medium")
_r("AEGIS-LAT-002", "T1021.006", "Lateral Movement", "WinRM Remote Command",
   r"(?:\bwinrs(?:\.exe)?\b.{0,100}-r:|invoke-command.{0,100}-computername|enter-pssession)", 60, "medium")
_r("AEGIS-LAT-003", "T1053.005", "Lateral Movement", "Remote Scheduled Task",
   r"\bschtasks(?:\.exe)?\b.{0,300}/s\s+\\?\\?\S+.{0,300}/create|\bschtasks(?:\.exe)?\b.{0,300}/create.{0,300}/s\s+\\?\\?\S+", 65, "medium")
_r("AEGIS-EXFIL-001", "T1567.002", "Exfiltration", "Rclone / Cloud Sync Exfiltration",
   r"\brclone(?:\.exe)?\s+(?:copy|sync|move)\b.{0,200}:", 80, "medium")
_r("AEGIS-EXFIL-002", "T1560.001", "Collection", "Archive With Password",
   r"(?:\b(?:7z|7za|rar)(?:\.exe)?\s+a\b.{0,200}-(?:p|hp)\S*|compress-archive.{0,200}-destinationpath.{0,100}(?:temp|public))", 45, "low")

# --------------------------------------------------------------- Network indicators
_r("AEGIS-NET-001", "T1071.001", "Command and Control", "Raw-IP URL in Command Line",
   r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/", 45, "medium")
_r("AEGIS-NET-002", "T1102", "Command and Control", "Paste/Tunnel/File-Share Host in Command Line",
   r"(?:pastebin\.com|paste\.ee|hastebin|transfer\.sh|temp\.sh|anonfiles|file\.io|ngrok\.(?:io|app)|trycloudflare\.com|discord(?:app)?\.com/attachments|\.onion\b|duckdns\.org|mega\.nz)", 45, "low")

# --------------------------------------------------------------- Image / tool-name rules
_r("AEGIS-TOOL-001", "T1588.002", "Resource Development", "Known Offensive Tool Binary",
   r"^(?:mimikatz|lazagne|rubeus|sharphound|seatbelt|certify|sharpup|safetykatz|nanodump|dumpert|pypykatz|sharpdpapi|sharpwmi|cobaltstrike|beacon|meterpreter)(?:\d+)?(?:\.exe)?$",
   95, "high", scope="image")
_r("AEGIS-TOOL-002", "T1219", "Command and Control", "Dual-Use Admin/Tunneling Tool Binary",
   r"^(?:psexesvc|nc|nc64|ncat|chisel|plink|rclone|adfind|procdump(?:64)?|sharpchisel|frpc|frps|revsocks)(?:\.exe)?$",
   55, "low", scope="image")
