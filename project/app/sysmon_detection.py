"""Conservative, explainable Sysmon detections (one primary rule per event).

Detection is a review signal, not proof of compromise. Avoid blanket alerts for
administrative tools, normal LSASS access, DLL loads and ordinary file writes.
"""
import ipaddress
import re


def _winname(value):
    return str(value or '').lower().replace('/', '\\').rsplit('\\', 1)[-1]


def _alert(rule, severity, message, technique, reason):
    return {
        'rule': rule, 'severity': severity, 'message': message,
        'mitre_technique': technique, 'evidence_reason': reason,
    }


def detect_sysmon(p):
    try:
        event_id = int(p.get('event_id') or 0)
    except (TypeError, ValueError):
        return None
    fields = p.get('fields') if isinstance(p.get('fields'), dict) else {}
    image = p.get('image') or fields.get('Image') or fields.get('SourceImage')
    parent = p.get('parent_image') or fields.get('ParentImage')
    name, parent_name = _winname(image), _winname(parent)
    command = str(p.get('command_line') or fields.get('CommandLine') or '')
    lower = command.lower()

    if event_id == 1:
        shells = {'powershell.exe', 'pwsh.exe', 'cmd.exe'}
        if name in shells and parent_name in {'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe'}:
            return _alert('SYSMON-OFFICE-SHELL', 'high', 'Office uygulamasi komut kabugu baslatti', 'T1204.002', 'office_parent_shell_child')
        if name in shells and parent_name in {'wscript.exe', 'cscript.exe', 'mshta.exe'}:
            return _alert('SYSMON-SCRIPT-SHELL', 'high', 'Script host komut kabugu baslatti', 'T1059', 'script_host_shell_child')
        if name in {'powershell.exe', 'pwsh.exe'}:
            if re.search(r'(?i)(?:^|\s)[-/](?:enc|encodedcommand)(?:\s|:|$)', command):
                return _alert('SYSMON-ENCODED-POWERSHELL', 'medium', 'Kodlanmis PowerShell komutu', 'T1059.001', 'encodedcommand_switch')
            if re.search(r'\b(?:downloadstring|invoke-expression)\b|(?<!\w)iex\s*(?:\(|\$|["\'])', lower):
                return _alert('SYSMON-POWERSHELL-EXECUTION', 'medium', 'PowerShell komutunda inceleme gerektiren ifade', 'T1059.001', 'dynamic_execution_expression')
        return None

    if event_id == 3:
        ip_string = str(p.get('dst_ip') or fields.get('DestinationIp') or '')
        port = str(p.get('dst_port') or fields.get('DestinationPort') or '')
        if port in {'4444', '5555', '6666', '1337'}:
            try:
                if ipaddress.ip_address(ip_string).is_global:
                    return _alert('SYSMON-UNUSUAL-OUTBOUND-PORT', 'medium', 'Alisilmadik porta dis baglanti', 'T1571', 'public_ip_unusual_port')
            except ValueError:
                pass
        return None

    if event_id == 22:
        domain = str(p.get('domain') or fields.get('QueryName') or '').lower().rstrip('.')
        if domain.endswith('.onion'):
            return _alert('SYSMON-SUSPICIOUS-DNS', 'medium', 'Inceleme gerektiren DNS sorgusu', 'T1071.004', 'onion_suffix')
        if domain.endswith('.invalid'):
            return _alert('SYSMON-SUSPICIOUS-DNS', 'low', 'Gecersiz DNS alani sorgulandi', 'T1071.004', 'invalid_suffix_test_possible')
        return None

    if event_id == 8:
        target = _winname(fields.get('TargetImage'))
        source = _winname(fields.get('SourceImage') or image)
        if target == 'lsass.exe' and source and source != target:
            return _alert('SYSMON-REMOTE-THREAD-LSASS', 'high', 'LSASS hedefli uzak is parcacigi olusturuldu', 'T1055', 'remote_thread_target_lsass')
        return None

    if event_id == 10:
        target = _winname(fields.get('TargetImage'))
        source = _winname(fields.get('SourceImage') or image)
        access = str(fields.get('GrantedAccess') or '').strip().lower()
        if (target == 'lsass.exe' and source and source != target and
                access in {'0x1fffff', '0x1f3fff', '0x1f0fff'} and
                source not in {'taskmgr.exe', 'procexp.exe', 'procexp64.exe'}):
            return _alert('SYSMON-LSASS-ACCESS', 'high', 'LSASS surecine yuksek yetkili erisim', 'T1003.001', 'lsass_sensitive_access_mask')
        return None

    if event_id == 11:
        target = str(fields.get('TargetFilename') or '').lower().replace('/', '\\')
        if ('\\start menu\\programs\\startup\\' in target or
                '\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\' in target):
            return _alert('SYSMON-STARTUP-FILE', 'medium', 'Baslangic klasorunde dosya olusturuldu', 'T1547.001', 'startup_folder_file_created')
        return None

    if event_id == 13:
        key = str(fields.get('TargetObject') or '').lower().replace('/', '\\')
        if re.search(r'\\(?:currentversion\\run(?:once)?|policies\\explorer\\run)\\[^\\]+$', key):
            return _alert('SYSMON-AUTORUN-REGISTRY', 'medium', 'Otomatik calistirma kaydi degistirildi', 'T1547.001', 'autorun_registry_value_set')
        return None

    if event_id == 25:
        return _alert('SYSMON-PROCESS-TAMPERING', 'high', 'Sysmon process tampering olayi', 'T1055', 'sysmon_event_25')
    return None
