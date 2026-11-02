import csv
import io
import ipaddress
import json
import re


def normalize(event):
    source = str(event.get('source', '')).upper()
    raw = str(event.get('raw') or '')
    msg = str(event.get('message') or '')
    result = {'source': source, 'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None,
              'protocol': None, 'action': None, 'signature': None, 'domain': None,
              'severity': str(event.get('severity', 'info')).lower(), 'message': msg[:500]}
    # AEGIS-SURICATA-PARSER-V2
    if source == 'SURICATA':
        try:
            obj = json.loads(raw[raw.index('{'):])

            if not isinstance(obj, dict):
                raise ValueError("EVE JSON nesnesi gecersiz")

            alert = obj.get('alert') or {}
            flow = obj.get('flow') or {}

            if not isinstance(alert, dict):
                alert = {}

            if not isinstance(flow, dict):
                flow = {}

            result.update(
                src_ip=obj.get('src_ip'),
                dst_ip=obj.get('dest_ip'),
                src_port=obj.get('src_port'),
                dst_port=obj.get('dest_port'),
                protocol=obj.get('proto'),
                action=alert.get('action'),
                signature=alert.get('signature'),

                signature_id=alert.get('signature_id'),
                gid=alert.get('gid'),
                signature_revision=alert.get('rev'),
                category=alert.get('category'),
                alert_severity=alert.get('severity'),
                alert_metadata=alert.get('metadata') or {},

                flow_id=obj.get('flow_id'),
                community_id=obj.get('community_id'),
                event_timestamp=obj.get('timestamp'),
                event_type=obj.get('event_type'),
                in_iface=obj.get('in_iface'),
                direction=obj.get('direction'),
                app_proto=obj.get('app_proto'),

                flow_start=flow.get('start'),
                pkts_toserver=flow.get('pkts_toserver'),
                pkts_toclient=flow.get('pkts_toclient'),
                bytes_toserver=flow.get('bytes_toserver'),
                bytes_toclient=flow.get('bytes_toclient')
            )

            result['message'] = (
                alert.get('signature')
                or obj.get('event_type', 'Suricata olayı')
            )

            severity = alert.get('severity')

            result['severity'] = (
                'low'
                if alert.get('signature') == 'KALI SECURITY TEST'
                else {
                    1: 'critical',
                    2: 'high',
                    3: 'medium'
                }.get(severity, 'info')
            )

        except (ValueError, TypeError):
            result['message'] = msg[:220]

    elif source == 'FIREWALL':
        match = re.search(r'filterlog\[\d+\]:\s*(.*)', raw)
        if match:
            try:
                fields = next(csv.reader(io.StringIO(match.group(1))))
                action = fields[6].upper()
                version = fields[8]
                result['action'] = action
                if version == '4':
                    # filterlog IPv4: 16 protocol, 18 src, 19 dst, 20 sport, 21 dport for TCP/UDP
                    result.update(protocol=fields[16].upper(), src_ip=fields[18], dst_ip=fields[19])
                    if fields[16].lower() in ('tcp', 'udp') and len(fields) > 21:
                        result.update(src_port=int(fields[20]), dst_port=int(fields[21]))
                elif version == '6':
                    # IPv6: 12 proto, 15 src, 16 dst; TCP/UDP ports follow
                    result.update(protocol=fields[12].upper(), src_ip=fields[15], dst_ip=fields[16])
                    if fields[12].lower() in ('tcp', 'udp') and len(fields) > 18:
                        result.update(src_port=int(fields[17]), dst_port=int(fields[18]))
                result['message'] = f"{action} · {result['src_ip'] or '?'} → {result['dst_ip'] or '?'}"
            except (IndexError, ValueError, TypeError):
                result['message'] = msg[:220]
        else:
            match = re.search(r'\b(PASS|BLOCK|REJECT)\s*\|\s*([^\s|]+)\s*->\s*([^\s|]+)', msg, re.I)
            if match:
                result.update(action=match[1].upper(), src_ip=match[2], dst_ip=match[3])
                result['message'] = f'{match[1].upper()} · {match[2]} → {match[3]}'
        if result['action'] in ('BLOCK', 'REJECT'):
            result['severity'] = 'medium'
    elif source == 'DNS':
        # Unbound query/reply lines: client domain type class [rcode ...]
        match = re.search(r'info:\s+((?:\d{1,3}\.){3}\d{1,3})\s+(\S+)\s+(A|AAAA|PTR|TXT|MX|SRV|CNAME|NS|SOA)\s+IN\b(?:\s+(NOERROR|NXDOMAIN|SERVFAIL|REFUSED))?', raw, re.I)
        if match:
            result.update(src_ip=match[1], domain=match[2], protocol='DNS', action=match[4] or 'QUERY')
            result['message'] = f'{match[2]} · {match[3].upper()} · {match[4] or "QUERY"}'
        else:
            result['message'] = msg[:220]
    elif source == 'SYSMON':
        from app.sysmon_engine import parse_sysmon

        item = parse_sysmon(event)

        if item:
            event_id = item.get('event_id')
            fields = item.get('fields') or {}

            result.update(
                event_id=event_id,
                record_id=item.get('record_id'),
                process_guid=item.get('process_guid'),
                parent_process_guid=item.get('parent_process_guid'),
                process_id=item.get('process_id'),
                image=item.get('image'),
                parent_image=item.get('parent_image'),
                command_line=item.get('command_line'),
                user=item.get('user'),
                fields=fields
            )

            # AEGIS_SYSMON_V3_EVIDENCE - preserve event-specific fields
            result.update(
                event_type={1: 'process_create', 3: 'network_connection',
                    8: 'remote_thread', 10: 'process_access', 11: 'file_create',
                    12: 'registry_key', 13: 'registry_value', 22: 'dns_query',
                    25: 'process_tampering'}.get(event_id, 'sysmon_event'),
                source_image=fields.get('SourceImage') or fields.get('Image'),
                target_image=fields.get('TargetImage'),
                target_filename=fields.get('TargetFilename'),
                target_object=fields.get('TargetObject'),
                granted_access=fields.get('GrantedAccess'),
            )

            if event_id == 1:
                result.update(
                    event_type='process_create',
                    parent_process_id=fields.get('ParentProcessId'),
                    parent_command_line=fields.get('ParentCommandLine'),
                    hashes=fields.get('Hashes'),
                    integrity_level=fields.get('IntegrityLevel')
                )
                result['message'] = (
                    f"Process Create | {item.get('image') or '?'} "
                    f"| Parent: {item.get('parent_image') or '?'}"
                )

            elif event_id == 3:
                result.update(
                    event_type='network_connection',
                    src_ip=fields.get('SourceIp'),
                    src_port=fields.get('SourcePort'),
                    dst_ip=fields.get('DestinationIp'),
                    dst_port=fields.get('DestinationPort'),
                    protocol=fields.get('Protocol'),
                    action='CONNECT'
                )
                result['message'] = (
                    f"Network Connection | {fields.get('SourceIp') or '?'} "
                    f"-> {fields.get('DestinationIp') or '?'}:"
                    f"{fields.get('DestinationPort') or '?'}"
                )

            elif event_id == 22:
                result.update(
                    event_type='dns_query',
                    domain=fields.get('QueryName'),
                    query_status=fields.get('QueryStatus'),
                    query_results=fields.get('QueryResults'),
                    protocol='DNS',
                    action='QUERY'
                )
                result['message'] = (
                    f"DNS Query | {fields.get('QueryName') or '?'} "
                    f"| Process: {item.get('image') or '?'}"
                )
            elif event_id in (8, 10, 11, 12, 13, 25):
                target = (fields.get('TargetImage') or fields.get('TargetFilename')
                          or fields.get('TargetObject') or '?')
                result['message'] = f'Sysmon Event {event_id} | {str(target)[:160]}'
    if source == 'SYSMON':
        from app.sysmon_detection import detect_sysmon
        detection = detect_sysmon(result)
        if detection:
            result['detection'] = detection
            result['severity'] = detection['severity']
            result['message'] = (
                detection['message'] + ' | ' + result['message']
            )
    return result
