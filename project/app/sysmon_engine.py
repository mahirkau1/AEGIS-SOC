"""AEGIS Sysmon telemetry parser and bounded process graph.

Network and DNS events carry their own ProcessGuid, but do not establish
that a process-create event is in the observed sample. Never invent parents.
"""
import json
import xml.etree.ElementTree as ET


def _local_name(tag):
    return str(tag).rsplit('}', 1)[-1]


def _get_xml_data(root):
    fields = {}
    for element in root.iter():
        if _local_name(element.tag) == 'EventData':
            for node in element:
                if _local_name(node.tag) == 'Data' and node.attrib.get('Name'):
                    fields[node.attrib['Name']] = node.text or ''
            break
    return fields


def _xml_metadata(root):
    for item in root:
        if _local_name(item.tag) == 'System':
            values = {}
            for node in item:
                key = _local_name(node.tag)
                if key in ('EventID', 'EventRecordID', 'Computer'):
                    values[key] = (node.text or '').strip()
                if key == 'TimeCreated':
                    values['TimeCreated'] = node.attrib.get('SystemTime')
            return values
    return {}


def parse_sysmon(event):
    if str(event.get('source') or '').upper() != 'SYSMON':
        return None
    try:
        raw = event.get('raw') or '{}'
        obj = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(obj, dict):
            return None
        xml = obj.get('xml') or obj.get('Xml')
        if not isinstance(xml, str) or not xml.strip():
            return None
        root = ET.fromstring(xml)
        if _local_name(root.tag) != 'Event':
            return None
        fields = _get_xml_data(root)
        sys = _xml_metadata(root)
        event_id = int(sys.get('EventID') or obj.get('event_id') or 0)
        if event_id <= 0:
            return None
        return {
            'event_id': event_id,
            'host': event.get('host') or obj.get('computer') or sys.get('Computer'),
            'record_id': obj.get('record_id') or sys.get('EventRecordID'),
            'timestamp': obj.get('timestamp') or sys.get('TimeCreated'),
            'process_guid': fields.get('ProcessGuid') or fields.get('SourceProcessGUID') or fields.get('SourceProcessGuid'),
            'parent_process_guid': fields.get('ParentProcessGuid'),
            'process_id': fields.get('ProcessId') or fields.get('SourceProcessId'),
            'image': fields.get('Image') or fields.get('SourceImage'),
            'parent_image': fields.get('ParentImage'),
            'command_line': fields.get('CommandLine'),
            'user': fields.get('User') or fields.get('SourceUser'),
            'query_name': fields.get('QueryName'),
            'destination_ip': fields.get('DestinationIp'),
            'destination_port': fields.get('DestinationPort'),
            'fields': fields,
        }
    except (TypeError, ValueError, ET.ParseError, AttributeError):
        return None


def _parsed(event):
    """Prefer persisted parsed data; gracefully support legacy raw XML events."""
    p = event.get('parsed') or {}
    if isinstance(p, dict) and p.get('event_id'):
        try:
            event_id = int(p['event_id'])
        except (TypeError, ValueError):
            return None
        fields = p.get('fields') if isinstance(p.get('fields'), dict) else {}
        return {
            'event_id': event_id,
            'host': event.get('host') or p.get('host'),
            'record_id': p.get('record_id'),
            'timestamp': event.get('event_time') or event.get('time'),
            'process_guid': p.get('process_guid') or fields.get('ProcessGuid'),
            'parent_process_guid': p.get('parent_process_guid') or fields.get('ParentProcessGuid'),
            'image': p.get('image') or fields.get('Image'),
            'parent_image': p.get('parent_image') or fields.get('ParentImage'),
            'command_line': p.get('command_line') or fields.get('CommandLine'),
            'user': p.get('user') or fields.get('User'),
            'query_name': p.get('domain') or fields.get('QueryName'),
            'destination_ip': p.get('dst_ip') or fields.get('DestinationIp'),
            'destination_port': p.get('dst_port') or fields.get('DestinationPort'),
            'fields': fields,
        }
    return parse_sysmon(event)


def build_process_tree(events):
    processes = {}
    network, dns = [], []
    for event in events:
        item = _parsed(event)
        if not item:
            continue
        host = str(item.get('host') or '').strip()
        guid = str(item.get('process_guid') or '').strip().lower()
        if not host:
            continue
        key = (host.lower(), guid)
        if item['event_id'] == 1 and guid:
            # First occurrence in caller order wins (usually latest)
            processes.setdefault(key, item)
        elif item['event_id'] == 3:
            network.append(item)
        elif item['event_id'] == 22:
            dns.append(item)

    nodes = []
    for (host_key, guid), process in processes.items():
        parent_guid = str(process.get('parent_process_guid') or '').strip()
        parent = processes.get((host_key, parent_guid.lower())) if parent_guid else None
        nodes.append({
            'id': guid,
            'host': process['host'],
            'image': process.get('image'),
            'command_line': process.get('command_line'),
            'user': process.get('user'),
            'parent_guid': parent_guid,
            'parent_image': parent.get('image') if parent else process.get('parent_image'),
            'parent_found': parent is not None,
        })
    return {
        'process_count': len(nodes),
        'network_count': len(network),
        'dns_count': len(dns),
        'processes': nodes,
        'network': network,
        'dns': dns,
    }
