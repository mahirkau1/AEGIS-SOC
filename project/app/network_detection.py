"""AEGIS network scan candidates (passive, no blocking).

Uses the *source event time*, filters service replies conservatively, and
restricts horizontal sweep candidates to the monitored lab address space.
"""
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
import json
import os

from app.event_time import occurred_at
from app.parser import normalize


def _networks():
    value = os.getenv('SOC_MONITORED_NETWORKS', '10.10.0.0/16')
    try:
        nets = [ipaddress.ip_network(x.strip(), strict=False) for x in value.split(',') if x.strip()]
        if not nets:
            raise ValueError('empty monitored networks')
        return nets
    except ValueError:
        # Fail closed; never silently expand a broken scope to the whole Internet.
        return []


def _event_parsed(event):
    p = event.get('parsed')
    if isinstance(p, str):
        try:
            p = json.loads(p)
        except (ValueError, TypeError):
            p = None
    if not isinstance(p, dict):
        p = normalize(event)
    return p


def _port(value):
    try:
        result = int(value)
        return result if 0 <= result <= 65535 else None
    except (ValueError, TypeError):
        return None


def detect_network_patterns(events, min_ports=5, min_hosts=5, since=None):
    """Identify scan *candidates* in five-minute source-event-time buckets.

    `since`, when present, is an aware datetime cutoff for event occurrence,
    not receipt. Raw/legacy source timestamps are recovered by occurred_at().
    """
    vertical = defaultdict(lambda: {'ports': set(), 'times': [], 'count': 0, 'sources': set()})
    horizontal = defaultdict(lambda: {'hosts': set(), 'times': [], 'count': 0, 'sources': set()})
    networks = _networks()
    excluded = defaultdict(int)
    since = since.astimezone(timezone.utc) if isinstance(since, datetime) and since.tzinfo else None

    for event in events:
        if not isinstance(event, dict):
            continue
        p = _event_parsed(event)
        src, dst = str(p.get('src_ip') or ''), str(p.get('dst_ip') or '')
        proto = str(p.get('protocol') or '').upper()
        if proto not in ('TCP', 'UDP', 'ICMP'):
            continue
        try:
            source_ip, dest_ip = ipaddress.ip_address(src), ipaddress.ip_address(dst)
            if any(x.is_multicast or x.is_unspecified or x.is_loopback for x in (source_ip, dest_ip)):
                continue
            if not networks or not any(dest_ip in net for net in networks):
                excluded['outside_scope'] += 1
                continue
            # Avoid counting expected broadcast/noise as host discovery.
            if isinstance(dest_ip, ipaddress.IPv4Address) and str(dest_ip).endswith('.255'):
                excluded['broadcast'] += 1
                continue
        except ValueError:
            continue
        when = occurred_at(event)
        if when is None:
            excluded['invalid_time'] += 1
            continue
        if since is not None and when < since:
            excluded['old_source_event'] += 1
            continue
        bucket = int(when.timestamp()) // 300
        sport = _port(p.get('src_port'))
        dport = _port(p.get('dst_port'))
        if proto != 'ICMP' and dport is None:
            continue

        event_source = str(event.get('source') or p.get('source') or '').upper()
        # Sysmon event 3 records both incoming and outgoing connections.
        if event_source == 'SYSMON':
            if int(p.get('event_id') or 0) != 3:
                continue
            initiated = str((p.get('fields') or {}).get('Initiated') or '').lower()
            if initiated == 'false':
                excluded['sysmon_inbound'] += 1
                continue
        # A response FROM a known service TO the client's ephemeral port is not
        # an initiator's port scan. This is a heuristic, not a TCP flow guarantee.
        if (proto in ('TCP', 'UDP') and sport is not None and
                sport <= 1024 and dport >= 32768):
            excluded['service_response'] += 1
            continue
        if event_source == 'SURICATA' and str(p.get('direction') or '').lower() == 'to_client':
            excluded['suricata_to_client'] += 1
            continue

        if dport is not None:
            item = vertical[(src, dst, proto, bucket)]
            item['ports'].add(dport)
            item['times'].append(when)
            item['count'] += 1
            item['sources'].add(event_source)

        key = (src, proto, dport, bucket)
        item = horizontal[key]
        item['hosts'].add(dst)
        item['times'].append(when)
        item['count'] += 1
        item['sources'].add(event_source)

    findings = []
    for (src, dst, proto, bucket), item in vertical.items():
        if len(item['ports']) < min_ports:
            continue
        findings.append({
            'detection_type': 'vertical_port_scan',
            'title': 'Possible Vertical Port Scan',
            'severity': 'medium', 'confidence': 'low',
            'source_ip': src, 'destination_ip': dst, 'protocol': proto,
            'distinct_ports': len(item['ports']), 'ports': sorted(item['ports']),
            'event_count': item['count'], 'evidence_sources': sorted(item['sources']),
            'first_seen': min(item['times']).isoformat(),
            'last_seen': max(item['times']).isoformat(),
            'window': bucket, 'status': 'candidate',
            'description': 'Bir hedefte çok sayıda port denemesi. Başarılı erişim veya saldırı kanıtlanmadı.'
        })
    for (src, proto, port, bucket), item in horizontal.items():
        if len(item['hosts']) < min_hosts:
            continue
        findings.append({
            'detection_type': 'horizontal_network_sweep',
            'title': 'Possible Network Sweep',
            'severity': 'medium', 'confidence': 'low',
            'source_ip': src, 'destination_port': port, 'protocol': proto,
            'distinct_hosts': len(item['hosts']), 'targets': sorted(item['hosts']),
            'event_count': item['count'], 'evidence_sources': sorted(item['sources']),
            'first_seen': min(item['times']).isoformat(),
            'last_seen': max(item['times']).isoformat(),
            'window': bucket, 'status': 'candidate',
            'description': 'Aynı hedef portunda birden fazla dahili hedef gözlendi; tarama adayı.'
        })
    return sorted(findings, key=lambda finding: finding['last_seen'], reverse=True)
