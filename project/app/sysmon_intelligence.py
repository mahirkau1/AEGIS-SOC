"""Read-only Sysmon endpoint coverage & detection summary.

This view reports only the latest bounded events actually persisted in the
SOC store. It never asserts a missing Event ID is disabled on the endpoint.
"""
from collections import Counter
from fastapi import APIRouter, HTTPException
from app import storage

router = APIRouter()

EVENT_NAMES = {
    1: 'Process Create', 3: 'Network Connection', 6: 'Driver Loaded',
    7: 'Image Load', 8: 'CreateRemoteThread', 10: 'Process Access',
    11: 'File Create', 12: 'Registry Key', 13: 'Registry Value',
    14: 'Registry Rename', 15: 'File Stream', 22: 'DNS Query',
    23: 'File Delete', 25: 'Process Tampering', 26: 'File Delete Detected',
}


def summarize(events, total=None):
    ids, hosts, rules, processes = Counter(), Counter(), Counter(), Counter()
    alerts, bad = 0, 0
    latest = None
    for e in events:
        if not isinstance(e, dict):
            bad += 1
            continue
        p = e.get('parsed') or {}
        if not isinstance(p, dict):
            bad += 1
            continue
        try:
            eid = int(p.get('event_id') or 0)
        except (ValueError, TypeError):
            eid = 0
        if eid <= 0:
            bad += 1
        else:
            ids[eid] += 1
        hosts[str(e.get('host') or 'unknown')[:128]] += 1
        detection = p.get('detection') or {}
        if isinstance(detection, dict) and detection.get('rule'):
            alerts += 1
            rules[str(detection['rule'])[:100]] += 1
        if eid == 1:
            image = str(p.get('image') or '')
            if image:
                processes[image.replace('/', '\\').rsplit('\\', 1)[-1].lower()[:120]] += 1
        when = e.get('event_time') or e.get('time')
        if isinstance(when, str) and when and (latest is None or when > latest):
            latest = when
    scanned = len(events)
    return {
        'sampled_events': scanned,
        'stored_total': total if total is not None else scanned,
        'sample_truncated': total is not None and total > scanned,
        'invalid_event_id': bad,
        'sample_alert_events': alerts,
        'observed_hosts': [{'host': h, 'count': n} for h, n in hosts.most_common(20)],
        'event_ids': [{'id': k, 'name': EVENT_NAMES.get(k, 'Other'), 'count': v}
                      for k, v in sorted(ids.items(), key=lambda x: (-x[1], x[0]))],
        'detections': [{'rule': k, 'count': v} for k, v in rules.most_common(15)],
        'top_processes': [{'name': k, 'count': v} for k, v in processes.most_common(10)],
        'last_observed': latest,
        'coverage_note': 'Bu sayilar yalnizca saklanan en yeni orneklem icindir; gorulmeyen Event ID devre disi demek degildir.',
        'mutates_database': False,
    }


@router.get('/api/sysmon/intelligence')
def sysmon_intelligence(limit: int = 2000):
    if limit < 100 or limit > 5000:
        raise HTTPException(status_code=422, detail='limit 100..5000 olmali')
    with storage.LOCK:
        db = storage.connect()
        try:
            total = db.execute("SELECT COUNT(*) FROM events WHERE source='SYSMON'").fetchone()[0]
        finally:
            db.close()
    events = storage.get_sysmon_events(limit=limit)
    return summarize(events, total)
