"""Read-only Active Directory analytics over existing SOC SQLite events."""
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from app import storage

FAILURE_IDS = {4625, 4771}
AUTH_IDS = {4768, 4769, 4776}
WATCH_IDS = FAILURE_IDS | AUTH_IDS | {4740}

def _date(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None

def overview(limit=1000):
    limit = max(1, min(int(limit), 2000))
    with storage.LOCK, storage.connect() as db:
        rows = db.execute('SELECT payload FROM events WHERE source=? ORDER BY id DESC LIMIT ?', ('AD', limit)).fetchall()
    items = []
    for (payload,) in rows:
        try:
            event = json.loads(payload)
            raw = json.loads(event.get('raw') or '{}')
        except (ValueError, TypeError):
            continue
        fields = raw.get('fields') or {}
        try:
            event_id = int(raw.get('event_id'))
        except (ValueError, TypeError):
            continue
        if event_id not in WATCH_IDS:
            continue
        status = str(fields.get('Status') or fields.get('SubStatus') or '').lower()
        user = str(fields.get('TargetUserName') or fields.get('AccountName') or 'unknown')
        origin = str(fields.get('IpAddress') or fields.get('Workstation') or fields.get('WorkstationName') or 'unknown')
        if origin.startswith('::ffff:'):
            origin = origin[7:]
        failed = event_id in FAILURE_IDS or (event_id in AUTH_IDS and status not in ('', '0x0', '0x00000000'))
        kind = 'lockout' if event_id == 4740 else ('failure' if failed else 'success')
        at = _date(raw.get('time') or event.get('time'))
        items.append({'event_id': event_id, 'record_id': raw.get('record_id'), 'time': at.isoformat() if at else '',
                      'user': user, 'origin': origin, 'status': status, 'kind': kind,
                      'host': event.get('host') or raw.get('computer') or 'DC01'})
    failures = [x for x in items if x['kind'] == 'failure']
    successes = [x for x in items if x['kind'] == 'success']
    lockouts = [x for x in items if x['kind'] == 'lockout']
    grouped = defaultdict(list)
    for x in failures:
        dt = _date(x['time'])
        if dt:
            grouped[(x['user'].casefold(), x['origin'].casefold())].append(dt)
    correlations = []
    for (user, origin), times in grouped.items():
        times.sort()
        left = 0
        for right, current in enumerate(times):
            while current - times[left] > timedelta(minutes=10):
                left += 1
            if right - left + 1 >= 5:
                correlations.append({'user': user, 'origin': origin, 'count': right-left+1,
                                     'window_minutes': 10, 'last_seen': current.isoformat(),
                                     'risk': 'high', 'title': 'Tekrarlanan başarısız kimlik doğrulama'})
                break
    return {'total': len(items), 'successes': len(successes), 'failures': len(failures),
            'lockouts': len(lockouts), 'correlations': correlations,
            'events': items[:100], 'note': 'Son %d AD olayı incelendi; korelasyon geçmiş kayıt penceresiyle sınırlıdır.' % limit}
