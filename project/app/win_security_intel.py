"""AEGIS WIN_SECURITY session intelligence, read-only.

Preserves the existing AD authentication correlations. Context signals from
4648 and 4672 are not proof of compromise. No passwords or raw events returned.
"""
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from app import storage

EVENT_IDS = {4624, 4625, 4634, 4647, 4648, 4672, 4778, 4779, 4800, 4801}
INTERACTIVE = {'2', '7', '10', '11'}
NAMES = {
    4624: 'successful_logon', 4625: 'failed_logon',
    4634: 'session_ended', 4647: 'user_logoff',
    4648: 'explicit_credentials', 4672: 'special_privileges',
    4778: 'rdp_reconnected', 4779: 'rdp_disconnected',
    4800: 'workstation_locked', 4801: 'workstation_unlocked',
}


def _time(v):
    try:
        t = datetime.fromisoformat(str(v).replace('Z', '+00:00'))
        return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _raw(item):
    value = item.get('raw') or {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def _field(raw, *names):
    values = {}
    for part in (raw.get('fields'), raw.get('event_data'), raw):
        if not isinstance(part, dict):
            continue
        for key, value in part.items():
            normalized = ''.join(c for c in str(key).casefold() if c.isalnum())
            if normalized not in values or not values[normalized]:
                values[normalized] = value
    for name in names:
        value = values.get(''.join(c for c in name.casefold() if c.isalnum()))
        if value is not None and str(value).strip() not in ('', '-'):
            return str(value).strip()
    return ''


def _account(value):
    account = str(value or '').strip().rsplit('\\', 1)[-1].split('@', 1)[0]
    if not account or account in ('-', '?') or account.endswith('$'):
        return ''
    if account.casefold() in ('system', 'anonymous logon', 'local service',
                               'network service', 'bilinmiyor'):
        return ''
    return account.casefold()


def _source(raw):
    src = _field(raw, 'source_ip', 'IpAddress', 'ClientAddress', 'SourceNetworkAddress')
    if src.startswith('::ffff:'):
        src = src[7:]
    if src in ('', '-', '127.0.0.1', '::1', '0.0.0.0', '::'):
        return ''
    return src.casefold()


def _event(item):
    raw = _raw(item)
    try:
        eid = int(_field(raw, 'event_id', 'EventID'))
    except (ValueError, TypeError):
        return None
    if eid not in EVENT_IDS:
        return None
    t = _time(_field(raw, 'timestamp', 'time', 'event_time', 'TimeCreated')
              or item.get('event_time') or item.get('time'))
    if t is None:
        return None
    host = str(item.get('host') or _field(raw, 'computer', 'Computer') or 'unknown').split('.')[0].upper()
    user = _account(_field(raw, 'user', 'TargetUserName', 'AccountName', 'subject_user', 'SubjectUserName'))
    actor = _account(_field(raw, 'subject_user', 'SubjectUserName', 'user', 'AccountName'))
    target = _account(_field(raw, 'target_user', 'TargetUserName', 'target_account'))
    rid = _field(raw, 'record_id', 'EventRecordID', 'RecordId')
    logon_id = _field(raw, 'logon_id', 'TargetLogonId', 'SubjectLogonId', 'LogonId').casefold()
    # For 4648, the subject and the explicitly supplied target are different roles.
    if eid == 4648:
        user = actor
    return dict(event_id=eid, host=host, time=t, user=user, actor=actor,
                target_user=target, source=_source(raw), logon_id=logon_id,
                logon_type=_field(raw, 'logon_type', 'LogonType'),
                status=_field(raw, 'status', 'Status').casefold(),
                record_id=rid)


def _evidence(event):
    return dict(source='WIN_SECURITY', host=event['host'],
                event_id=event['event_id'], record_id=event['record_id'],
                time=event['time'].isoformat())


def _signal(rule, title, user, source, evidence, first, last, detail,
            actor='', target_user=''):
    return dict(rule=rule, severity='medium', title=title, detail=detail,
                user=user, actor=actor, target_user=target_user,
                source=source, count=len(evidence),
                first_seen=first.isoformat(), last_seen=last.isoformat(),
                evidence=[_evidence(e) for e in evidence[:30]],
                # Context only; no ATT&CK technique asserted without stronger proof.
                mitre=None)


def evaluate(items):
    """Analyze WIN_SECURITY event records without modifying the database."""
    unique = {}
    for item in items:
        e = _event(item)
        if e is None:
            continue
        key = (e['host'], e['event_id'], e['record_id']) if e['record_id'] else (
            e['host'], e['event_id'], e['time'].isoformat(),
            e['user'], e['source'], e['logon_id'])
        unique[key] = e
    events = sorted(unique.values(), key=lambda e: (e['time'], e['host'], e['record_id']))
    counts = Counter(e['event_id'] for e in events)
    sessions = {}
    # Build a session only from 4624 + a usable LogonId, never from time proximity.
    for e in events:
        sid = e['logon_id']
        key = (e['host'], sid)
        if not sid:
            continue
        if e['event_id'] == 4624 and e['user'] and e['logon_type'] in INTERACTIVE:
            sessions[key] = dict(host=e['host'], logon_id=sid, user=e['user'],
                                 source=e['source'], logon_type=e['logon_type'],
                                 started=e['time'], ended=None, privileged=False,
                                 privilege_event=None, login_event=e,
                                 reconnects=0, locks=0, unlocks=0)
        elif key in sessions:
            s = sessions[key]
            if e['time'] < s['started']:
                continue
            # Do not enrich a different account, even if LogonId was reused.
            if e['user'] and e['user'] != s['user']:
                continue
            if e['event_id'] == 4672:
                s['privileged'] = True
                s['privilege_event'] = e
            elif e['event_id'] in (4634, 4647):
                if s['ended'] is None:
                    s['ended'] = e['time']
            elif e['event_id'] == 4778:
                s['reconnects'] += 1
            elif e['event_id'] == 4800:
                s['locks'] += 1
            elif e['event_id'] == 4801:
                s['unlocks'] += 1

    detections = []
    for s in sessions.values():
        if s['privileged'] and s['privilege_event']:
            a, b = s['login_event'], s['privilege_event']
            detections.append(_signal(
                'win_privileged_session', 'Ayricalikli interaktif oturum (inceleme)',
                s['user'], s['source'] or 'LOCAL:' + s['host'], [a, b],
                a['time'], b['time'],
                f"WIN oturumu {s['logon_type']} / 4672 ayricalik verildi; tek basina saldiri kaniti degil."
            ))
    for e in events:
        if e['event_id'] == 4648 and (e['actor'] or e['target_user']):
            detections.append(_signal(
                'win_explicit_credentials', 'Acik kimlik bilgisi kullanimi (inceleme)',
                e['actor'], e['source'] or 'LOCAL:' + e['host'], [e],
                e['time'], e['time'],
                f"4648 goruldu; actor={e['actor'] or 'bilinmiyor'} / hedef={e['target_user'] or 'dogrulanamadi'}. Normal runas islemi de olabilir.",
                actor=e['actor'], target_user=e['target_user']
            ))
    # 3-4 failed RDP logons may deserve review, but >=5 is already covered
    # by the existing AD/WIN brute-force engine (avoid double alerts).
    groups = defaultdict(list)
    for e in events:
        if (e['event_id'] == 4625 and e['logon_type'] == '10' and e['user']
                and e['source'] and e['status'] != '0xc0000133'):
            groups[(e['host'], e['user'], e['source'])].append(e)
    for (host, user, source), group in groups.items():
        window = []
        for e in group:
            window.append(e)
            window = [a for a in window if e['time'] - a['time'] <= timedelta(minutes=10)]
        # If there are already >=5 failures, the existing brute-force
        # engine handles them; no duplicate WIN_SECURITY review signal.
        if 3 <= len(window) < 5:
            detections.append(_signal(
                'win_rdp_failed_logons', 'Tekrarlayan basarisiz RDP girisi (inceleme)',
                user, source, window,
                window[0]['time'], window[-1]['time'],
                f"{host}: {len(window)} RDP girisi basarisiz (4625, logon type 10)."
            ))
    detections.sort(key=lambda d: d['last_seen'], reverse=True)
    summary = dict(
        total=len(events), hosts=sorted({e['host'] for e in events}),
        counts={str(eid): counts[eid] for eid in sorted(counts)},
        successful_logons=counts[4624], failed_logons=counts[4625],
        rdp_logons=sum(e['event_id'] == 4624 and e['logon_type'] == '10' for e in events),
        privileged_events=counts[4672], explicit_credential_events=counts[4648],
        sessions_correlated=len(sessions),
        last_seen=events[-1]['time'].isoformat() if events else None,
        note='4648/4672 olaylari baglam sinyalidir; tek basina ihlal kaniti degildir.'
    )
    public_sessions = []
    for s in sorted(sessions.values(), key=lambda z:z['started'], reverse=True)[:40]:
        public_sessions.append(dict(
            host=s['host'], user=s['user'], logon_id=s['logon_id'],
            logon_type=s['logon_type'], source=s['source'],
            start=s['started'].isoformat(),
            end=s['ended'].isoformat() if s['ended'] else None,
            privileged=s['privileged'], reconnects=s['reconnects'],
            locks=s['locks'], unlocks=s['unlocks']))
    activity = [dict(event_id=e['event_id'], kind=NAMES[e['event_id']],
                     host=e['host'], user=e['user'], source=e['source'],
                     target_user=e['target_user'] if e['event_id'] == 4648 else '',
                     logon_type=e['logon_type'], time=e['time'].isoformat(),
                     record_id=e['record_id'])
                for e in reversed(events[-60:])]
    return dict(summary=summary, sessions=public_sessions,
                activity=activity, detections=detections[:60])


def analyze(limit=3000):
    cap = max(100, min(int(limit), 5000))
    with storage.LOCK, closing(storage.connect()) as db:
        rows = db.execute(
            'SELECT payload FROM events WHERE source=? ORDER BY id DESC LIMIT ?',
            ('WIN_SECURITY', cap)
        ).fetchall()
    items = []
    for (payload,) in rows:
        try:
            value = json.loads(payload)
            if isinstance(value, dict):
                items.append(value)
        except (ValueError, TypeError):
            continue
    return evaluate(items)
