"""AEGIS Identity bridge: read-only, evidence-oriented AD/WIN correlation.

Never writes raw events, changes identity accounts, or triggers SOAR.
"""
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
import os
import re
from app import storage

GROUP_IDS = {4728, 4729, 4732, 4733, 4756, 4757}
ADD_IDS = {4728, 4732, 4756}
CRIT_RIDS = {512, 518, 519, 544, 548, 549, 551}
CRIT_NAMES = {'domain admins', 'enterprise admins', 'schema admins',
              'administrators', 'account operators', 'server operators',
              'backup operators'}


def _raw(event):
    v = event.get('raw') or {}
    try:
        v = json.loads(v) if isinstance(v, str) else v
    except (ValueError, TypeError):
        return {}
    return v if isinstance(v, dict) else {}


def _time(value):
    try:
        t = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _account(x):
    s = str(x or '').strip().rsplit('\\', 1)[-1].split('@', 1)[0]
    if not s or s == '-' or s.endswith('$') or s.casefold() in {
        'bilinmiyor', 'system', 'anonymous logon'}:
        return ''
    return s.casefold()


def _src(value, host='', interactive=False):
    s = str(value or '').strip()
    if s.startswith('::ffff:'):
        s = s[7:]
    if s in ('', '-', 'Bilinmiyor', '::1', '127.0.0.1', '0.0.0.0'):
        return ('LOCAL:' + str(host).split('.')[0].upper()) if interactive else ''
    return s.casefold()


def _rows(source, limit):
    with storage.LOCK, storage.connect() as db:
        result = db.execute(
            'SELECT payload FROM events WHERE source=? ORDER BY id DESC LIMIT ?',
            (source, limit)
        ).fetchall()
    for (payload,) in result:
        try:
            item = json.loads(payload)
            if isinstance(item, dict):
                yield item
        except (TypeError, ValueError):
            continue


def _windows_legacy(limit=3000, items=None):
    result = []
    seen = set()
    for item in (items if items is not None else _rows('WIN_SECURITY', limit)):
        raw = _raw(item)
        try:
            eid = int(raw.get('event_id'))
        except (ValueError, TypeError):
            continue
        if eid not in (4624, 4625):
            continue
        t = _time(raw.get('timestamp') or item.get('event_time') or item.get('time'))
        user = _account(raw.get('user'))
        host = str(item.get('host') or 'WIN01')
        record = str(raw.get('record_id') or '')
        if not t or not user:
            continue
        key = (host.casefold(), eid, record or t.isoformat(), user)
        if key in seen:
            continue
        seen.add(key)
        lt = str(raw.get('logon_type') or '')
        if eid == 4624 and lt not in ('2', '7', '10', '11'):
            continue
        if eid == 4625 and lt not in ('2', '3', '7', '10', '11'):
            continue
        status = str(raw.get('status') or '').casefold()
        if eid == 4625 and status == '0xc0000133':
            continue  # clock skew is not a password-guessing signal
        src = _src(raw.get('source_ip') or raw.get('workstation'), host,
                   interactive=(lt in ('2', '7', '11')))
        result.append(dict(event_id=eid, user=user, source=src, host=host,
                           time=t, record_id=record, logon_type=lt,
                           kind='success' if eid == 4624 else 'failure',
                           provenance='WIN_SECURITY'))
    return result


def _windows_normalized(items):
    """Adapter for identical correlation fields, using the canonical schema."""
    from app.identity_events import normalize
    result, seen = [], set()
    for item in items:
        e = normalize(item)
        if not e or e['event_id'] not in (4624, 4625):
            continue
        eid = e['event_id']
        t = _time(e['event_time'])
        user = e['user']
        host = e['host']
        record = e['record_id']
        if not t or not user:
            continue
        key = (host.casefold(), eid, record or t.isoformat(), user)
        if key in seen:
            continue
        seen.add(key)
        lt = e['logon_type']
        if eid == 4624 and lt not in ('2', '7', '10', '11'):
            continue
        if eid == 4625 and lt not in ('2', '3', '7', '10', '11'):
            continue
        if eid == 4625 and e['status'] == '0xc0000133':
            continue
        src = _src(e['source_identity'], host, interactive=(lt in ('2', '7', '11')))
        result.append(dict(event_id=eid, user=user, source=src, host=host,
                           time=t, record_id=record, logon_type=lt,
                           kind='success' if eid == 4624 else 'failure',
                           provenance='WIN_SECURITY'))
    return result


def _win_key(event):
    return (event['host'].casefold(), event['event_id'],
            event['record_id'] or event['time'].isoformat(), event['user'])


def _windows_with_stats(limit=3000):
    """Default: shadow (legacy output). Set env to 'enabled' to switch.

    No persistence or new alerts are introduced by this adapter. The changes
    to correlation output take effect ONLY when mode is explicitly enabled.
    """
    mode = os.getenv('AEGIS_IDENTITY_NORMALIZER_MODE', 'shadow').strip().lower()
    if mode not in ('legacy', 'shadow', 'enabled'):
        mode = 'legacy'
    if mode == 'legacy':
        return _windows_legacy(limit), {'mode': 'legacy'}
    items = list(_rows('WIN_SECURITY', limit))
    original = _windows_legacy(limit, items=items)
    try:
        normalized = _windows_normalized(items)
    except Exception as exc:
        # The legacy answer must remain available even on malformed telemetry.
        import logging
        logging.getLogger(__name__).exception('Identity shadow adapter failed')
        return original, {'mode': mode, 'state': 'fallback_legacy',
                          'error_type': type(exc).__name__}
    if mode == 'enabled':
        return normalized, {'mode': 'enabled', 'input_events': len(items),
                            'normalized_events': len(normalized)}
    old_keys = {_win_key(e) for e in original}
    new_keys = {_win_key(e) for e in normalized}
    return original, {'mode': 'shadow', 'input_events': len(items),
                      'legacy_events': len(original),
                      'normalized_events': len(normalized),
                      'new_only': len(new_keys - old_keys),
                      'legacy_only': len(old_keys - new_keys),
                      'state': 'comparison_only'}


def _windows(limit=3000):
    """Backward-compatible private bridge helper; returns list as before."""
    return _windows_with_stats(limit)[0]


def _ad_auth(ad_events):
    result = []
    for e in ad_events:
        eid = e.get('event_id')
        if eid not in (4624, 4625, 4771, 4776):
            continue
        kind = e.get('kind')
        if kind not in ('failure', 'success'):
            continue
        if eid == 4776 and kind == 'success':
            continue  # NTLM verification is not an interactive logon
        if eid == 4624 and str(e.get('logon_type')) not in ('2', '7', '10', '11'):
            continue
        if eid == 4625 and str(e.get('status')).casefold() == '0xc0000133':
            continue
        t = e.get('_t') or _time(e.get('time'))
        user = _account(e.get('user'))
        host = str(e.get('host') or 'DC01')
        if not t or not user:
            continue
        src = _src(e.get('source'), host,
                   interactive=str(e.get('logon_type')) in ('2', '7', '11'))
        result.append(dict(event_id=eid, user=user, source=src, host=host,
                           time=t, record_id=str(e.get('record_id') or ''),
                           logon_type=str(e.get('logon_type') or ''), kind=kind,
                           provenance='AD'))
    return result


def _latest_users():
    snapshots = {}
    for e in _rows('AD_INVENTORY', 40):
        r = _raw(e)
        if r.get('schema') != 'aegis.ad_inventory.v2':
            continue
        try:
            sid = str(r['snapshot_id'])
            part, count, total = int(r['part_index']), int(r['part_count']), int(r['total_users'])
        except (ValueError, KeyError, TypeError):
            continue
        if not (1 <= part <= count <= 100 and 1 <= total <= 10000):
            continue
        s = snapshots.setdefault(sid, dict(count=count, total=total, parts={},
                                           time=_time(r.get('collected_at'))))
        if s['count'] == count and s['total'] == total:
            s['parts'][part] = r['users'] if isinstance(r.get('users'), list) else []
    ready = []
    for v in snapshots.values():
        if not v['time'] or len(v['parts']) != v['count']:
            continue
        users = {}
        for i in range(1, v['count'] + 1):
            for u in v['parts'][i]:
                if isinstance(u, dict) and u.get('sid') and u.get('sam'):
                    users[str(u['sid']).casefold()] = str(u['sam'])
        if len(users) == v['total']:
            ready.append((v['time'], users))
    return max(ready, key=lambda a: a[0])[1] if ready else {}


def _group_changes(limit, users, ai):
    out = []
    for item in _rows('AD', limit):
        raw = _raw(item)
        try:
            eid = int(raw.get('event_id'))
        except (ValueError, TypeError):
            continue
        if eid not in GROUP_IDS:
            continue
        f = raw.get('fields') or {}
        if not isinstance(f, dict):
            continue
        t = _time(raw.get('time') or item.get('event_time') or item.get('time'))
        if not t:
            continue
        group = str(f.get('TargetUserName') or '').strip()
        group_sid = str(f.get('TargetSid') or '').strip()
        member_sid = str(f.get('MemberSid') or '').strip()
        member_dn = str(f.get('MemberName') or '').strip()
        actor = str(f.get('SubjectUserName') or '').strip()
        member = users.get(member_sid.casefold(), '')
        # DN's CN is a display name, not a verified sAMAccountName.
        # If SID cannot be mapped, leave identity unattributed.
        rid = str(raw.get('record_id') or '')
        host = str(item.get('host') or raw.get('computer') or 'DC01')
        is_critical = (group.casefold() in CRIT_NAMES or
                       (group_sid.startswith('S-1-5-') and
                        group_sid.rsplit('-', 1)[-1].isdigit() and
                        int(group_sid.rsplit('-', 1)[-1]) in CRIT_RIDS))
        addition = eid in ADD_IDS
        sev = 'high' if is_critical else 'medium'
        rule = 'priv_group' if addition else 'group_member_removed'
        title = 'AD gruba uye eklendi' if addition else 'AD gruptan uye cikarildi'
        mitre = 'T1098'
        out.append(dict(rule=rule, severity=sev, title=title,
                        detail=f"{actor or '?'} -> {group or '?'} / member={member or member_dn or member_sid or '?'} "
                               '(uye kimligi SID ile dogrulanmadi)' if not member else
                               f"{actor or '?'} -> {group or '?'} / member={member}",
                        user=member, target_user=member, actor=actor, group=group,
                        group_sid=group_sid, member_sid=member_sid, member_dn=member_dn,
                        identity_verified=bool(member), source=host, count=1,
                        mitre=dict(id=mitre, name=ai.MITRE[mitre][0], tactic=ai.MITRE[mitre][1]),
                        first_seen=t.isoformat(), last_seen=t.isoformat(),
                        evidence=[dict(source='AD', host=host, event_id=eid,
                                       record_id=rid, time=t.isoformat())]))
    return out


def _auth_detections(ad_events, wins, ai):
    auth = _ad_auth(ad_events) + wins
    distinct = {}
    for a in auth:
        key = (a['provenance'], a['host'].casefold(), a['event_id'],
               a['record_id'] or a['time'].isoformat(), a['user'])
        distinct[key] = a
    by_pair = defaultdict(list)
    by_source = defaultdict(list)
    for a in distinct.values():
        if a['kind'] == 'failure' and a['source']:
            by_pair[(a['user'], a['source'])].append(a)
            by_source[a['source']].append(a)
    found = []
    def add(rule, sev, code, title, items, account='', source=''):
        ts = [a['time'] for a in items]
        found.append(dict(rule=rule, severity=sev, title=title,
                          detail=f"{account or 'Coklu hesap'} / {source}: {len(items)} kanit.",
                          user=account, source=source, count=len(items),
                          mitre=dict(id=code, name=ai.MITRE[code][0], tactic=ai.MITRE[code][1]),
                          first_seen=min(ts).isoformat(), last_seen=max(ts).isoformat(),
                          evidence=[dict(source=a['provenance'], host=a['host'],
                                         event_id=a['event_id'], record_id=a['record_id'],
                                         time=a['time'].isoformat()) for a in items[:30]]))
    for (user, source), entries in by_pair.items():
        entries.sort(key=lambda e:e['time'])
        # Sliding window: latest qualifying window, not all historical failures.
        window = []
        for f in entries:
            window.append(f)
            window = [x for x in window if f['time'] - x['time'] <= timedelta(minutes=10)]
            if len(window) >= 5:
                if any(x['provenance'] == 'WIN_SECURITY' for x in window):
                    add('identity_brute_force', 'high', 'T1110.001',
                        'WIN/AD brute-force supheleri', window, user, source)
                candidates = sorted((a for a in distinct.values()
                    if a['kind'] == 'success' and a['event_id'] == 4624
                    and a['logon_type'] in ('2', '10', '11')
                    and a['user'] == user and a['source'] == source
                    and f['time'] <= a['time'] <= f['time'] + timedelta(minutes=15)),
                    key=lambda a:a['time'])
                if candidates:
                    add('success_after_fail', 'critical', 'T1078',
                        'Basarisiz girislerden sonra interaktif oturum',
                        window + candidates[:1], user, source)
                break
    for source, entries in by_source.items():
        entries.sort(key=lambda e:e['time'])
        window = []
        for e in entries:
            window.append(e)
            window = [x for x in window if e['time'] - x['time'] <= timedelta(minutes=10)]
            if len({x['user'] for x in window}) >= 5 and any(x['provenance'] == 'WIN_SECURITY' for x in window):
                add('identity_password_spray', 'high', 'T1110.003',
                    'WIN/AD password spraying supheleri', window, '', source)
                break
    return found, len(wins)


# AEGIS_IDENTITY_EVIDENCE_FIX_20261031
# Gercek olaylardan kanit bagla; eksik kanit uydurma.

def _legacy_evidence(detections, ad_events):
    def account(value):
        return str(value or '').strip().casefold().rsplit('\\', 1)[-1].split('@', 1)[0]

    for d in detections:
        rule = d.get('rule')

        if rule not in ('brute_force', 'unauthorized_share_access'):
            continue

        if d.get('evidence'):
            continue

        start = _time(d.get('first_seen'))
        end = _time(d.get('last_seen'))

        if not start or not end:
            continue

        matches = []
        seen = set()

        for ev in ad_events:
            t = ev.get('_t') or _time(ev.get('time'))

            if not t:
                continue

            if not (
                start - timedelta(seconds=1)
                <= t <=
                end + timedelta(seconds=1)
            ):
                continue

            if str(ev.get('source') or '').casefold() != str(d.get('source') or '').casefold():
                continue

            if account(ev.get('user')) != account(d.get('user')):
                continue

            if rule == 'brute_force' and ev.get('kind') != 'failure':
                continue

            if rule == 'unauthorized_share_access':
                if ev.get('event_id') != 5145:
                    continue
                if ev.get('audit_result') != 'failure':
                    continue

            host = str(ev.get('host') or 'DC01')
            rid = str(ev.get('record_id') or '')

            key = (
                host.casefold(),
                ev.get('event_id'),
                rid or t.isoformat()
            )

            if key in seen:
                continue

            seen.add(key)

            matches.append({
                'source': 'AD',
                'host': host,
                'event_id': ev.get('event_id'),
                'record_id': rid,
                'time': t.isoformat()
            })

        if matches:
            matches.sort(key=lambda x: x['time'])
            d['evidence'] = matches[-30:]
            d['evidence_observed'] = len(matches)


def enhance(base, ad_events, ai, limit=2000):
    """Keep legacy output schema and remove only known invalid/ambiguous rules."""
    wins, normalizer_stats = _windows_with_stats(3000)
    users = _latest_users()
    new_auth, win_count = _auth_detections(ad_events, wins, ai)
    changes = _group_changes(limit, users, ai)
    obsolete = {'success_after_fail', 'priv_group', 'group_member_removed'}
    detections = [d for d in base.get('detections', []) if d.get('rule') not in obsolete]
    detections.extend(changes)
    detections.extend(new_auth)
    # AEGIS_WIN_SECURITY_INTEL_20261031: context-only WIN_SECURITY analysis
    # Keep legacy detection and incident thresholds unchanged.
    from app import win_security_intel
    win_context = win_security_intel.analyze(limit=3000)
    base['win_security'] = win_context
    _legacy_evidence(detections, ad_events)
    detections.sort(key=lambda d: (ai.SEV.get(d.get('severity'), 0), d.get('last_seen', '')),
                    reverse=True)
    base['detections'] = detections
    base['version'] = str(base.get('version', 'v6')) + '+identity-bridge'
    base['identity_bridge'] = dict(win_events=win_count, group_changes=len(changes),
                                   inventory_accounts=len(users), model='evidence-v1',
                                   note='AD olay akisi korunur; WIN_SECURITY korelasyona dahildir.')
    base['identity_bridge']['normalizer'] = normalizer_stats
    base['entities'] = ai.entity_risk(detections)
    mt = Counter(d['mitre']['id'] for d in detections if d.get('mitre'))
    base['mitre'] = [dict(id=k, name=ai.MITRE[k][0], tactic=ai.MITRE[k][1], count=v)
                     for k, v in mt.most_common() if k in ai.MITRE]
    base['findings'] = [dict(level='high' if d['severity'] in ('critical', 'high') else 'medium',
                             title=f"[{d['severity'].upper()}] {d['title']}", detail=d['detail'])
                        for d in detections[:8]] or base.get('findings', [])
    base['playbooks'] = [dict(rule=r, title=next(d['title'] for d in detections if d['rule'] == r),
                              steps=[dict(phase=a, action=b, approval=bool(c))
                                     for a,b,c in ai.PLAYBOOKS[r]])
                         for r in dict.fromkeys(d['rule'] for d in detections) if r in ai.PLAYBOOKS]
    base['correlations'] = [dict(user=d.get('user', ''), source=d.get('source', ''),
                                 count=d['count'], window_minutes=10,
                                 last_seen=d['last_seen'], severity=d['severity'])
                            for d in detections if d['rule'] in ('brute_force', 'identity_brute_force', 'success_after_fail')]
    return base


def incidents(detections):
    """Return a small, bounded collection, preserving network incident schema."""
    selected = [d for d in detections if d.get('severity') in ('high', 'critical')]
    out = []
    for d in selected[:50]:
        evidence = d.get('evidence') or []
        stamp = d.get('last_seen') or ''
        rawid = '|'.join((d.get('rule',''), d.get('user',''), d.get('source',''),
                          d.get('first_seen','')))
        import hashlib
        iid = 'INC-ID-' + hashlib.sha256(rawid.encode()).hexdigest()[:14].upper()
        out.append(dict(id=iid, category='identity', title=d.get('title','Identity'),
                        risk='critical' if d['severity'] == 'critical' else 'high',
                        confidence='low' if not evidence or str(d.get('source') or '').upper().startswith('LOCAL:') else 'medium',
                        risk_score=90 if d['severity'] == 'critical' else 65,
                        source_ip=d.get('source') or '', destination_ip='',
                        user=d.get('user') or '', actor=d.get('actor') or '',
                        group=d.get('group') or '', rule=d['rule'],
                        first_seen=d.get('first_seen',''), last_seen=stamp,
                        evidence_count=max(len(evidence), int(d.get('count', 1))),
                        evidence=evidence[:30], detail=d.get('detail',''),
                        possible_mitre=d.get('mitre',{}).get('id'),
                        limitations=['Risk priority, not a confirmed compromise.',
                                     'Only observed events in the query sample are included.']))
    return out
