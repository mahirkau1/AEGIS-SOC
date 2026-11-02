"""AEGIS Phase 3A: evidence-first, read-only contextual identity review.

This DOES NOT replace User 360 V5 scores, create incidents, apply AD changes,
trigger detection rules, or infer access/attack paths. Exact SID matching only.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

SID = re.compile(r'^S-\d+(?:-\d+){2,}$', re.I)
AD_GROUP_ADD = {4728, 4732, 4756}
AD_GROUP_REMOVE = {4729, 4733, 4757}
AD_TARGET_ACCOUNT_CHANGE = {4720, 4722, 4724, 4725, 4726, 4738}
INTERESTING = AD_GROUP_ADD | AD_GROUP_REMOVE | AD_TARGET_ACCOUNT_CHANGE
MAX_SCAN = 3000
WINDOW_DAYS = 7
MAX_EVIDENCE = 20


def _obj(raw):
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and len(raw) <= 250000:
        try:
            out = json.loads(raw)
            return out if isinstance(out, dict) else {}
        except (TypeError, ValueError):
            pass
    return {}


def _field(fields, key):
    if not isinstance(fields, dict):
        return ''
    if key in fields:
        return str(fields[key] or '').strip()
    for k, val in fields.items():
        if str(k).casefold() == key.casefold():
            return str(val or '').strip()
    return ''


def _timestamp(value):
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return ts.astimezone(timezone.utc) if ts.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def _sid(value):
    s = str(value or '').strip()
    return s.upper() if SID.fullmatch(s) else ''


def read_recent_ad_events(db_path: Path, limit: int = MAX_SCAN):
    """Read the SOC event DB without mutating it or its journal settings."""
    if not 1 <= int(limit) <= MAX_SCAN:
        raise ValueError('Unsupported event read limit')
    path = Path(db_path).resolve()
    if not path.is_file():
        raise FileNotFoundError('SOC events DB not found')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
        db.execute('PRAGMA query_only=ON')
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone():
            raise ValueError('SOC events table missing')
        rows = db.execute('SELECT payload FROM events WHERE source=? ORDER BY id DESC LIMIT ?',
                          ('AD', limit)).fetchall()
    out = []
    for (payload,) in rows:
        e = _obj(payload)
        if e:
            out.append(e)
    return out


def evaluate(evidence: dict, events: list[dict], now: datetime | None = None):
    """Return a bounded *review-priority context* from verified SID-linked AD events.

    Fail closed on SID ambiguity. Privilege membership alone gives zero points.
    A missing event is not a guarantee of safety (bounded log history).
    """
    now = (now or datetime.now(timezone.utc))
    if now.tzinfo is None:
        raise ValueError('now must be timezone-aware')
    now = now.astimezone(timezone.utc)
    user = evidence.get('user') or {}
    user_sid = _sid(user.get('sid'))
    if not user_sid:
        raise ValueError('AD user SID is unavailable/invalid')
    collected = _timestamp(evidence.get('collected_at_utc'))
    stale = bool(evidence.get('stale')) or collected is None
    if collected and (now - collected > timedelta(days=7) or collected > now + timedelta(minutes=5)):
        stale = True
    # Domain group RID classification requires the user's validated domain SID.
    domain_prefix = user_sid.rsplit('-', 1)[0]
    tier0_sids = {f'{domain_prefix}-{rid}'.upper() for rid in (512, 518, 519)}
    enabled = user.get('enabled')
    tier0_groups = list(evidence.get('tier0_membership_evidence') or [])
    context = {
        'current_tier0_group_count': len(tier0_groups),
        'tier0_membership_observed': bool(tier0_groups),
        'enabled': enabled,
        'privilege_snapshot_stale': stale,
        'privilege_snapshot_at': evidence.get('collected_at_utc'),
    }
    # The score is an independent contextual review indicator, NOT the SOC score.
    dedup = set()
    signals = []
    qualifying = 0
    lower = now - timedelta(days=WINDOW_DAYS)
    for event in events[:MAX_SCAN]:
        if str(event.get('source') or '').upper() != 'AD':
            continue
        raw = _obj(event.get('raw'))
        try:
            eid = int(raw.get('event_id'))
        except (TypeError, ValueError):
            continue
        if eid not in INTERESTING:
            continue
        fields = raw.get('fields') or raw.get('event_data') or {}
        if not isinstance(fields, dict):
            continue
        at = _timestamp(raw.get('time') or raw.get('timestamp') or event.get('event_time'))
        if at is None or not lower <= at <= now + timedelta(minutes=5):
            continue
        member_sid = _sid(_field(fields, 'MemberSid'))
        target_sid = _sid(_field(fields, 'TargetSid'))
        host = str(event.get('host') or raw.get('computer') or '')[:128]
        record = str(raw.get('record_id') or '')[:80]
        # Only the affected member/target is attributed to this user's risk.
        # SubjectUserSid is an actor and must not be conflated with TargetSid.
        if eid in AD_GROUP_ADD | AD_GROUP_REMOVE:
            if member_sid != user_sid:
                continue
            group_sid = target_sid
            if not group_sid:
                continue
            is_tier0 = group_sid in tier0_sids
            if eid in AD_GROUP_REMOVE:
                category, points, title = 'group_removed', 0, 'Grup üyeliği kaldırıldı (bağlam)'
            elif is_tier0:
                category, points, title = 'tier0_group_added', 55, 'Tier-0 grubuna üyelik ekleme olayı'
            else:
                category, points, title = 'group_added', 12, 'AD grup üyeliği ekleme olayı'
        else:
            if target_sid != user_sid:
                continue
            group_sid = ''
            category = 'account_changed'
            points = 10
            title = 'AD hesap değişikliği / işlem girişimi'
            # 4724 records a password reset ATTEMPT; do not assert success.
            if eid == 4724:
                title = 'Parola sıfırlama girişimi kaydı'
        key = (host.casefold(), eid, record or at.isoformat(), user_sid, group_sid)
        if key in dedup:
            continue
        dedup.add(key)
        qualifying += 1
        signals.append({
            'category': category, 'title': title, 'points': points,
            'event_id': eid, 'time': at.isoformat(), 'host': host,
            'record_id': record, 'group_sid': group_sid,
            'subject_sid_verified': user_sid,
            'note': 'SID ile hedef eşleşmesi; olay tek başına kötü niyet/ihlal kanıtı değildir.',
        })

    signals.sort(key=lambda x: (x['time'], x['points']), reverse=True)
    score = min(100, sum(row['points'] for row in signals))
    if score >= 55:
        priority = 'inceleme_oncelikli'
    elif score > 0:
        priority = 'inceleme'
    else:
        priority = 'gozlem'
    return {
        'schema': 'aegis.identity.risk_context.v1', 'mode': 'shadow',
        'user': {'sid': user_sid, 'sam': str(user.get('sam') or '')},
        'priority_score': score, 'priority': priority,
        'existing_user360_score_unchanged': True,
        'window_days': WINDOW_DAYS, 'ad_events_scanned': min(len(events), MAX_SCAN),
        'matching_events': qualifying, 'signals': signals[:MAX_EVIDENCE],
        'signals_truncated': max(0, len(signals) - MAX_EVIDENCE),
        'context': context,
        'coverage': 'partial' if stale or len(events) >= MAX_SCAN else 'bounded',
        'limitations': (
            'Bu puan SOC alarmı veya saldırı kanıtı değildir. Sadece SID ile eşleşen '
            'son 7 günlük AD hesap/grup olaylarını değerlendirir. Yalnızca en son 3000 '
            'AD olayı taranır. Mevcut Tier-0 üyeliği tek başına puan üretmez; '
            'WIN_SECURITY/başarılı-başarısız girişler bu modelde puanlanmaz. '
            'SID içermeyen olaylara kullanıcı atfedilmez; tam geçmiş garantisi yoktur.'
        ),
    }
