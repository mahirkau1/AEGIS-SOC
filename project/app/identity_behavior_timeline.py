"""AEGIS Phase 3B — bounded, SID-verified AD change history, read only.

No account-name matching, no login guessing, no privilege inference, no new incidents,
no replacement of Phase3A or User 360 risk scores.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import json

from app.identity_risk_context import (
    AD_GROUP_ADD, AD_GROUP_REMOVE, AD_TARGET_ACCOUNT_CHANGE,
    INTERESTING, MAX_SCAN, _obj, _field, _sid, _timestamp,
)

WINDOW_DAYS = 30
TIMELINE_LIMIT = 50
CLUSTER_MIN = 3
CLUSTER_MINUTES = 15

LABELS = {
    4720: 'Hesap oluşturma', 4722: 'Hesap etkinleştirme',
    4724: 'Parola sıfırlama girişimi', 4725: 'Hesap devre dışı bırakma',
    4726: 'Hesap silme', 4738: 'Hesap değişikliği',
    4728: 'Global gruba üye ekleme', 4729: 'Global gruptan üye çıkarma',
    4732: 'Yerel gruba üye ekleme', 4733: 'Yerel gruptan üye çıkarma',
    4756: 'Universal gruba üye ekleme', 4757: 'Universal gruptan üye çıkarma',
}


def analyze(user_evidence: dict, events: list[dict], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('now must be timezone aware')
    now = now.astimezone(timezone.utc)
    user = user_evidence.get('user') or {}
    sid = _sid(user.get('sid'))
    if not sid:
        raise ValueError('Verified user SID required')
    collected = _timestamp(user_evidence.get('collected_at_utc'))
    snapshot_stale = (bool(user_evidence.get('stale')) or not collected
                      or now-collected > timedelta(days=7)
                      or collected > now+timedelta(minutes=5))
    start = now - timedelta(days=WINDOW_DAYS)
    # A rolling 30*24h window spans parts of 31 UTC calendar dates.
    days = [(now.date()-timedelta(days=30-i)).isoformat() for i in range(31)]
    by_day = {d: {'date':d,'as_actor':0,'as_target':0,'events':0} for d in days}
    entries = []
    dedup = set()
    cutoff_future = now + timedelta(minutes=5)
    for e in events[:MAX_SCAN]:
        if str(e.get('source') or '').upper() != 'AD':
            continue
        raw = _obj(e.get('raw'))
        try:
            event_id = int(raw.get('event_id'))
        except (TypeError, ValueError):
            continue
        if event_id not in INTERESTING:
            continue
        f = raw.get('fields') or raw.get('event_data') or {}
        if not isinstance(f, dict):
            continue
        when = _timestamp(raw.get('time') or raw.get('timestamp') or e.get('event_time'))
        if when is None or not start <= when <= cutoff_future or when > now:
            continue
        actor = _sid(_field(f, 'SubjectUserSid'))
        target = _sid(_field(f, 'MemberSid') if event_id in AD_GROUP_ADD | AD_GROUP_REMOVE
                      else _field(f, 'TargetSid'))
        actor_match = actor == sid
        target_match = target == sid
        if not (actor_match or target_match):
            continue
        # For group change events TargetSid denotes the GROUP; never treat as the user.
        group_sid = _sid(_field(f, 'TargetSid')) if event_id in AD_GROUP_ADD | AD_GROUP_REMOVE else ''
        host = str(e.get('host') or raw.get('computer') or '')[:120]
        rec = str(raw.get('record_id') or '').strip()[:80]
        if rec:
            key = ('record',host.casefold(),rec,event_id)
        else:
            key = ('payload', hashlib.sha256(json.dumps({
                'eid':event_id,'when':when.isoformat(),'actor':actor,'target':target,
                'group':group_sid,'host':host,'fields':f
            },sort_keys=True,default=str).encode()).hexdigest())
        if key in dedup:
            continue
        dedup.add(key)
        role = 'both' if actor_match and target_match else ('actor' if actor_match else 'target')
        kind = ('group_add' if event_id in AD_GROUP_ADD else
                'group_remove' if event_id in AD_GROUP_REMOVE else 'account_change')
        row = {'event_id':event_id,'title':LABELS[event_id],'role':role,
               'kind':kind,'time':when.isoformat(),'host':host,'record_id':rec}
        entries.append(row)
        daily = by_day.get(when.date().isoformat())
        if daily is not None:
            daily['events'] += 1
            daily['as_actor'] += int(actor_match)
            daily['as_target'] += int(target_match)
    entries.sort(key=lambda x:(x['time'],x['event_id'],x['record_id']),reverse=True)
    # A burst marker is a review hint, NOT an attack label or a SOC alert.
    chron = sorted(_timestamp(row['time']) for row in entries)
    best = 0
    left = 0
    for right, ts in enumerate(chron):
        while left <= right and ts - chron[left] > timedelta(minutes=CLUSTER_MINUTES):
            left += 1
        best = max(best,right-left+1)
    as_actor = sum(row['role'] in ('actor','both') for row in entries)
    as_target = sum(row['role'] in ('target','both') for row in entries)
    recent_week = sum(1 for x in entries if _timestamp(x['time']) >= now-timedelta(days=7))
    previous_week = sum(1 for x in entries if now-timedelta(days=14) <= _timestamp(x['time']) < now-timedelta(days=7))
    markers = []
    if best >= CLUSTER_MIN:
        markers.append({'kind':'change_density','label':'15 dakikalık pencerede değişiklik yoğunluğu',
                        'max_events_in_15m':best,'interpretation':'İnceleme işareti; saldırı kanıtı değildir.'})
    partial = len(events)>=MAX_SCAN or snapshot_stale
    return {
        'schema':'aegis.identity.behavior_timeline.v1', 'mode':'shadow',
        'user':{'sid':sid,'sam':str(user.get('sam') or '')},
        'window_days':WINDOW_DAYS,'ad_events_scanned':min(len(events),MAX_SCAN),
        'observed_events':len(entries),'as_actor':as_actor,'as_target':as_target,
        'group_add_events':sum(x['kind']=='group_add' for x in entries),
        'group_remove_events':sum(x['kind']=='group_remove' for x in entries),
        'account_change_events':sum(x['kind']=='account_change' for x in entries),
        'last_7d':recent_week,'previous_7d':previous_week,
        'daily':list(by_day.values()), 'timeline':entries[:TIMELINE_LIMIT],
        'timeline_truncated':max(0,len(entries)-TIMELINE_LIMIT),
        'review_markers':markers,'snapshot_stale':snapshot_stale,
        'coverage':'partial' if partial else 'bounded',
        'existing_risk_scores_unchanged':True,
        'limitations':(
            'Son 3000 AD kaydı/30 gün ile sınırlı ve eksik olabilir. Yalnızca kesin SID '
            'eşleşmeleri sayılır; aktör ve hedef ayrı değerlendirilir. İşlem kaydı başarılı '
            'saldırı kanıtı değildir. 4724 bir girişimdir. Grup üyeliği tek başına risk '
            'oluşturmaz. Windows oturum açma olayları, ACL, GPO ve uç nokta erişim izinleri '
            'bu modelde değerlendirilmez. Bu model SOC alarmı veya otomatik müdahale üretmez.'
        ),
    }
