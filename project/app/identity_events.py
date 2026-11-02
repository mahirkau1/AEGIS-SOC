"""Canonical, read-only Identity event adapter (schema v1).

Converts WIN_SECURITY and AD events into a deterministic, evidence-oriented
shape. Does not write to SQLite, emit incidents, or make security decisions.
Missing identity/SID fields remain missing; no guessed account ownership.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json

SCHEMA = 'aegis.identity.event.v1'
IDENTITY_SOURCES = frozenset({'WIN_SECURITY', 'AD'})
_SUCCESS = frozenset({4624})
_FAILURE = frozenset({4625, 4771})


def _object(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            obj = json.loads(value)
            return obj if isinstance(obj, dict) else {}
        except (TypeError, ValueError):
            return {}
    return {}


def _field(raw, *names):
    """Canonical field lookup; nested Windows event_data/fields before top level.

    Preserves the existing WIN_SECURITY field precedence to avoid a collision
    between event metadata and the actual Windows security event fields.
    """
    found = {}
    for section in (raw.get('fields'), raw.get('event_data'), raw):
        if not isinstance(section, dict):
            continue
        for k, v in section.items():
            name = ''.join(ch for ch in str(k).casefold() if ch.isalnum())
            if name not in found or not str(found[name] or '').strip():
                found[name] = v
    for name in names:
        norm = ''.join(c for c in name.casefold() if c.isalnum())
        value = found.get(norm)
        if value is not None and str(value).strip() not in ('', '-'):
            return str(value).strip()
    return ''


def _time(value):
    if not value:
        return ''
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).strip().replace('Z', '+00:00'))
        if dt.tzinfo is None:
            # No timezone means unknown provenance, not an assumed UTC time.
            return ''
        return dt.astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        return ''


def _account(value):
    account = str(value or '').strip().rsplit('\\', 1)[-1].split('@', 1)[0]
    if not account or account in ('-', '?') or account.endswith('$'):
        return ''
    if account.casefold() in ('system', 'anonymous logon', 'local service',
                              'network service', 'bilinmiyor'):
        return ''
    return account.casefold()


def _source_address(value):
    value = str(value or '').strip()
    if not value or value == '-':
        return ''
    if value.startswith('::ffff:'):
        value = value[7:]
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return ''  # workstation name is not an IP address
    if ip.is_unspecified or ip.is_loopback:
        return ''
    return ip.compressed.casefold()


def normalize(item):
    """Return a JSON-serializable dict or None for malformed/non-Identity input.

    The output is for evidence and correlation, not an assertion of compromise.
    A source record ID is meaningful only inside its own source + host scope.
    """
    if not isinstance(item, dict):
        return None
    source = str(item.get('source') or '').strip().upper()
    if source not in IDENTITY_SOURCES:
        return None
    raw = _object(item.get('raw'))
    if not raw:
        return None
    try:
        event_id = int(_field(raw, 'event_id', 'EventID'))
    except (TypeError, ValueError):
        return None
    if not 0 < event_id < 65536:
        return None
    host = str(item.get('host') or _field(raw, 'computer', 'Computer') or '').strip().split('.')[0].upper()
    host = host or 'UNKNOWN'
    record_id = _field(raw, 'record_id', 'EventRecordID', 'RecordId')
    event_time = (_time(_field(raw, 'timestamp', 'time', 'event_time', 'TimeCreated'))
                  or _time(item.get('event_time')) or _time(item.get('time')))
    received_at = _time(item.get('time'))
    user = _account(_field(raw, 'user', 'TargetUserName', 'AccountName', 'subject_user', 'SubjectUserName'))
    actor = _account(_field(raw, 'subject_user', 'SubjectUserName', 'user', 'AccountName'))
    target_user = _account(_field(raw, 'target_user', 'TargetUserName', 'target_account'))
    if event_id == 4648:
        user = actor
    src = _source_address(_field(raw, 'source_ip', 'IpAddress', 'ClientAddress', 'SourceNetworkAddress'))
    workstation = _field(raw, 'workstation', 'WorkstationName', 'Workstation')
    source_identity = src or workstation.casefold()
    if source_identity in ('-', 'bilinmiyor'):
        source_identity = ''
    status = _field(raw, 'status', 'Status', 'SubStatus').casefold()
    logon_type = _field(raw, 'logon_type', 'LogonType')
    logon_id = _field(raw, 'logon_id', 'TargetLogonId', 'SubjectLogonId', 'LogonId').casefold()
    if event_id in _SUCCESS:
        outcome = 'success'
    elif event_id in _FAILURE:
        outcome = 'failure'
    else:
        audit = _field(raw, 'audit_result') or str(raw.get('audit_result') or '')
        outcome = audit.casefold() if audit.casefold() in ('success', 'failure') else 'observed'
    user_sid = _field(raw, 'TargetUserSid', 'TargetSid', 'UserSid')
    actor_sid = _field(raw, 'SubjectUserSid')
    is_group_change = event_id in (4728, 4729, 4732, 4733, 4756, 4757)
    group = _field(raw, 'TargetUserName') if is_group_change else ''
    group_sid = (_field(raw, 'GroupSid', 'TargetSid') if is_group_change
                 else _field(raw, 'GroupSid'))
    member_sid = _field(raw, 'MemberSid')
    if is_group_change:
        # TargetUserName names the group in these events, not an account.
        user = ''
        target_user = ''
    # SID strings are preserved as claims in the source event, not proof of
    # current SID-to-name ownership. No inference from display name or DN.
    if record_id:
        uid_material = json.dumps([source, host, event_id, record_id], separators=(',', ':'))
    else:
        # Without EventRecordID, identical replays should share an ID while
        # genuinely distinct raw records should not collapse merely by time.
        uid_material = json.dumps([source, host, event_id, event_time, raw],
                                  sort_keys=True, ensure_ascii=False, default=str,
                                  separators=(',', ':'))
    event_uid = hashlib.sha256(uid_material.encode('utf-8')).hexdigest()
    warnings = []
    if not record_id:
        warnings.append('record_id_missing')
    if not event_time:
        warnings.append('event_time_missing')
    if not user:
        warnings.append('user_unattributed')
    return {
        'schema': SCHEMA, 'event_uid': event_uid,
        'evidence_ref': {'source': source, 'host': host, 'event_id': event_id,
                         'record_id': record_id, 'time': event_time},
        'source': source, 'host': host, 'event_id': event_id,
        'record_id': record_id, 'event_time': event_time,
        'received_at': received_at, 'user': user, 'actor': actor,
        'target_user': target_user, 'user_sid': user_sid,
        'actor_sid': actor_sid, 'group': group, 'group_sid': group_sid,
        'member_sid': member_sid, 'logon_id': logon_id,
        'logon_type': logon_type, 'source_ip': src,
        'source_identity': source_identity, 'status': status,
        'outcome': outcome, 'quality': 'partial' if warnings else 'complete',
        'warnings': warnings,
    }
