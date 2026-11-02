"""Event occurrence time, distinct from SOC receipt time (no DB migration)."""
from datetime import datetime, timedelta, timezone
import json
import re

_SYSLOG_TIME = re.compile(r'^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))\b')


def parse_time(value):
    if not value:
        return None
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).strip().replace('Z', '+00:00'))
        return dt.astimezone(timezone.utc) if dt.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def _guard_clock(candidate, receipt):
    """Malformed sender timezone must not move an event hours into future.

    Old events remain old: never replace late-arriving historical telemetry.
    """
    if candidate and receipt and candidate > receipt + timedelta(minutes=10):
        return receipt
    return candidate


def occurred_at(event):
    """Return best-effort UTC occurrence time; legacy rows work unchanged.

    Use source timestamp when credible. Forwarding relays sometimes write a
    wrong timezone (+4h in supplied OPNsense filterlog sample), in which case
    receipt time is safer than a future incident window.
    """
    received = parse_time(event.get('time'))
    parsed = event.get('parsed') or {}
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except (ValueError, TypeError):
            parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    for key, value in (('event_time', event.get('event_time')),
                       ('event_timestamp', parsed.get('event_timestamp'))):
        candidate = parse_time(value)
        if candidate:
            return _guard_clock(candidate, received)

    source = str(event.get('source') or '').upper()
    raw = event.get('raw') or ''
    if isinstance(raw, dict):
        obj, raw_text = raw, ''
    else:
        raw_text, obj = str(raw), None
        if source in ('SYSMON', 'AD', 'SURICATA'):
            try:
                obj = json.loads(raw_text[raw_text.index('{'):])
            except (ValueError, TypeError):
                pass
    if isinstance(obj, dict):
        keys = ('timestamp', 'time') if source != 'AD' else ('time', 'timestamp')
        for key in keys:
            candidate = parse_time(obj.get(key))
            if candidate:
                return _guard_clock(candidate, received)
    if source in ('FIREWALL', 'DNS', 'SURICATA'):
        match = _SYSLOG_TIME.match(raw_text)
        if match:
            candidate = parse_time(match.group(1))
            if candidate:
                return _guard_clock(candidate, received)
    return received
