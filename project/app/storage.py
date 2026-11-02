"""Bounded SQLite event store; only the Python standard library is required."""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DB = Path(os.getenv('SOC_DB_PATH', str(Path(__file__).resolve().parent.parent / 'data' / 'soc.sqlite3')))
DB.parent.mkdir(parents=True, exist_ok=True)
LOCK = threading.RLock()
MAX_EVENTS = max(1000, int(os.getenv('SOC_MAX_EVENTS', '50000')))


def connect():
    db = sqlite3.connect(str(DB), timeout=15)
    db.execute('PRAGMA busy_timeout=15000')
    db.execute('PRAGMA journal_mode=WAL')
    return db


def init():
    with LOCK, connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL UNIQUE, received TEXT NOT NULL, source TEXT NOT NULL, severity TEXT NOT NULL, is_alert INTEGER NOT NULL, payload TEXT NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_events_alert ON events(is_alert,id DESC)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_events_source ON events(source,id DESC)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_events_received ON events(received)')


def fingerprint(item):
    # Source log timestamp is preserved in raw; repeated delivery is idempotent.
    return hashlib.sha256((item['source'] + '\0' + item.get('host', '') + '\0' + (item.get('raw') or item['message'])).encode('utf-8')).hexdigest()


def is_alert(item):
    p = item.get("parsed") or {}
    source = item.get("source", "")

    if source == "SYSMON" and p.get("detection"):
        return True

    if source == "SURICATA" and p.get("signature"):
        return True

    if str(p.get("action") or "").upper() in ("BLOCK", "REJECT", "DROP"):
        return True

    if source == "AD":
        try:
            raw = item.get("raw") or {}
            if isinstance(raw, str):
                raw = json.loads(raw)

            event_id = int(raw.get("event_id"))
            fields = raw.get("fields") or {}
            status = str(
                fields.get("Status") or
                fields.get("SubStatus") or ""
            ).lower()

            if event_id in (4625, 4740, 4771):
                return True

            if event_id == 4776:
                return status not in ("", "0x0", "0x00000000")

        except (ValueError, TypeError, AttributeError):
            return False

    return False

def insert(item):
    alert = is_alert(item)
    with LOCK, connect() as db:
        cur = db.execute('INSERT OR IGNORE INTO events(fingerprint,received,source,severity,is_alert,payload) VALUES(?,?,?,?,?,?)', (fingerprint(item), item['time'], item['source'], item['parsed']['severity'], int(alert), json.dumps(item, ensure_ascii=False)))
        inserted = cur.rowcount > 0
        if inserted and cur.lastrowid % 250 == 0:
            db.execute('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM events)', (MAX_EVENTS,))
    return inserted


def get_events(limit=100, offset=0, mode='alerts', source=None, since=None, until=None):
    """Read events using SQL filters *before* pagination.

    Time filters match SOC receipt timestamps. Event occurrence is in
    payload.event_time (new) or may be derived from raw (legacy).
    """
    limit = max(1, min(int(limit), 5000))
    offset = max(0, min(int(offset), 100000))
    clauses, args = [], []
    if mode == 'alerts':
        clauses.append('is_alert=1')
    elif mode == 'blocks':
        clauses.extend(('is_alert=1', 'source=?'))
        args.append('FIREWALL')
    elif mode != 'all':
        raise ValueError('Unsupported event mode')

    if source:
        sources = [s.strip().upper() for s in str(source).split(',') if s.strip()]
        if len(sources) > 8 or not all(s.replace('_', '').isalnum() and len(s) <= 40 for s in sources):
            raise ValueError('Invalid source filter')
        if sources:
            clauses.append('source IN (' + ','.join('?' for _ in sources) + ')')
            args.extend(sources)

    for op, value in (('>=', since), ('<=', until)):
        if value is not None:
            # SQLite julianday compares instants, including different UTC offsets.
            clauses.append(f'julianday(received) {op} julianday(?)')
            args.append(value.isoformat() if hasattr(value, 'isoformat') else str(value))

    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    with LOCK, connect() as db:
        rows = db.execute(
            f'SELECT payload FROM events{where} ORDER BY id DESC LIMIT ? OFFSET ?',
            (*args, limit, offset)
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def stats():
    with LOCK, connect() as db:
        total, alerts, critical = db.execute('SELECT COUNT(*), COALESCE(SUM(is_alert),0), COALESCE(SUM(CASE WHEN is_alert=1 AND severity IN ("critical","high") THEN 1 ELSE 0 END),0) FROM events').fetchone()
        sources = [x[0] for x in db.execute('SELECT DISTINCT source FROM events')]
    return {'total': total, 'alerts': alerts, 'critical': critical, 'sources': sources}

init()


# SYSMON_SOURCE_QUERY_V2
def get_sysmon_events(limit=1000, offset=0):
    limit = max(1, min(int(limit), 5000))
    offset = max(0, int(offset))
    with LOCK, connect() as db:
        rows = db.execute(
            "SELECT payload FROM events WHERE source=? ORDER BY id DESC LIMIT ? OFFSET ?",
            ("SYSMON", limit, offset)
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


# SYSMON_GUID_CORRELATION_V1
def get_sysmon_chain(host, process_guid, limit=500):
    """Return Sysmon evidence for one process and its immediate relatives."""
    host = str(host).strip()
    guid = str(process_guid).strip().lower()

    if not host or not guid or len(host) > 255 or len(guid) > 255:
        raise ValueError("Invalid host or ProcessGuid")

    limit = max(1, min(int(limit), 2000))

    with LOCK, connect() as db:
        rows = db.execute(
            """
            SELECT payload
            FROM events
            WHERE source = 'SYSMON'
            ORDER BY id DESC
            """
        ).fetchall()

    selected = []
    parent_guid = None

    for (raw,) in rows:
        event = json.loads(raw)
        parsed = event.get("parsed") or {}

        if str(event.get("host", "")).lower() != host.lower():
            continue

        current_guid = str(
            parsed.get("process_guid") or ""
        ).lower()

        if current_guid == guid:
            selected.append(event)

            if int(parsed.get("event_id") or 0) == 1:
                parent_guid = str(
                    parsed.get("parent_process_guid") or ""
                ).lower() or parent_guid

    for (raw,) in rows:
        event = json.loads(raw)
        parsed = event.get("parsed") or {}

        if str(event.get("host", "")).lower() != host.lower():
            continue

        current_guid = str(
            parsed.get("process_guid") or ""
        ).lower()

        child_parent = str(
            parsed.get("parent_process_guid") or ""
        ).lower()

        if (
            current_guid == parent_guid and parent_guid
        ) or (
            child_parent == guid and current_guid != guid
        ):
            selected.append(event)

    selected.sort(
        key=lambda event: event.get("time") or "",
        reverse=True
    )

    return selected[:limit]
