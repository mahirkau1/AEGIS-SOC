"""AEGIS Identity 2D: evidence-only read API for the standalone Phase 2C sidecar.

Only serves data when SOC Dashboard Basic authentication has been explicitly
configured. Never turns group membership into endpoint permissions/attack paths.
"""
from __future__ import annotations

from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
import os
import base64
import secrets
import ipaddress
from urllib.parse import urlsplit
from pathlib import Path
import re
import sqlite3

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix='/api/identity/privileges', tags=['Identity Privilege Evidence'])
SID_RE = re.compile(r'^S-\d+(?:-\d+){2,}$', re.I)
EXPECTED_TABLES = {'priv_snapshots', 'priv_users', 'priv_groups', 'priv_edges'}
EDGE_KINDS = {'user_memberof', 'user_primarygroup', 'group_memberof'}
MAX_EDGES = 100000


# AEGIS_IDENTITY_PHASE2E_LOOPBACK_V1
# Intentionally restrict these privileged directory endpoints even when the main
# API binds 0.0.0.0 for collectors. The dashboard UI itself remains unchanged.
def _local_request(request: Request) -> bool:
    client = request.client
    if client is None:
        return False
    try:
        if not ipaddress.ip_address(client.host).is_loopback:
            return False
    except ValueError:
        return False
    # Host validation also reduces DNS-rebinding and accidental proxy exposure.
    host = request.headers.get('host', '').strip().lower()
    if not re.fullmatch(r'(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?', host):
        return False
    origin = request.headers.get('origin', '').strip()
    if origin:
        try:
            parts = urlsplit(origin)
            if parts.scheme not in ('http', 'https') or parts.hostname not in ('localhost', '127.0.0.1', '::1'):
                return False
        except ValueError:
            return False
    if request.headers.get('sec-fetch-site', '') == 'cross-site':
        return False
    return True


# AEGIS_IDENTITY_PHASE2F_LABHOST_V1
# Opt-in: allow the same Windows host to access its own LAN address on port 8088.
# No general subnet exposure is introduced by this helper.
def _same_host_lab_request(request: Request) -> bool:
    if os.getenv('AEGIS_IDENTITY_LAB_LAN_ACCESS', '').strip() != '1':
        return False
    expected = os.getenv('AEGIS_IDENTITY_LAB_HOST', '192.168.1.111').strip()
    try:
        addr = ipaddress.ip_address(expected)
        if addr.version != 4 or not addr.is_private or addr.is_loopback:
            return False
        if request.client is None or ipaddress.ip_address(request.client.host) != addr:
            return False
    except ValueError:
        return False

    expected_host = f'{expected}:8088'
    if request.headers.get('host', '').strip().lower() != expected_host:
        return False

    origin = request.headers.get('origin', '').strip()
    if origin:
        try:
            parts = urlsplit(origin)
            if (parts.scheme != 'http' or parts.netloc.lower() != expected_host or
                    parts.username is not None or parts.password is not None or
                    parts.path not in ('', '/') or parts.query or parts.fragment):
                return False
        except ValueError:
            return False
    if request.headers.get('sec-fetch-site', '').lower() not in ('', 'none', 'same-origin'):
        return False
    # Do not trust asserted proxy host/client headers for this lab-only exception.
    if request.headers.get('forwarded') or request.headers.get('x-forwarded-host'):
        return False
    return True


def require_configured_auth(request: Request):
    # Localhost remains allowed. The explicit lab exception accepts only
    # same-host access through the Windows machine's own 192.168.x.x address.
    # Other machines on the LAN are not given access by this patch.
    if not (_local_request(request) or _same_host_lab_request(request)):
        raise HTTPException(status_code=403, detail='Privilege evidence is restricted to the analyst computer')

    user = os.getenv('SOC_DASHBOARD_USER', '')
    password = os.getenv('SOC_DASHBOARD_PASSWORD', '')
    # A partially configured password never activates a bypass.
    if bool(user) != bool(password):
        raise HTTPException(status_code=503, detail='Incomplete Dashboard authentication configuration')

    # If the regular Dashboard has Basic auth configured, honor it on localhost.
    if user and password:
        supplied = request.headers.get('Authorization', '')
        if not supplied.startswith('Basic '):
            raise HTTPException(status_code=401, detail='Analyst authorization required',
                                headers={'WWW-Authenticate': 'Basic realm="AEGIS SOC"'})
        try:
            decoded = base64.b64decode(supplied[6:], validate=True).decode('utf-8')
            given_user, given_pass = decoded.split(':', 1)
        except (ValueError, UnicodeDecodeError, TypeError):
            raise HTTPException(status_code=401, detail='Invalid analyst authorization')
        if not (secrets.compare_digest(given_user, user) and
                secrets.compare_digest(given_pass, password)):
            raise HTTPException(status_code=401, detail='Invalid analyst authorization')
        return

    # Independent local-only mode does not turn on Basic auth on the LAN API.
    # Local Windows access is its security boundary; user opt-in is required.
    if os.getenv('AEGIS_IDENTITY_LOCAL_ONLY', '').strip() != '1':
        raise HTTPException(status_code=503, detail='Privilege evidence is disabled; enable local-only mode on the SOC API process')


def sidecar_path() -> Path:
    value = os.getenv('AEGIS_IDENTITY_PRIVILEGE_DB', '').strip()
    return Path(value) if value else Path.home() / 'Desktop' / 'AEGIS_Identity_Store' / 'identity_privilege.sqlite3'


def open_sidecar(db: Path):
    db = Path(db).resolve()
    if not db.is_file():
        raise FileNotFoundError('Privilege sidecar is not available')
    # Opening via URI mode=ro, and PRAGMA query_only ensures no writes.
    conn = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=5)
    try:
        conn.execute('PRAGMA query_only=ON')
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        tables = {x[0] for x in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if version != 1 or not EXPECTED_TABLES.issubset(tables):
            raise ValueError('Unsupported Identity Privilege sidecar schema')
    except BaseException:
        conn.close()
        raise
    return conn


def latest(conn):
    return conn.execute('''SELECT snapshot_id, collected_at, domain_sid, users_count, groups_count
                           FROM priv_snapshots ORDER BY collected_at DESC, imported_at DESC LIMIT 1''').fetchone()


def summary(db: Path):
    with closing(open_sidecar(db)) as conn:
        rec = latest(conn)
        if not rec:
            raise ValueError('No imported AD privilege snapshot')
        snap, stamp, domain_sid, users_count, groups_count = rec
        edges = conn.execute('SELECT evidence_kind, COUNT(*) FROM priv_edges WHERE snapshot_id=? GROUP BY evidence_kind', (snap,)).fetchall()
        counts = {name: count for name, count in edges}
        return {'schema': 'aegis.identity.privilege.read.v1', 'status': 'ready',
                'snapshot_id': snap, 'collected_at_utc': stamp,
                'users_count': users_count, 'groups_count': groups_count,
                'direct_explicit_edges': counts.get('user_memberof', 0),
                'primary_group_edges': counts.get('user_primarygroup', 0),
                'nested_group_edges': counts.get('group_memberof', 0),
                'note': 'Directory group membership only; no endpoint rights or attack paths inferred.'}


def user_evidence(db: Path, *, sid: str | None = None, sam: str | None = None):
    if bool(sid) == bool(sam):
        raise ValueError('Specify either a user SID or a SAM account name')
    if sid and (len(sid) > 256 or not SID_RE.fullmatch(sid)):
        raise ValueError('Invalid SID')
    if sam and (len(sam) > 256 or not sam.strip() or any(ch in sam for ch in '\x00\r\n')):
        raise ValueError('Invalid SAM account name')
    with closing(open_sidecar(db)) as conn:
        record = latest(conn)
        if not record:
            raise ValueError('No AD privilege snapshot')
        snapshot_id, stamp, domain_sid, _, _ = record
        if sid:
            users = conn.execute('SELECT sid,sam,enabled FROM priv_users WHERE snapshot_id=? AND sid=? COLLATE NOCASE', (snapshot_id, sid)).fetchall()
        else:
            # Case-insensitive exact SAM, no wildcard or substring matching.
            users = conn.execute('SELECT sid,sam,enabled FROM priv_users WHERE snapshot_id=? AND sam=? COLLATE NOCASE', (snapshot_id, sam.strip())).fetchall()
        if not users:
            raise LookupError('Account not present in the latest AD evidence snapshot')
        if len(users) != 1:
            raise ValueError('Ambiguous identity; select by SID')
        user_sid, user_sam, enabled = users[0]

        groups = {g[0]: {'sid': g[0], 'name': g[1], 'category': g[2], 'scope': g[3]}
                  for g in conn.execute('SELECT sid,sam,category,scope FROM priv_groups WHERE snapshot_id=?', (snapshot_id,))}
        edge_count = conn.execute('SELECT COUNT(*) FROM priv_edges WHERE snapshot_id=?', (snapshot_id,)).fetchone()[0]
        if edge_count > MAX_EDGES:
            raise ValueError('Privilege graph exceeds safe read limit')
        graph = defaultdict(list)
        for source, target, kind in conn.execute('SELECT src_sid,dst_group_sid,evidence_kind FROM priv_edges WHERE snapshot_id=? ORDER BY src_sid,dst_group_sid,evidence_kind', (snapshot_id,)):
            if kind not in EDGE_KINDS:
                raise ValueError('Unexpected edge evidence type')
            if target not in groups:
                raise ValueError('Edge points to unresolved group')
            graph[source].append((target, kind))

        # BFS preserves shortest directory membership chain and terminates on cycles.
        paths = {}
        todo = deque([(user_sid, [], [])])
        while todo:
            at, path, kinds = todo.popleft()
            for group_sid, kind in graph.get(at, []):
                if group_sid in paths:
                    continue
                group_path = path + [group_sid]
                kind_path = kinds + [kind]
                paths[group_sid] = (group_path, kind_path)
                todo.append((group_sid, group_path, kind_path))

        direct, primary, inherited = [], [], []
        for group_sid, (path, kinds) in sorted(paths.items(), key=lambda item: (len(item[1][0]), item[1][0])):
            row = dict(groups[group_sid])
            row['path'] = [groups[g]['name'] for g in path]
            row['path_sids'] = path
            row['evidence_kinds'] = kinds
            if len(path) > 1:
                row['membership_type'] = 'nested'
                inherited.append(row)
            elif kinds[0] == 'user_primarygroup':
                row['membership_type'] = 'primary'
                primary.append(row)
            else:
                row['membership_type'] = 'direct'
                direct.append(row)

        target_sids = {f'{domain_sid}-{rid}' for rid in (512, 518, 519)}
        tier0 = [r for r in direct + primary + inherited if r['sid'] in target_sids]
        try:
            collected = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            age_seconds = (datetime.now(timezone.utc) - collected.astimezone(timezone.utc)).total_seconds()
            days_old = age_seconds / 86400
        except (ValueError, TypeError):
            days_old = None
        return {
            'schema': 'aegis.identity.user_privileges.v1',
            'status': 'ready', 'snapshot_id': snapshot_id, 'collected_at_utc': stamp,
            'stale': days_old is None or days_old > 7 or days_old < -(5/1440),
            'user': {'sid': user_sid, 'sam': user_sam, 'enabled': bool(enabled)},
            'direct_groups': direct,
            'primary_groups': primary,
            'inherited_groups': inherited,
            'effective_group_count': len(paths),
            'tier0_membership_evidence': tier0,
            'limitations': 'Verified directory membership only. Does not prove machine-local admin rights, AD ACL permissions, GPO delegation, or exploitable attack paths.',
        }


@router.get('/status')
def privilege_status(request: Request):
    require_configured_auth(request)
    try:
        return summary(sidecar_path())
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        raise HTTPException(503, detail='Privilege sidecar unavailable or invalid') from exc


@router.get('/user')
def privilege_user(request: Request, sid: str | None = None, sam: str | None = None):
    require_configured_auth(request)
    try:
        return user_evidence(sidecar_path(), sid=sid, sam=sam)
    except LookupError as exc:
        raise HTTPException(404, detail=str(exc)) from exc
    except ValueError as exc:
        if str(exc).startswith('Ambiguous identity'):
            raise HTTPException(409, detail=str(exc)) from exc
        if str(exc).startswith(('Invalid', 'Specify')):
            raise HTTPException(422, detail=str(exc)) from exc
        raise HTTPException(503, detail='Privilege sidecar data error') from exc
    except (OSError, sqlite3.DatabaseError) as exc:
        raise HTTPException(503, detail='Privilege sidecar unavailable') from exc
