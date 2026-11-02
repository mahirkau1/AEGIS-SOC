"""Phase3B read-only endpoint using existing Phase2F access guard."""
from __future__ import annotations
import sqlite3
from fastapi import APIRouter, HTTPException, Request
from app import identity_privilege_api as privilege
from app.identity_risk_context import read_recent_ad_events
from app.identity_behavior_timeline import analyze

router = APIRouter(prefix='/api/identity/behavior',tags=['Identity Behavior (shadow)'])

@router.get('/user')
def behavior_user(request: Request, sid: str | None = None, sam: str | None = None):
    privilege.require_configured_auth(request)
    try:
        verified = privilege.user_evidence(privilege.sidecar_path(),sid=sid,sam=sam)
    except LookupError as exc:
        raise HTTPException(404,detail='User absent from privilege snapshot') from exc
    except ValueError as exc:
        if str(exc).startswith('Ambiguous'):
            raise HTTPException(409,detail='Ambiguous user; use SID') from exc
        if str(exc).startswith(('Invalid','Specify')):
            raise HTTPException(422,detail='Invalid identity selector') from exc
        raise HTTPException(503,detail='Privilege evidence unavailable') from exc
    except (OSError, sqlite3.DatabaseError) as exc:
        raise HTTPException(503,detail='Privilege evidence unavailable') from exc
    try:
        from app import storage
        records = read_recent_ad_events(storage.DB)
        return analyze(verified, records)
    except (ValueError, OSError, sqlite3.DatabaseError) as exc:
        raise HTTPException(503,detail='Read-only AD history unavailable') from exc
