"""Read-only Phase 3A endpoints sharing Phase 2F privilege access guard."""
from pathlib import Path
import sqlite3

from fastapi import APIRouter, HTTPException, Request
from app import identity_privilege_api as privilege
from app.identity_risk_context import read_recent_ad_events, evaluate

router = APIRouter(prefix='/api/identity/risk', tags=['Identity Contextual Review'])


@router.get('/user')
def contextual_user(request: Request, sid: str | None = None, sam: str | None = None):
    # Reuse the exact existing Phase2F restricted same-host access policy.
    privilege.require_configured_auth(request)
    try:
        user = privilege.user_evidence(privilege.sidecar_path(), sid=sid, sam=sam)
    except LookupError as exc:
        raise HTTPException(404, detail='User absent from latest privilege snapshot') from exc
    except ValueError as exc:
        if str(exc).startswith('Ambiguous'):
            raise HTTPException(409, detail='Ambiguous identity, use SID') from exc
        if str(exc).startswith(('Invalid', 'Specify')):
            raise HTTPException(422, detail='Invalid identity selector') from exc
        raise HTTPException(503, detail='Privilege evidence unavailable') from exc
    except (OSError, sqlite3.DatabaseError) as exc:
        raise HTTPException(503, detail='Privilege evidence unavailable') from exc
    try:
        # Import already-initialized storage only after access is authorized.
        from app import storage
        events = read_recent_ad_events(storage.DB)
        return evaluate(user, events)
    except (ValueError, OSError, sqlite3.DatabaseError) as exc:
        raise HTTPException(503, detail='Read-only AD event analysis unavailable') from exc
