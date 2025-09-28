# backend/auth.py
from fastapi import APIRouter, HTTPException
from typing import Optional

from core.teamserver import auth_manager as auth

from .dependencies import create_access_token
from .schemas import LoginRequest, TokenResponse, OperatorCreate, OperatorOut, OperatorUpdate

router = APIRouter()


def _get_operator_by_username(username: str) -> Optional[dict]:
    """Best-effort lookup for an operator row by username using whatever
    helpers the bundled auth_manager exposes."""
    # Fast path: dedicated getter
    try:
        if hasattr(auth, "get_operator_by_username"):
            row = auth.get_operator_by_username(username)
            if row:
                return row
    except Exception:
        pass

    # Fallback: list and scan
    try:
        for o in (auth.list_operators() or []):
            if str(o.get("username", "")).lower() == username.lower():
                return o
    except Exception:
        pass

    # Fallback: verify_username -> synthesize minimal row
    try:
        if hasattr(auth, "verify_username"):
            op_id = auth.verify_username(username)
            if op_id:
                # role may be unknown here; default to 'operator'
                return {"id": op_id, "username": username, "role": "operator"}
    except Exception:
        pass

    return None


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest):
    """
    Accepts JSON: {"username": "...", "password": "..."}
    Normalizes the variety of return shapes from core.teamserver.auth_manager.
    """
    ok = False
    row: Optional[dict] = None

    # Primary path: verify_credentials
    try:
        if hasattr(auth, "verify_credentials"):
            res = auth.verify_credentials(body.username, body.password)

            # Common shapes we see in the wild:
            # 1) (bool_ok, row_dict)
            if isinstance(res, tuple) and len(res) >= 2:
                ok, row = bool(res[0]), res[1]

            # 2) dict row on success (truthy), None/False on failure
            elif isinstance(res, dict):
                ok, row = True, res

            # 3) plain bool
            elif isinstance(res, bool):
                ok = res
                if ok:
                    row = _get_operator_by_username(body.username)

            # 4) None → invalid creds
            else:
                ok = False
        else:
            ok = False
    except Exception:
        # If verify_credentials misbehaves, try split checks.
        try:
            if hasattr(auth, "verify_username") and hasattr(auth, "verify_password"):
                op_id = auth.verify_username(body.username)
                if op_id and auth.verify_password(op_id, body.password):
                    ok = True
                    row = _get_operator_by_username(body.username)
        except Exception:
            ok = False
            row = None

    if not ok or not row:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Normalize keys used by token creation
    uid = row.get("id") or row.get("op_id") or row.get("uuid")
    uname = row.get("username") or body.username
    role = row.get("role") or "operator"
    if not uid:
        # last-ditch: obtain id from auth.verify_username
        try:
            uid = auth.verify_username(uname)
        except Exception:
            pass
    if not uid:
        raise HTTPException(status_code=500, detail="Account is missing an ID")

    token = create_access_token({"sub": uid, "username": uname, "role": role})
    return {"token": token}


@router.get("/operators", response_model=list[OperatorOut])
def list_operators():
    ops = auth.list_operators() or []
    return [{"id": o.get("id") or o.get("uuid") or o.get("op_id"),
             "username": o.get("username", ""),
             "role": o.get("role", "operator")} for o in ops]


@router.post("/operators", response_model=OperatorOut)
def add_operator(body: OperatorCreate):
    try:
        oid = auth.add_operator(body.username, body.password, body.role)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"id": oid, "username": body.username, "role": body.role}


@router.delete("/operators/{operator_id}")
def delete_operator(operator_id: str):
    ok = auth.delete_operator(operator_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Operator not found")
    return {"status": "deleted", "id": operator_id}
