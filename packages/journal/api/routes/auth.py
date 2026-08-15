"""访客读口令登录 + crypto 元数据（KDF 参数/公钥）"""
import base64
import json
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from db import get_db
from models import CryptoParam, SigningKey, Credential
from security.sessions import create_session, set_session_cookie, destroy_session, parse_ip, get_session

router = APIRouter(tags=["auth"])

# 读口令校验用（服务端）：与前端派生 KEK 的 Argon2id 完全独立（独立 salt/参数）。
ph = PasswordHasher(
    time_cost=2, memory_cost=32 * 1024, parallelism=1,
)


# ── 当前会话探针 ────────────────────────────────────
@router.get("/api/me")
def me(request: Request, db: Session = Depends(get_db)):
    sess = get_session(db, request)
    if not sess:
        return {"authenticated": False}
    label = None
    if sess.credential_id:
        cred = db.query(Credential).filter(Credential.cred_id == sess.credential_id).first()
        label = cred.label if cred else None
    return {
        "authenticated": True,
        "role": sess.role,
        "can_write": bool(sess.can_write),
        "credential_label": label,
    }


# ── 访客读口令登录 → reader session（24h，不续期）─────────
@router.post("/api/session")
def reader_login(body: dict, request: Request, db: Session = Depends(get_db)):
    """读口令校验：crypto_params.role='reader' 的 password_hash。
    限流：nginx limit_req（/api/session 5r/m）。
    """
    password = (body.get("password") or "").strip()
    if not password:
        raise HTTPException(422, "缺少口令")

    row = db.query(CryptoParam).filter(CryptoParam.role == "reader").first()
    if not row or not row.password_hash:
        raise HTTPException(500, "读口令未初始化")

    try:
        ph.verify(str(row.password_hash), password)
    except VerifyMismatchError:
        raise HTTPException(403, "口令错误")
    except Exception:
        raise HTTPException(500, "口令校验异常")

    token = create_session(
        db, role="reader", can_write=False,
        ip=parse_ip(request.client.host if request.client else None),
        user_agent=request.headers.get("user-agent"),
    )
    resp = JSONResponse({"ok": True, "role": "reader", "can_write": False})
    set_session_cookie(resp, token)
    return resp


# ── 登出 ─────────────────────────────────────────────
@router.post("/api/logout")
def logout(request: Request, response, db: Session = Depends(get_db)):
    destroy_session(db, request, response)
    return {"ok": True}


# ── crypto 参数与签名公钥（前端初始化要用）─────────────────
@router.get("/api/crypto/params")
def crypto_params(request: Request, db: Session = Depends(get_db)):
    rows = db.query(CryptoParam).all()
    return {
        r.role: {
            "salt": base64.b64encode(r.salt).decode(),
            "algo": r.algo,
            "params": json.loads(r.params),
            "verifier": base64.b64encode(r.verifier).decode(),
            "verifier_iv": base64.b64encode(r.verifier_iv).decode(),
            "key_epoch": r.key_epoch,
        }
        for r in rows
    }


@router.get("/api/signing-keys")
def signing_keys(request: Request, db: Session = Depends(get_db)):
    rows = db.query(SigningKey).all()
    return [
        {
            "key_id": str(uuid.UUID(bytes=k.key_id)),
            "public_key": base64.b64encode(k.public_key).decode(),
            "created_at": k.created_at,
            "retired_at": k.retired_at,
        }
        for k in rows
    ]