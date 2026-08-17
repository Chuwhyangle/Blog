"""访客读口令登录 + crypto 元数据（KDF 参数/公钥）"""
import base64
import json
import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from db import get_db
from models import CryptoParam, SigningKey, Credential
from security.sessions import (
    create_session, set_session_cookie, destroy_session, parse_ip, get_session,
    require_session,
)

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
@router.post("/api/admin/login")
def admin_login(body: dict, request: Request, db: Session = Depends(get_db)):
    """管理员密码登录（替代 passkey 登录，密码模式）。
    校验 credentials 表特殊行的 Argon2id 哈希 → owner 会话（can_write=1）。
    限流：nginx limit_req（与 /api/session 同 zone 5r/m）；
          应用层：10 次失败 → 账号级冻结 30min（改 IP 也无法绕过）。
    """
    password = (body.get("password") or "")
    if not password:
        raise HTTPException(422, "缺少口令")

    row = db.query(Credential).filter(Credential.cred_id == b"admin-password").first()
    if not row or not row.password_hash:
        raise HTTPException(500, "管理员密码未初始化")

    now = datetime.now(timezone.utc)
    if row.frozen_until and row.frozen_until > now:
        raise HTTPException(429, "账号已冻结，请稍后再试")

    try:
        ph.verify(str(row.password_hash), password)
    except VerifyMismatchError:
        row.failed_count = (row.failed_count or 0) + 1
        if row.failed_count >= 10:
            row.frozen_until = now + timedelta(minutes=30)
        db.commit()
        raise HTTPException(403, "口令错误")
    except Exception:
        raise HTTPException(500, "口令校验异常")

    # 成功：清零失败计数/冻结
    row.failed_count = 0
    row.frozen_until = None
    db.commit()

    token = create_session(
        db, role="owner", credential_id=b"admin-password", can_write=True,
        ip=parse_ip(request.client.host if request.client else None),
        user_agent=request.headers.get("user-agent"),
    )
    resp = JSONResponse({"ok": True, "role": "owner", "can_write": True})
    set_session_cookie(resp, token)
    return resp


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


# ── 读口令轮换（⑤ §7 + ⑩ key_epoch）──────────────────
# 前端流程：新读口令 → 派生新 KEK_reader' → 逐条重包 → 调本端点
# 落库：password_hash（新口令在线校验）+ salt/params/verifier + key_epoch+1
@router.put("/api/crypto/rotate-reader")
def rotate_reader(body: dict, request: Request, db: Session = Depends(get_db)):
    sess = require_session(db, request)
    if sess.role != "owner" or not sess.can_write:
        raise HTTPException(403, "仅主人可轮换读口令")

    row = db.query(CryptoParam).filter(CryptoParam.role == "reader").first()
    if not row:
        raise HTTPException(404, "未初始化读口令")

    password = (body.get("password") or "")
    if len(password) < 8:
        raise HTTPException(422, "新读口令至少 8 位")

    try:
        salt = base64.b64decode(body["salt"])
        verifier = base64.b64decode(body["verifier"])
        verifier_iv = base64.b64decode(body["verifier_iv"])
    except KeyError as e:
        raise HTTPException(422, f"缺少字段: {e}")
    except Exception:
        raise HTTPException(422, "salt/verifier 必须是 base64")

    if len(salt) != 32:
        raise HTTPException(422, "salt 必须 32 字节")
    if len(verifier_iv) not in (12, 16):
        raise HTTPException(422, "verifier_iv 必须 12 字节（GCM nonce）")

    params = body.get("params") or row.params
    try:
        params_str = json.dumps(params) if isinstance(params, dict) else str(params)
        params_obj = json.loads(params_str)
    except Exception:
        raise HTTPException(422, "params 必须是合法 JSON")
    if not isinstance(params_obj, dict) or "m" not in params_obj:
        raise HTTPException(422, "params 必须是 {\"m\":..,\"t\":..,\"p\":..}")

    row.salt = salt
    row.params = params_str
    row.verifier = verifier
    row.verifier_iv = verifier_iv
    row.password_hash = ph.hash(password)
    row.key_epoch = (row.key_epoch or 0) + 1
    db.commit()
    return {"ok": True, "key_epoch": row.key_epoch}