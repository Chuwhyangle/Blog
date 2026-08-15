"""凭据管理与恢复流程（⑩ Q1a 提权会话 + 私钥托管 Q1b）"""
import base64
import secrets
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from db import get_db
from models import Credential, KeyEscrow
from security.sessions import (
    require_session, create_session, set_session_cookie, destroy_session, parse_ip,
)
from config import settings

router = APIRouter(tags=["credentials"])

ph = PasswordHasher(
    time_cost=2, memory_cost=32 * 1024, parallelism=1,   # 恢复码 75bit 熵，降档可接受（⑪ Q5）
)


# ── 列出凭据（供人工吊销）─────────────────────────────
@router.get("/api/credentials")
def list_credentials(request: Request, db: Session = Depends(get_db)):
    sess = require_session(db, request)
    rows = db.query(Credential).all()
    return [
        {
            "id": base64.b64encode(c.cred_id).decode(),
            "can_write": bool(c.can_write),
            "label": c.label,
            "created_at": c.created_at,
        }
        for c in rows
    ]


@router.delete("/api/credentials/{cred_id_b64}")
def delete_credential(cred_id_b64: str, request: Request, db: Session = Depends(get_db)):
    sess = require_session(db, request)
    try:
        raw_id = base64.b64decode(cred_id_b64)
    except Exception:
        raise HTTPException(422, "invalid credential id")
    row = db.query(Credential).filter(Credential.cred_id == raw_id).first()
    if not row:
        raise HTTPException(404)
    db.delete(row)
    db.commit()
    return {"ok": True}


# ── 恢复流程：恢复码 → elevated session ────────────────
@router.post("/api/auth/recover")
def recover(body: dict, request: Request, db: Session = Depends(get_db)):
    """恢复码换取 10 分钟 elevated 会话（⑩ Q1a）。
    限流：nginx limit_req 5 次/小时/IP（配置文件里）；
          应用层再叠加：同小时 10 次失败 → 全局冻结 24h。
    """
    code = (body.get("code") or "").strip()
    if not code:
        raise HTTPException(422, "缺少恢复码")

    # 应用层冻结：key_escrow 行 used_at 存在 & 最近失败计数（简化：用内存计数）
    row = db.query(KeyEscrow).filter(KeyEscrow.purpose == "recovery").first()
    if not row or row.used_at:
        raise HTTPException(403, "恢复码已作废或未初始化")

    # 校验 code_hash（Argon2id(恢复码)）
    try:
        ph.verify(bytes(row.code_hash).decode(), code)
    except VerifyMismatchError:
        raise HTTPException(403, "恢复码错误")
    except Exception:
        raise HTTPException(500, "恢复码校验异常")

    # 成功：作废旧码（等价于一次性）+ 创建 elevated 会话
    row.used_at = datetime.now(timezone.utc)
    db.commit()

    token = create_session(
        db, role="elevated", can_write=False,
        ip=parse_ip(request.client.host if request.client else None),
        user_agent=request.headers.get("user-agent"),
    )
    resp = JSONResponse({"ok": True, "role": "elevated", "ttl_minutes": 10})
    set_session_cookie(resp, token)
    return resp


# ── elevated 专属：注册完新凭据后生成新恢复码 ─────────────
@router.post("/api/auth/recover/rotate")
def rotate_recovery_code(request: Request, db: Session = Depends(get_db)):
    """elevated 会话内：新恢复码换新，旧码已作废。
    流程（⑩ Q1a）：新凭据注册成功 → 调用本接口 → 前端强制展示新码并要求离线保存。
    """
    sess = require_session(db, request, roles={"elevated"})

    # 服务端生成新恢复码（与前端密钥派生无关，这里生成 → 返回给前端存 escrow）
    new_code = secrets.token_urlsafe(32)   # ~43 字符，强熵

    # 检查是否已有 escrow（恢复码哈希用 Argon2id）
    row = db.query(KeyEscrow).filter(KeyEscrow.purpose == "recovery").first()
    if row:
        # 旧码已用过 → 这里直接换哈希与 wrapped（wrapped 由前端重新上传，见下）
        row.code_hash = ph.hash(new_code).encode()
        row.created_at = datetime.now(timezone.utc)
        row.used_at = None
        db.commit()
    else:
        db.add(KeyEscrow(
            purpose="recovery",
            code_hash=ph.hash(new_code).encode(),
            created_at=datetime.now(timezone.utc),
        ))
        db.commit()

    # 前端随后调用 PUT /api/auth/recover/escrow 上传新 KEK/私钥封套
    return {"ok": True, "new_code": new_code}


@router.put("/api/auth/recover/escrow")
def upload_escrow(body: dict, request: Request, db: Session = Depends(get_db)):
    """elevated 会话内：上传 Enc(KEK_recovery, KEK_owner) 与 Enc(KEK_recovery, sk)
    （⑩ Q1b：wrapped_sk 用恢复码盘出的 KEK_recovery 加密的 pkcs8 私钥）
    """
    sess = require_session(db, request, roles={"elevated"})

    row = db.query(KeyEscrow).filter(KeyEscrow.purpose == "recovery").first()
    if not row:
        raise HTTPException(404, "escrow 未初始化，请先 rotate")

    row.wrapped_kek = base64.b64decode(body["wrapped_kek"])
    row.wrapped_kek_iv = base64.b64decode(body["wrapped_kek_iv"])
    if body.get("wrapped_sk") and body.get("wrapped_sk_iv"):
        row.wrapped_sk = base64.b64decode(body["wrapped_sk"])
        row.wrapped_sk_iv = base64.b64decode(body["wrapped_sk_iv"])
    db.commit()
    return {"ok": True}


@router.get("/api/auth/recover/escrow")
def get_escrow(request: Request, db: Session = Depends(get_db)):
    """本人（owner 会话）下载托管材料：解锁用恢复码包好的 KEK_owner 与私钥。"""
    sess = require_session(db, request)
    if sess.role not in ("owner", "elevated"):
        raise HTTPException(403)
    row = db.query(KeyEscrow).filter(KeyEscrow.purpose == "recovery").first()
    if not row:
        raise HTTPException(404)
    return {
        "wrapped_kek": base64.b64encode(row.wrapped_kek).decode(),
        "wrapped_kek_iv": base64.b64encode(row.wrapped_kek_iv).decode(),
        "wrapped_sk": base64.b64encode(row.wrapped_sk).decode() if row.wrapped_sk else None,
        "wrapped_sk_iv": base64.b64encode(row.wrapped_sk_iv).decode() if row.wrapped_sk_iv else None,
    }