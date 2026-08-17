"""首次初始化端点（bootstrap）：
 /api/setup/passwords   —— 保存 KDF 参数 + verifier + 读口令哈希
 /api/setup/signing-key —— 注册首个签名公钥
安全模型：
 - bootstrap 仅在 credentials 表为空时允许（首注册 = 唯一写凭据）
 - 之后任何凭据注册必须走 elevated 会话（⑩ Q1a）
 - 已初始化后重跑会 403
"""
import base64, json, uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from argon2 import PasswordHasher

from db import get_db
from models import Credential, CryptoParam, SigningKey, KeyEscrow
from security.sessions import require_session, create_session, set_session_cookie, parse_ip

router = APIRouter(prefix="/api/setup", tags=["setup"])

ph = PasswordHasher(time_cost=2, memory_cost=32 * 1024, parallelism=1)


def _ensure_bootstrap(db: Session) -> None:
    """仅在没有签名公钥时允许初始化（首公钥 = 初始化完成的标志）。
    注意：不能用 credentials 表判空 —— 初始化 Step0 先注册 passkey，
    之后 step1/step2 继续需要本端点。已有公钥 = 系统已初始化。
    """
    if db.query(SigningKey).count() > 0:
        raise HTTPException(403, "已初始化，请使用恢复流程注册新凭据")


@router.get("/status")
def setup_status(db: Session = Depends(get_db)):
    """初始化进度（向导断点续走用）：半初始化状态刷新后定位到未完成步骤。"""
    return {
        "admin_password_set": db.query(Credential).filter(Credential.cred_id == b"admin-password").count() > 0,
        "crypto_params_set": db.query(CryptoParam).count() >= 2,
        "signing_key_set": db.query(SigningKey).count() > 0,
        "escrow_set": db.query(KeyEscrow).count() > 0,
    }


@router.post("/admin-password")
def setup_admin_password(body: dict, request: Request, db: Session = Depends(get_db)):
    """设置管理员密码（登录身份，替代 passkey 注册）。
    bootstrap：signing_keys 空时允许；成功后直接建立 owner 会话（设置向导后续步骤需要）。
    幂等：若已设置（半初始化重入），不覆盖密码，直接返回 ok + 会话。
    管理员密码 Argon2id 哈希存 credentials 表特殊行（cred_id=b'admin-password'）。
    """
    _ensure_bootstrap(db)
    password = (body.get("password") or "")
    if len(password) < 8:
        raise HTTPException(422, "管理员密码至少 8 位")

    row = db.query(Credential).filter(Credential.cred_id == b"admin-password").first()
    if not row:
        db.add(Credential(
            cred_id=b"admin-password",
            public_key=b"",
            sign_count=0,
            can_write=True,
            label="管理员密码登录",
            password_hash=ph.hash(password),
            created_at=datetime.now(timezone.utc),
        ))
        db.commit()

    token = create_session(
        db, role="owner", credential_id=b"admin-password", can_write=True,
        ip=parse_ip(request.client.host if request.client else None),
        user_agent=request.headers.get("user-agent"),
    )
    resp = JSONResponse({"ok": True, "can_write": True, "role": "owner"})
    set_session_cookie(resp, token)
    return resp


@router.post("/passwords")
def setup_passwords(body: dict, request: Request, db: Session = Depends(get_db)):
    require_session(db, request)          # 必须已登录（刚刚注册的 passkey 会话）
    _ensure_bootstrap(db)

    owner = body.get("owner")
    reader = body.get("reader")
    if not owner or not reader:
        raise HTTPException(422, "缺少 owner/reader 参数")

    # 半初始化重入保护：参数已存在时绝不允许覆盖（盐/参数/verifier 一经写入不可变）
    for role in ("owner", "reader"):
        if db.query(CryptoParam).filter(CryptoParam.role == role).count() > 0:
            raise HTTPException(409, f"{role} 参数已初始化，不能覆盖")

    # owner+reader 必须同一事务原子写入：任一失败全部回滚，
    # 避免半初始化单行状态卡死向导（探测阈值是 ≥2 行）。
    def _save(role: str, data: dict, with_password: bool = False) -> None:
        salt = base64.b64decode(data["salt"])
        params = json.dumps(data["params"])
        verifier = base64.b64decode(data["verifier"])
        verifier_iv = base64.b64decode(data["verifier_iv"])
        db.add(CryptoParam(
            role=role, salt=salt, params=params,
            verifier=verifier, verifier_iv=verifier_iv,
            password_hash=ph.hash(data["password"]) if (with_password and data.get("password")) else None,
            key_epoch=1,
            algo="argon2id",
        ))

    try:
        _save("owner", owner)
        _save("reader", reader, with_password=True)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"ok": True}


@router.post("/signing-key")
def setup_signing_key(body: dict, request: Request, db: Session = Depends(get_db)):
    require_session(db, request)
    _ensure_bootstrap(db)   # 仅首公钥（无公钥时）允许

    key_id = uuid.UUID(body["key_id"]).bytes
    public_key = base64.b64decode(body["public_key"])
    if len(public_key) != 32:
        raise HTTPException(422, "Ed25519 公钥必须 32 字节")

    db.add(SigningKey(
        key_id=key_id,
        public_key=public_key,
        created_at=datetime.now(timezone.utc),
        retired_at=None,
        note="initial",
    ))
    db.commit()
    return {"ok": True}