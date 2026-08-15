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
from sqlalchemy.orm import Session

from argon2 import PasswordHasher

from db import get_db
from models import Credential, CryptoParam, SigningKey
from security.sessions import require_session

router = APIRouter(prefix="/api/setup", tags=["setup"])

ph = PasswordHasher(time_cost=2, memory_cost=32 * 1024, parallelism=1)


def _ensure_bootstrap(db: Session) -> None:
    """仅在所有凭据为空时允许初始化。"""
    cnt = db.query(Credential).count()
    if cnt > 0:
        raise HTTPException(403, "已初始化，请使用恢复流程注册新凭据")


@router.post("/passwords")
def setup_passwords(body: dict, request: Request, db: Session = Depends(get_db)):
    require_session(db, request)          # 必须已登录（刚刚注册的 passkey 会话）
    _ensure_bootstrap(db)

    owner = body.get("owner")
    reader = body.get("reader")
    if not owner or not reader:
        raise HTTPException(422, "缺少 owner/reader 参数")

    def _save(role: str, data: dict, with_password: bool = False) -> None:
        salt = base64.b64decode(data["salt"])
        params = json.dumps(data["params"])
        verifier = base64.b64decode(data["verifier"])
        verifier_iv = base64.b64decode(data["verifier_iv"])
        row = db.query(CryptoParam).filter(CryptoParam.role == role).first()
        if row:
            row.salt = salt; row.params = params
            row.verifier = verifier; row.verifier_iv = verifier_iv
            if with_password and data.get("password"):
                row.password_hash = ph.hash(data["password"])
        else:
            db.add(CryptoParam(
                role=role, salt=salt, params=params,
                verifier=verifier, verifier_iv=verifier_iv,
                password_hash=ph.hash(data["password"]) if (with_password and data.get("password")) else None,
                key_epoch=1,
                algo="argon2id",
            ))
        db.commit()

    _save("owner", owner)
    _save("reader", reader, with_password=True)
    return {"ok": True}


@router.post("/signing-key")
def setup_signing_key(body: dict, request: Request, db: Session = Depends(get_db)):
    require_session(db, request)
    _ensure_bootstrap(db)

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