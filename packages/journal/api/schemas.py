"""Pydantic 请求/响应模型"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# ── 条目 ───────────────────────────────────────────────
class EntryIn(BaseModel):
    """客户端上传：全是密文/签名/元数据，服务端不解密（⑤ §4）"""
    id: bytes                    # UUIDv7 原始字节 (16)
    visibility: str = Field(pattern="^(private|shared)$")
    created_at: datetime
    updated_at: datetime
    ciphertext: bytes
    iv: bytes
    dek_owner: bytes
    dek_owner_iv: bytes
    dek_reader: Optional[bytes] = None
    dek_reader_iv: Optional[bytes] = None
    signature: bytes
    signing_key_id: bytes


class EntryOut(BaseModel):
    id: str
    visibility: str
    created_at: datetime
    updated_at: datetime
    ciphertext: bytes
    iv: bytes
    dek_owner: bytes
    dek_owner_iv: bytes
    dek_reader: Optional[bytes] = None
    dek_reader_iv: Optional[bytes] = None
    signature: bytes
    signing_key_id: str


# ── 会话 ───────────────────────────────────────────────
class SessionOut(BaseModel):
    role: str
    can_write: bool
    credential_label: Optional[str] = None


# ── 访客口令登录 ────────────────────────────────────────
class ReaderLoginIn(BaseModel):
    password: str


# ── WebAuthn ───────────────────────────────────────────
class WebAuthnRegisterOptionsOut(BaseModel):
    challenge: str
    rp_id: str
    rp_name: str
    user_id: str
    user_name: str
    user_display_name: str
    can_write: bool = False   # 注册时前端指定（服务端只对 elevated 会话放行 can_write=1）


class WebAuthnRegisterVerifyIn(BaseModel):
    credential: dict
    label: Optional[str] = None
    can_write: bool = False


class WebAuthnLoginOptionsOut(BaseModel):
    challenge: str
    rp_id: str


class WebAuthnLoginVerifyIn(BaseModel):
    credential: dict


# ── 恢复 ───────────────────────────────────────────────
class RecoveryIn(BaseModel):
    code: str


class RecoveryOut(BaseModel):
    ok: bool
    new_code: Optional[str] = None   # 仅在轮换成功后返回一次


# ── 元数据（前端拿参数）────────────────────────────────
class CryptoParamsOut(BaseModel):
    role: str
    salt: str          # base64
    algo: str
    params: dict
    key_epoch: int


class SigningKeyOut(BaseModel):
    key_id: str
    public_key: str    # base64
    created_at: datetime
    retired_at: Optional[datetime] = None


class EscrowOut(BaseModel):
    wrapped_kek: str
    wrapped_kek_iv: str
    wrapped_sk: Optional[str] = None
    wrapped_sk_iv: Optional[str] = None