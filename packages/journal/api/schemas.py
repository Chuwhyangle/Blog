"""Pydantic 请求/响应模型"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# ── 条目 ───────────────────────────────────────────────
from typing import Optional
import base64
from pydantic import BaseModel, Field, field_validator, field_serializer


def _b64(v: str) -> bytes:
    return base64.b64decode(v)


class EntryIn(BaseModel):
    """客户端上传：全是密文/签名/元数据，服务端不解密（⑤ §4）
    注意：JSON 传输用字符串（id 为 hex，其余 base64）；
    模型层统一解码成 bytes —— pydantic 原生 bytes 字段会把 str 按 UTF-8 编码（双重编码 bug）。
    """
    id: bytes                    # UUIDv7 原始字节 (16)，传输为 hex 字符串
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
    owner_epoch: int = 1
    reader_epoch: int = 0

    @field_validator("id", "signing_key_id", mode="before")
    @classmethod
    def _hex_id(cls, v):
        if isinstance(v, str):
            return bytes.fromhex(v)
        return v

    @field_validator("ciphertext", "iv", "dek_owner", "dek_owner_iv",
                     "dek_reader", "dek_reader_iv", "signature", mode="before")
    @classmethod
    def _b64_bytes(cls, v):
        if isinstance(v, str):
            return _b64(v)
        return v


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
    owner_epoch: int = 1
    reader_epoch: int = 0

    @field_serializer("ciphertext", "iv", "dek_owner", "dek_owner_iv",
                       "dek_reader", "dek_reader_iv", "signature")
    @classmethod
    def _b64_out(cls, v):
        # bytes 字段默认按 UTF-8 序列化，非 UTF-8 字节直接抛
        # PydanticSerializationError → 明确转 base64
        if v is None:
            return None
        return base64.b64encode(v).decode()


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