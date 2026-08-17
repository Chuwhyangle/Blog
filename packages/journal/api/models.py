"""ORM 模型 —— 对应 deploy/sql/schema.sql 的 8 张表"""
from datetime import datetime
from sqlalchemy import (
    Column, String, LargeBinary, DateTime, Integer, Enum,
    Boolean, ForeignKey, UniqueConstraint,
)
from db import Base


class Entry(Base):
    """日记条目：服务端只见密文（③ §1）"""
    __tablename__ = "entries"

    id = Column(LargeBinary(16), primary_key=True)          # UUIDv7 原始字节
    visibility = Column(Enum("private", "shared"), nullable=False, default="private")
    created_at = Column(DateTime(3), nullable=False)
    updated_at = Column(DateTime(3), nullable=False)
    ciphertext = Column(LargeBinary, nullable=False)        # MEDIUMBLOB
    iv = Column(LargeBinary(12), nullable=False)
    dek_owner = Column(LargeBinary(48), nullable=False)
    dek_owner_iv = Column(LargeBinary(12), nullable=False)
    dek_reader = Column(LargeBinary(48), nullable=True)
    dek_reader_iv = Column(LargeBinary(12), nullable=True)
    signature = Column(LargeBinary(64), nullable=False)
    signing_key_id = Column(LargeBinary(16), nullable=False)
    owner_epoch = Column(Integer, nullable=False, default=1)
    reader_epoch = Column(Integer, nullable=False, default=0)


class CryptoParam(Base):
    """KDF 参数（按 role 分行，参数写进数据行）"""
    __tablename__ = "crypto_params"

    role = Column(Enum("owner", "reader"), primary_key=True)
    salt = Column(LargeBinary(32), nullable=False)
    algo = Column(String(16), nullable=False, default="argon2id")
    params = Column(String(255), nullable=False)    # JSON {"m":65536,"t":3,"p":1}
    verifier = Column(LargeBinary(64), nullable=False)
    verifier_iv = Column(LargeBinary(12), nullable=False)
    key_epoch = Column(Integer, nullable=False, default=1)
    password_hash = Column(String(255), nullable=True)   # 仅 reader 行非空（服务端在线校验）
    failed_count = Column(Integer, nullable=False, default=0)   # 读口令失败计数（账号级锁）
    frozen_until = Column(DateTime(3), nullable=True)            # 冻结截止时间


class Credential(Base):
    """WebAuthn 凭据（⑤ §6 写权限唯一判据）
    管理员密码登录模式：存一行特殊记录（cred_id=b'admin-password'，password_hash 非空）
    """
    __tablename__ = "credentials"

    cred_id = Column(LargeBinary(255), primary_key=True)
    public_key = Column(LargeBinary(512), nullable=False)
    sign_count = Column(Integer, nullable=False, default=0)
    can_write = Column(Boolean, nullable=False, default=False)
    label = Column(String(64), nullable=True)
    password_hash = Column(String(255), nullable=True)   # 管理员密码登录模式用
    created_at = Column(DateTime(3), nullable=False)
    failed_count = Column(Integer, nullable=False, default=0)   # 密码失败计数（账号级锁）
    frozen_until = Column(DateTime(3), nullable=True)            # 冻结截止时间


class SigningKey(Base):
    """作者签名公钥（多行，支持轮换，旧公钥永久保留）"""
    __tablename__ = "signing_keys"

    key_id = Column(LargeBinary(16), primary_key=True)   # UUIDv7
    public_key = Column(LargeBinary(32), nullable=False)  # Ed25519 原始字节
    created_at = Column(DateTime(3), nullable=False)
    retired_at = Column(DateTime(3), nullable=True)
    note = Column(String(120), nullable=True)


class KeyEscrow(Base):
    """恢复码托管：Enc(KEK_recovery, KEK_owner) + Enc(KEK_recovery, sk)"""
    __tablename__ = "key_escrow"

    purpose = Column(String(32), primary_key=True)   # 'recovery'
    code_hash = Column(LargeBinary(255), nullable=False)   # Argon2id(恢复码)
    wrapped_kek = Column(LargeBinary(64), nullable=False)
    wrapped_kek_iv = Column(LargeBinary(12), nullable=False)
    wrapped_sk = Column(LargeBinary(128), nullable=True)
    wrapped_sk_iv = Column(LargeBinary(12), nullable=True)
    created_at = Column(DateTime(3), nullable=False)
    used_at = Column(DateTime(3), nullable=True)
    failed_count = Column(Integer, nullable=False, default=0)      # 失败计数（⑪ Q6 应用层冻结）
    frozen_until = Column(DateTime(3), nullable=True)              # 全局冻结截止时间


class SessionRow(Base):
    """服务端会话表：主键存 SHA-256(token)（⑪ Q4）"""
    __tablename__ = "sessions"

    id = Column(LargeBinary(32), primary_key=True)   # SHA-256(token)
    role = Column(Enum("owner", "reader", "elevated"), nullable=False)
    credential_id = Column(LargeBinary(255), nullable=True)
    can_write = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(3), nullable=False)
    expires_at = Column(DateTime(3), nullable=False)
    last_seen_at = Column(DateTime(3), nullable=False)
    ip = Column(LargeBinary(16), nullable=True)
    user_agent = Column(String(255), nullable=True)


class WebAuthnChallenge(Base):
    """WebAuthn challenge：删除即校验（防重放）"""
    __tablename__ = "webauthn_challenges"

    challenge = Column(LargeBinary(32), primary_key=True)
    purpose = Column(Enum("register", "authenticate"), nullable=False)
    expires_at = Column(DateTime(3), nullable=False)