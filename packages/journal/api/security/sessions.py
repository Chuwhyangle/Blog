"""会话安全：token 生成、SHA-256 落库、cookie 解析（⑪ Q4）"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from models import SessionRow

# Cookie 名：__Host- 前缀强制 Secure + Path=/ + 禁 Domain（三子域架构隔离）
SESSION_COOKIE = "__Host-sid"

# TTL（⑪ Q4）
TTL = {
    "owner": timedelta(days=30),      # 30 天滑动
    "reader": timedelta(hours=24),    # 24 小时不续期
    "elevated": timedelta(minutes=10),  # 恢复流程一次性
}


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def create_session(db: Session, role: str, credential_id: bytes | None = None,
                   can_write: bool = False, ip: bytes | None = None,
                   user_agent: str | None = None) -> str:
    """生成会话并落库，返回明文 token（只返回一次，只进 cookie）"""
    token = new_session_token()
    now = datetime.now(timezone.utc)
    row = SessionRow(
        id=hash_token(token),
        role=role,
        credential_id=credential_id,
        can_write=can_write,
        created_at=now,
        expires_at=now + TTL[role],
        last_seen_at=now,
        ip=ip,
        user_agent=(user_agent or "")[:255],
    )
    db.add(row)
    db.commit()
    return token


def set_session_cookie(response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, secure=True, samesite="lax",
        max_age=int(TTL["owner"].total_seconds()),  # 最长为 owner TTL；具体以服务端为准
        path="/",
    )


def get_session(db: Session, request: Request) -> SessionRow | None:
    """从 cookie 取有效会话；顺带滑动 last_seen / 续期 owner"""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    row = db.query(SessionRow).filter(SessionRow.id == hash_token(token)).first()
    if not row:
        return None
    now = datetime.now(timezone.utc)
    if row.expires_at < now:
        db.delete(row)
        db.commit()
        return None
    # owner 滑动续期（每次请求刷新 TTL）
    if row.role == "owner" and row.expires_at - now < timedelta(days=29):
        row.expires_at = now + TTL["owner"]
    row.last_seen_at = now
    db.commit()
    return row


def require_session(db: Session, request: Request, roles: set[str] | None = None) -> SessionRow:
    sess = get_session(db, request)
    if not sess:
        raise HTTPException(401, "未登录")
    if roles and sess.role not in roles:
        raise HTTPException(403, "无权限")
    return sess


def destroy_session(db: Session, request: Request, response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.query(SessionRow).filter(SessionRow.id == hash_token(token)).delete()
        db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")


def parse_ip(raw: str | None) -> bytes | None:
    """IPv4/IPv6 原始字节存 VARBINARY(16)"""
    if not raw:
        return None
    try:
        import ipaddress
        return ipaddress.ip_address(raw).packed
    except ValueError:
        return None