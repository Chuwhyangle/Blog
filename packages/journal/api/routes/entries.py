"""条目路由：密文存取，服务端不解密（⑤ §3/§6 + ③ §3 路由表）"""
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from db import get_db
from models import Entry, Credential, SigningKey
from security.sessions import require_session, get_session
from schemas import EntryIn, EntryOut

router = APIRouter(prefix="/api/entries", tags=["entries"])


def _uuid_bytes(hex_str: str) -> bytes:
    return uuid.UUID(hex_str).bytes


def _to_out(e: Entry) -> EntryOut:
    return EntryOut(
        id=str(uuid.UUID(bytes=e.id)),
        visibility=e.visibility,
        created_at=e.created_at,
        updated_at=e.updated_at,
        ciphertext=e.ciphertext,
        iv=e.iv,
        dek_owner=e.dek_owner,
        dek_owner_iv=e.dek_owner_iv,
        dek_reader=e.dek_reader,
        dek_reader_iv=e.dek_reader_iv,
        signature=e.signature,
        signing_key_id=str(uuid.UUID(bytes=e.signing_key_id)),
    )


def _can_write(db: Session, cred_id: bytes) -> bool:
    """写权限唯一判据：服务端回查 credentials.can_write（⑤ §6 硬判据）"""
    cred = db.query(Credential).filter(Credential.cred_id == cred_id).first()
    return bool(cred and cred.can_write)


@router.get("")
def list_entries(request: Request, db: Session = Depends(get_db)):
    """GET：按 session 角色过滤（③ §4 纵深防御）"""
    sess = require_session(db, request)
    q = (
        db.query(Entry)
        .filter((1 == 1) if sess.role == "owner" else (Entry.visibility == "shared"))
        .order_by(Entry.created_at.desc())
    )
    return [_to_out(e) for e in q.all()]


@router.post("", status_code=201)
def create_entry(body: EntryIn, request: Request, db: Session = Depends(get_db)):
    """POST：必须 session + can_write（服务端强制写权限）"""
    sess = require_session(db, request, roles={"owner"})
    if not sess.credential_id or not _can_write(db, sess.credential_id):
        raise HTTPException(403, "该凭据无写权限")

    # 服务端校验格式与合理性（③ Q3 裁决）
    if len(body.id) != 16:
        raise HTTPException(422, "id 必须为 UUIDv7 原始字节")
    now = datetime.now(timezone.utc)
    age = abs((body.created_at - now).total_seconds())
    if age > 86_400:    # 24h 内，挡离谱时钟
        raise HTTPException(422, "created_at 超出 24 小时窗口")
    if body.updated_at < body.created_at:
        raise HTTPException(422, "updated_at 不能早于 created_at")
    if body.visibility == "private" and (body.dek_reader or body.dek_reader_iv):
        raise HTTPException(422, "private 条目不得携带 reader 封套")

    # 签名公钥必须已登记（服务端只认它见过的公钥）
    if not db.query(SigningKey).filter(SigningKey.key_id == body.signing_key_id).first():
        raise HTTPException(422, "signing_key_id 未登记")

    entry = Entry(
        id=body.id,
        visibility=body.visibility,
        created_at=body.created_at,
        updated_at=body.updated_at,
        ciphertext=body.ciphertext,
        iv=body.iv,
        dek_owner=body.dek_owner,
        dek_owner_iv=body.dek_owner_iv,
        dek_reader=body.dek_reader,
        dek_reader_iv=body.dek_reader_iv,
        signature=body.signature,
        signing_key_id=body.signing_key_id,
        owner_epoch=body.owner_epoch if hasattr(body, "owner_epoch") else 1,
        reader_epoch=body.reader_epoch if hasattr(body, "reader_epoch") else 0,
    )
    db.add(entry)
    db.commit()
    return _to_out(entry)


@router.put("/{entry_id}")
def update_entry(entry_id: str, body: EntryIn, request: Request, db: Session = Depends(get_db)):
    """PUT：更新（换 DEK+IV、重包封套后上传；id/created_at/signing_key_id 不可变）"""
    sess = require_session(db, request, roles={"owner"})
    if not sess.credential_id or not _can_write(db, sess.credential_id):
        raise HTTPException(403, "该凭据无写权限")

    eid = _uuid_bytes(entry_id)
    e = db.query(Entry).filter(Entry.id == eid).first()
    if not e:
        raise HTTPException(404, "条目不存在")

    # 裁决 ⑩ Q1b：id / created_at / signing_key_id 写入后不可变，忽略客户端请求值
    # + 必须仍指向已登记公钥
    if body.signing_key_id != e.signing_key_id:
        raise HTTPException(422, "signing_key_id 不可变更")
    e.visibility = body.visibility
    e.updated_at = body.updated_at
    e.ciphertext = body.ciphertext
    e.iv = body.iv
    e.dek_owner = body.dek_owner
    e.dek_owner_iv = body.dek_owner_iv
    e.dek_reader = body.dek_reader
    e.dek_reader_iv = body.dek_reader_iv
    e.signature = body.signature
    e.owner_epoch = getattr(body, "owner_epoch", 1)
    e.reader_epoch = getattr(body, "reader_epoch", 0)
    db.commit()
    return _to_out(e)


@router.delete("/{entry_id}")
def delete_entry(entry_id: str, request: Request, db: Session = Depends(get_db)):
    sess = require_session(db, request, roles={"owner"})
    if not sess.credential_id or not _can_write(db, sess.credential_id):
        raise HTTPException(403, "该凭据无写权限")
    eid = _uuid_bytes(entry_id)
    e = db.query(Entry).filter(Entry.id == eid).first()
    if not e:
        raise HTTPException(404, "条目不存在")
    db.delete(e)
    db.commit()
    return {"ok": True}