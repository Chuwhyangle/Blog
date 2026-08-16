"""WebAuthn 注册 / 断言 / 会话（② py_webauthn + ⑪ Q4 challenge 落库）"""
import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from config import settings
from db import get_db
from models import Credential, WebAuthnChallenge, SessionRow
from security.sessions import (
    create_session, set_session_cookie, require_session, destroy_session, parse_ip,
)
from schemas import (
    WebAuthnRegisterOptionsOut, WebAuthnRegisterVerifyIn,
    WebAuthnLoginOptionsOut, WebAuthnLoginVerifyIn,
)

from webauthn import (
    generate_registration_options, verify_registration_response,
    generate_authentication_options, verify_authentication_response,
)
from webauthn.helpers.options_to_json import options_to_json_dict
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    RegistrationCredential, AuthenticationCredential,
    AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
    AuthenticatorAttachment,
)

router = APIRouter(prefix="/api/webauthn", tags=["webauthn"])


def _b64url_to_bytes(x: str) -> bytes:
    return base64url_to_bytes(x)


def _bytes_to_b64url(x: bytes) -> str:
    return bytes_to_base64url(x)


# ── 工具 ─────────────────────────────────────────────
def _make_challenge() -> bytes:
    return secrets.token_bytes(32)   # BINARY(32)


def _store_challenge(db: Session, challenge: bytes, purpose: str) -> None:
    db.add(WebAuthnChallenge(
        challenge=challenge,
        purpose=purpose,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=120),
    ))
    db.commit()


def _consume_challenge(db: Session, challenge: bytes, purpose: str) -> bool:
    """删除并检查影响行数 —— 天然防重放（⑪ Q4 一条 SQL）"""
    row = db.query(WebAuthnChallenge).filter(
        WebAuthnChallenge.challenge == challenge,
        WebAuthnChallenge.purpose == purpose,
        WebAuthnChallenge.expires_at > datetime.now(timezone.utc),
    ).first()
    if not row:
        return False
    db.delete(row)
    db.commit()
    return True


def _client_data_bytes(credential: dict) -> bytes:
    # WebAuthn 校验需要 clientDataJSON/authenticatorData/signature 原始字节
    client_data = credential.get("clientDataJSON")
    if not client_data:
        raise HTTPException(422, "缺少 clientDataJSON")
    return _b64url_to_bytes(client_data)


# ── 注册 ─────────────────────────────────────────────
@router.post("/register/options", response_model=WebAuthnRegisterOptionsOut)
def register_options(request: Request, db: Session = Depends(get_db)):
    """生成注册 challenge。
    权限：正常注册（can_write=0 设备）需已有 effective owner 会话；
          can_write=1 注册只在 elevated 会话下放行（⑩ Q1a）。
    """
    sess = None
    # 例外：首次初始化（credentials 表为空）→ 匿名 bootstrap 注册首个写凭据
    bootstrap = db.query(Credential).count() == 0
    if not bootstrap:
        sess = require_session(db, request)

    # 前端要求 can_write=1 时，必须是 elevated 会话，
    # 例外：bootstrap（首注册）直接放行。
    want_write = request.query_params.get("can_write") == "1"
    if want_write and (sess is None or sess.role != "elevated") and not bootstrap:
        raise HTTPException(403, "注册写密钥需要恢复流程（elevated 会话）")

    challenge = _make_challenge()
    purpose = "register"
    _store_challenge(db, challenge, purpose)

    # 用户 id：固定为作者的稳定标识（个人日记单用户）—— generate_registration_options 需要 bytes
    user_id = hashlib.sha256(b"leyanwc-journal-owner").digest()[:16]
    options = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_id=user_id,
        user_name="leyanwc",
        user_display_name="LeyanWC",
        challenge=challenge,
        timeout=120_000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,  # 与前端 Setup 一致（本机 passkey）
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    data = options_to_json_dict(options)
    return JSONResponse({
        "challenge": data["challenge"],
        "rp_id": data["rp"]["id"],
        "rp_name": data["rp"]["name"],
        "user_id": data["user"]["id"],
        "user_name": data["user"]["name"],
        "user_display_name": data["user"]["displayName"],
        "publicKey": data,
    })


@router.post("/register/verify")
def register_verify(body: WebAuthnRegisterVerifyIn, request: Request, db: Session = Depends(get_db)):
    """校验注册响应并存凭据。can_write 判定：
    - 默认（device 注册）→ 0
    - elevated 会话 + can_write=True → 1（⑩ Q1a 恢复流程）
    """
    sess = None
    bootstrap = db.query(Credential).count() == 0
    if not bootstrap:
        sess = require_session(db, request)

    cred = body.credential
    raw_id = _b64url_to_bytes(cred["id"])
    challenge = _b64url_to_bytes(cred.get("challenge", ""))

    if not _consume_challenge(db, challenge, "register"):
        raise HTTPException(400, "challenge 无效或已过期")

    try:
        verification = verify_registration_response(
            credential=RegistrationCredential.model_validate({
                "id": cred["id"],
                "rawId": cred["rawId"],
                "response": cred["response"],
                "type": "public-key",
            }),
            expected_challenge=challenge,
            expected_origin=settings.origin,
            expected_rp_id=settings.rp_id,
        )
    except Exception as e:
        raise HTTPException(400, f"WebAuthn 注册校验失败: {e}")

    # 写权限：默认 False；elevated 会话授权 can_write=1 或 bootstrap（首个凭据）才放行
    can_write = False
    if body.can_write and ((sess is not None and sess.role == "elevated") or bootstrap):
        can_write = True

    db.add(Credential(
        cred_id=raw_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        can_write=can_write,
        label=(body.label or "")[:64] or None,
        created_at=datetime.now(timezone.utc),
    ))
    db.commit()

    # bootstrap 或本人注册后直接建立 owner 会话（设置向导需要登录态）
    token = create_session(
        db, role="owner", credential_id=raw_id, can_write=can_write,
        ip=parse_ip(request.client.host if request.client else None),
        user_agent=request.headers.get("user-agent"),
    )
    resp = JSONResponse({"ok": True, "can_write": can_write, "role": "owner"})
    set_session_cookie(resp, token)
    return resp


# ── 断言（登录）───────────────────────────────────────
@router.post("/login/options", response_model=WebAuthnLoginOptionsOut)
def login_options(request: Request, db: Session = Depends(get_db)):
    challenge = _make_challenge()
    _store_challenge(db, challenge, "authenticate")
    options = generate_authentication_options(
        rp_id=settings.rp_id,
        challenge=challenge,
        timeout=120_000,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    data = options_to_json_dict(options)
    return JSONResponse({
        "challenge": data["challenge"],
        "rp_id": data["rpId"],
        "publicKey": data,
    })


@router.post("/login/verify")
def login_verify(body: WebAuthnLoginVerifyIn, request: Request, response, db: Session = Depends(get_db)):
    cred = body.credential
    raw_id = _b64url_to_bytes(cred["id"])
    challenge = _b64url_to_bytes(cred.get("challenge", ""))

    if not _consume_challenge(db, challenge, "authenticate"):
        raise HTTPException(400, "challenge 无效或已过期")

    stored = db.query(Credential).filter(Credential.cred_id == raw_id).first()
    if not stored:
        raise HTTPException(404, "凭据不存在")

    try:
        verification = verify_authentication_response(
            credential=AuthenticationCredential.model_validate({
                "id": cred["id"],
                "rawId": cred["rawId"],
                "response": cred["response"],
                "type": "public-key",
            }),
            expected_challenge=challenge,
            expected_origin=settings.origin,
            expected_rp_id=settings.rp_id,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
        )
    except Exception as e:
        raise HTTPException(400, f"WebAuthn 断言失败: {e}")

    # 防克隆：sign_count 必须单调不减
    if verification.new_sign_count > stored.sign_count:
        stored.sign_count = verification.new_sign_count
        db.commit()

    token = create_session(
        db, role="owner", credential_id=raw_id, can_write=stored.can_write,
        ip=parse_ip(request.client.host if request.client else None),
        user_agent=request.headers.get("user-agent"),
    )
    resp = JSONResponse({"ok": True, "can_write": stored.can_write, "role": "owner"})
    set_session_cookie(resp, token)
    return resp


# ── 登出 ─────────────────────────────────────────────
@router.post("/logout")
def logout(request: Request, response, db: Session = Depends(get_db)):
    destroy_session(db, request, response)
    return {"ok": True}