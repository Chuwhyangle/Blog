"""核心鉴权/过滤逻辑单元测试（不依赖真实 MySQL —— SQLite 内存库）"""
import os, sys, uuid
from datetime import datetime, timezone, timedelta

# 确保能 import 项目模块
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["SESSION_SECRET"] = "test-secret-0123456789abcdef0123456789abcdef"
os.environ["RP_ID"] = "journal.leyanwc.xyz"

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from db import Base, get_db
from models import Credential, SessionRow, Entry, SigningKey, CryptoParam
from security.sessions import create_session, hash_token, TTL, SESSION_COOKIE

try:
    import sqlalchemy  # noqa
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,   # 所有连接共享同一个内存库
    )
except Exception:
    raise
TestingSession = sessionmaker(bind=engine, autoflush=False)

@pytest.fixture
def db():
    Base.metadata.create_all(engine)
    s = TestingSession()
    yield s
    s.close()
    Base.metadata.drop_all(engine)

@pytest.fixture
def client(db):
    from main import app
    def override():
        yield db
    app.dependency_overrides[get_db] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ── 工具：造数据 ──────────────────────────────────────
def make_cred(db, can_write=False, cred_id=b"\x01" * 16):
    c = Credential(
        cred_id=cred_id, public_key=b"\x02" * 32, sign_count=0,
        can_write=can_write, label="t", created_at=datetime.now(timezone.utc),
    )
    db.add(c)
    db.commit()
    return c

def make_owner_session(db, can_write=True, role="owner"):
    c = make_cred(db, can_write)
    token = create_session(db, role, credential_id=c.cred_id, can_write=can_write)
    return token

def make_signing_key(db):
    k = SigningKey(
        key_id=b"\x03" * 16, public_key=b"\x04" * 32,
        created_at=datetime.now(timezone.utc), note="t",
    )
    db.add(k)
    db.commit()
    return k

def make_entry(db, signed_key_id, visibility="private"):
    e = Entry(
        id=uuid.uuid4().bytes, visibility=visibility,
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
        ciphertext=b"ct", iv=b"\x00" * 12,
        dek_owner=b"\x05" * 48, dek_owner_iv=b"\x06" * 12,
        dek_reader=(b"\x07" * 48 if visibility == "shared" else None),
        dek_reader_iv=(b"\x08" * 12 if visibility == "shared" else None),
        signature=b"\x09" * 64, signing_key_id=signed_key_id,
        owner_epoch=1, reader_epoch=(1 if visibility == "shared" else 0),
    )
    db.add(e)
    db.commit()
    return e


# ── 测试 ──────────────────────────────────────────────
class TestSession:
    def test_session_hash(self, db):
        token = "abc123"
        sess = SessionRow(id=hash_token(token), role="reader", created_at=datetime.now(timezone.utc),
                          expires_at=datetime.now(timezone.utc) + TTL["reader"],
                          last_seen_at=datetime.now(timezone.utc))
        db.add(sess)
        db.commit()
        assert db.query(SessionRow).filter(SessionRow.id == hash_token("abc123")).first() is not None
        # 不同 token 查不到
        assert db.query(SessionRow).filter(SessionRow.id == hash_token("xyz")).first() is None

    def test_reader_ttl(self, db):
        """reader 24h 固定不续期"""
        token = create_session(db, "reader", can_write=False)
        row = db.query(SessionRow).filter(SessionRow.id == hash_token(token)).first()
        assert row.role == "reader"
        assert (row.expires_at - row.created_at).total_seconds() == pytest.approx(24 * 3600, abs=2)

    def test_elevated_ttl(self, db):
        token = create_session(db, "elevated")
        row = db.query(SessionRow).filter(SessionRow.id == hash_token(token)).first()
        assert (row.expires_at - row.created_at).total_seconds() == pytest.approx(600, abs=2)


class TestEntriesAuth:
    def test_entries_requires_session(self, client, db):
        r = client.get("/api/entries")
        assert r.status_code == 401

    def test_read_write_separation(self, client, db):
        k = make_signing_key(db)
        e_priv = make_entry(db, k.key_id, "private")
        e_shared = make_entry(db, k.key_id, "shared")
        db.add(CryptoParam(role="reader", salt=b"\x00" * 32, params='{"m":32768,"t":2,"p":1}',
                           verifier=b"\x00" * 64, verifier_iv=b"\x00" * 12))
        db.commit()

        # 作者：看到全部
        token = make_owner_session(db)
        r = client.get("/api/entries", cookies={SESSION_COOKIE: token})
        assert r.status_code == 200
        ids = [e["id"] for e in r.json()]
        assert len(ids) == 2

    def test_reader_sees_only_shared(self, client, db):
        k = make_signing_key(db)
        make_entry(db, k.key_id, "private")
        make_entry(db, k.key_id, "shared")
        token = create_session(db, "reader", can_write=False)
        r = client.get("/api/entries", cookies={SESSION_COOKIE: token})
        assert r.status_code == 200
        vis = [e["visibility"] for e in r.json()]
        assert vis == ["shared"] and len(vis) == 1

    def test_write_requires_can_write(self, client, db):
        k = make_signing_key(db)
        # 读者会话（can_write=False）
        token = create_session(db, "reader", can_write=False)
        payload = {
            "id": "018f8f6a2b3c4d5e6f708192a3b4c5d6e7",
            "visibility": "private",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "ciphertext": "AA==", "iv": "AAAAAAAAAAAAAAAA",
            "dek_owner": "A" * 64, "dek_owner_iv": "AAAAAAAAAAAAAAAA",
            "signature": "A" * 88, "signing_key_id": "03030303030303030303030303030303",
            "owner_epoch": 1, "reader_epoch": 0,
        }
        r = client.post("/api/entries", json=payload, cookies={SESSION_COOKIE: token})
        assert r.status_code == 403

    def test_create_with_unregistered_signing_key(self, client, db):
        token = make_owner_session(db)
        payload = {
            "id": "018f8f6a2b3c4d5e6f708192a3b4c5d6e7",
            "visibility": "private",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "ciphertext": "AA==", "iv": "AAAAAAAAAAAAAAAA",
            "dek_owner": "A" * 64, "dek_owner_iv": "AAAAAAAAAAAAAAAA",
            "signature": "A" * 88, "signing_key_id": "ffffffffffffffffffffffffffffffff",
            "owner_epoch": 1, "reader_epoch": 0,
        }
        r = client.post("/api/entries", json=payload, cookies={SESSION_COOKIE: token})
        assert r.status_code == 422

    def test_update_cannot_change_signing_key(self, client, db):
        k = make_signing_key(db)
        e = make_entry(db, k.key_id, "private")
        token = make_owner_session(db)
        payload = {
            "id": str(uuid.UUID(bytes=e.id)),
            "visibility": "private",
            "created_at": e.created_at.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "ciphertext": "AA==", "iv": "AAAAAAAAAAAAAAAA",
            "dek_owner": "A" * 64, "dek_owner_iv": "AAAAAAAAAAAAAAAA",
            "signature": "A" * 88,
            "signing_key_id": "ffffffffffffffffffffffffffffffff",  # 试图换公钥
            "owner_epoch": 1, "reader_epoch": 0,
        }
        r = client.put(f"/api/entries/{uuid.UUID(bytes=e.id)}", json=payload, cookies={SESSION_COOKIE: token})
        assert r.status_code == 422


class TestCryptoParams:
    def test_crypto_params_public(self, client, db):
        db.add(CryptoParam(role="owner", salt=b"\x00" * 32, params='{"m":65536,"t":3,"p":1}',
                           verifier=b"\x00" * 64, verifier_iv=b"\x00" * 12))
        db.commit()
        r = client.get("/api/crypto/params")
        assert r.status_code == 200
        assert "owner" in r.json()