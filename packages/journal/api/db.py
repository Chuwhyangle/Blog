"""SQLAlchemy 引擎与会话 —— 连接池配置（③ §2 FastAPI 连接池）"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from config import settings

engine = create_engine(
    settings.db_url(),
    pool_size=5,
    max_overflow=5,
    pool_recycle=3600,   # 防 MySQL wait_timeout 静默断连（Python+MySQL 最常见生产问题）
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()