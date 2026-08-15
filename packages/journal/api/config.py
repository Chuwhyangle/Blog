"""配置：从环境变量读取（systemd EnvironmentFile 注入）。"""
import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    db_host: str = field(default_factory=lambda: os.getenv("JOURNAL_DB_HOST", "127.0.0.1"))
    db_port: int = field(default_factory=lambda: int(os.getenv("JOURNAL_DB_PORT", "3306")))
    db_name: str = field(default_factory=lambda: os.getenv("JOURNAL_DB_NAME", "journal"))
    db_user: str = field(default_factory=lambda: os.getenv("JOURNAL_DB_USER", "journal_app"))
    db_password: str = field(default_factory=lambda: os.getenv("JOURNAL_DB_PASSWORD", ""))

    host: str = field(default_factory=lambda: os.getenv("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "8000")))

    # 会话 token 签名密钥（systemd EnvironmentFile 提供，openssl rand -hex 32）
    session_secret: str = field(default_factory=lambda: os.getenv("SESSION_SECRET", ""))

    # WebAuthn
    rp_id: str = field(default_factory=lambda: os.getenv("RP_ID", "journal.leyanwc.xyz"))
    rp_name: str = field(default_factory=lambda: os.getenv("RP_NAME", "LeyanWC Journal"))
    origin: str = field(default_factory=lambda: os.getenv("ORIGIN", "https://journal.leyanwc.xyz"))

    def db_url(self) -> str:
        return (
            f"mysql+pymysql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}?charset=utf8mb4"
        )


settings = Settings()

# 安全断言：生产环境必须显式设置
if settings.session_secret == "":
    raise RuntimeError("SESSION_SECRET 未设置（openssl rand -hex 32）")