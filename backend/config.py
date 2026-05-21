from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """HorseSafe backend configuration.

    Loads from environment + .env file. Production: /opt/horsesafe/.env (mode 600).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="HORSESAFE_",
        extra="ignore",
    )

    app_name: str = "HorseSafe"
    app_version: str = "0.0.4-Rivest"

    db_path: Path = Field(default=Path("./db/horsesafe.db"))
    vaults_dir: Path = Field(default=Path("./vaults"))

    jwt_secret: str = Field(default="dev-only-replace-in-production")
    jwt_algorithm: str = "HS256"
    jwt_ttl_minutes: int = 720  # 12 uur sliding window
    cookie_name: str = "horsesafe_session"
    cookie_secure: bool = True
    cookie_samesite: str = "strict"

    failed_login_max: int = 5
    failed_login_window_minutes: int = 15

    vault_max_bytes: int = 50 * 1024 * 1024  # 50 MiB

    # Argon2id voor account-pw (server-side hash van het LOGIN-wachtwoord, NIET vault-pw)
    argon2_time_cost: int = 3
    argon2_memory_kib: int = 65536  # 64 MiB
    argon2_parallelism: int = 4

    cors_origins: str = ""  # Comma-separated; leeg = geen CORS (production-default)
    rate_limit_enabled: bool = True

    # MFA — Fase 3 (v0.0.3-Merkle)
    totp_encryption_key: str = ""  # 32-byte hex; leeg = test/dev-mode (plaintext fallback)
    totp_issuer: str = "HorseSafe"
    gmail_user: str = ""  # Voor magic-link e-mail
    gmail_app_password: str = ""  # Google App Password (vereist 2FA op Gmail)
    magic_link_ttl_minutes: int = 10
    public_url: str = "http://localhost:8000"  # Voor magic-link redemption URL
    mfa_required: bool = False  # Force MFA voor alle accounts (v0.1.0 dienst)

    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()
