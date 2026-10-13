from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Gevendorde, publieke data (Yubico-roots, AAGUID-allowlist). Bewust geen map backend/config/:
# die zou botsen met deze module.
_DATA_DIR = Path(__file__).parent / "data"


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
    app_version: str = "0.3.3-Miller"

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
    docs_enabled: bool = False  # OpenAPI /docs + /openapi.json; uit in productie (info-disclosure)

    # MFA — Fase 3 (v0.0.3-Merkle)
    totp_encryption_key: str = ""  # 32-byte hex; leeg = test/dev-mode (plaintext fallback)
    totp_issuer: str = "HorseSafe"
    gmail_user: str = ""  # Fallback-mailer (SMTP_SSL 465; werkt niet op HC55)
    gmail_app_password: str = ""  # Google App Password (vereist 2FA op Gmail)
    magic_link_ttl_minutes: int = 10
    public_url: str = "http://localhost:8000"  # Voor magic-link redemption URL
    mfa_required: bool = False  # Force MFA voor alle accounts (v0.1.0 dienst)

    # Generieke SMTP-mailer — v0.2.0-Koblitz (besluit 4, docs/HARDWARE_KEYS.md §12.11).
    # Waarden alleen in /opt/horsesafe/.env; nooit in code, docs of logs.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""  # leeg = smtp_user; afwijkend wordt genegeerd (From = SMTP-gebruiker)
    smtp_starttls: bool = True
    smtp_timeout_seconds: int = 15

    # Hardware-sleutels — v0.2.0-Koblitz (docs/HARDWARE_KEYS.md §12.2)
    webauthn_rp_id: str = "icthorsecloud.nl"
    webauthn_rp_name: str = "HorseSafe"
    webauthn_origin: str = "https://icthorsecloud.nl"
    webauthn_challenge_ttl_seconds: int = 300
    webauthn_timeout_ms: int = 120000
    stepup_ttl_seconds: int = 300
    test_attestation: bool = False  # ALLEEN tests; create_app() weigert dit met de productie-rpId
    aaguid_allowlist_path: Path = Field(default=_DATA_DIR / "aaguids.json")
    attestation_roots_path: Path = Field(default=_DATA_DIR / "yubico_fido_roots.pem")
    vault_keys_max: int = 10  # per vault, telt status != 'revoked'
    recovery_delay_hours: int = 24  # wachttijd voordat een noodsleutel bruikbaar is
    recovery_window_hours: int = 24  # zo lang blijft een vrijgegeven noodsleutel bruikbaar

    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()
