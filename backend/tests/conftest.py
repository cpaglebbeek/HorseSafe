from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Pak parent toe aan sys.path zodat `backend.*` imports werken vanaf backend/ als rootdir
ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Elke test krijgt eigen DB + vaults-dir + lichte argon2-params voor snelheid."""
    monkeypatch.setenv("HORSESAFE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("HORSESAFE_VAULTS_DIR", str(tmp_path / "vaults"))
    monkeypatch.setenv(
        "HORSESAFE_JWT_SECRET", "test-secret-32bytes-not-for-prod-use-only-in-pytest"
    )
    monkeypatch.setenv("HORSESAFE_COOKIE_SECURE", "false")  # voor httpx-tests
    monkeypatch.setenv("HORSESAFE_ARGON2_TIME_COST", "2")
    monkeypatch.setenv("HORSESAFE_ARGON2_MEMORY_KIB", "8192")  # 8 MiB voor snelheid
    monkeypatch.setenv("HORSESAFE_ARGON2_PARALLELISM", "1")
    monkeypatch.setenv("HORSESAFE_BCRYPT_ROUNDS", "4")  # lichte bcrypt voor snelle tests

    # Reset cached settings + cryptcontext
    import backend.config as cfg
    import backend.services.auth_service as auth_svc

    cfg.get_settings.cache_clear() if hasattr(cfg.get_settings, "cache_clear") else None
    # Forceer re-init van auth-service met nieuwe params door module-reload-flag
    # (we hebben geen cache, dus volstaat herimport van settings; cryptcontext leest config bij import)
    # Voor degelijke test-isolatie: herlaad het module
    import importlib

    importlib.reload(cfg)
    importlib.reload(auth_svc)


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    import importlib

    import backend.app as app_module

    importlib.reload(app_module)
    transport = ASGITransport(app=app_module.app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Forceer lifespan startup zodat init_db draait
        async with app_module.app.router.lifespan_context(app_module.app):
            yield c


VALID_PW = "SuperStrongPw123!"


# ─────────────── v0.2.0-Koblitz: mailer, WebAuthn-testomgeving ───────────────


@pytest.fixture(autouse=True)
def _reset_mailer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Geen echte mail in tests: SMTP/Gmail-env leeg en geen vaste zender uit een vorige test."""
    for var in (
        "HORSESAFE_SMTP_HOST",
        "HORSESAFE_SMTP_USER",
        "HORSESAFE_SMTP_PASSWORD",
        "HORSESAFE_SMTP_FROM",
        "HORSESAFE_GMAIL_USER",
        "HORSESAFE_GMAIL_APP_PASSWORD",
        "HORSESAFE_TEST_ATTESTATION",
    ):
        monkeypatch.delenv(var, raising=False)
    from backend.services import mail_service

    mail_service.set_sender(None)


@pytest.fixture
def ca():  # type: ignore[no-untyped-def]
    from .softauth import TestCA

    return TestCA()


@pytest.fixture
def hw_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ca):  # type: ignore[no-untyped-def]
    """rpId localhost + test-root + test-allowlist (testvlag blijft UIT tenzij een test hem zet)."""
    from .softauth import ORIGIN, RP_ID, allowlist_json

    roots = tmp_path / "roots.pem"
    roots.write_bytes(ca.pem())
    allow = tmp_path / "aaguids.json"
    allow.write_text(allowlist_json(), encoding="utf-8")
    monkeypatch.setenv("HORSESAFE_WEBAUTHN_RP_ID", RP_ID)
    monkeypatch.setenv("HORSESAFE_WEBAUTHN_ORIGIN", ORIGIN)
    monkeypatch.setenv("HORSESAFE_ATTESTATION_ROOTS_PATH", str(roots))
    monkeypatch.setenv("HORSESAFE_AAGUID_ALLOWLIST_PATH", str(allow))
    return ca


@pytest.fixture
def mailbox():  # type: ignore[no-untyped-def]
    from backend.services import mail_service

    from .hwkeys_helpers import Mailbox

    box = Mailbox()
    mail_service.set_sender(box)
    yield box
    mail_service.set_sender(None)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Verzetbare klok voor vault_key_service.now() (recovery, challenges, step-up)."""
    from backend.services import vault_key_service as svc

    state = {"t": 1_800_000_000}
    monkeypatch.setattr(svc, "now", lambda: state["t"])
    return state
