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
