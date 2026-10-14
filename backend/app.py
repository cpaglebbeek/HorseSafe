from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from .config import get_settings
from .db.init import init_db
from .db.migrate import check_vault_keys_schema, run_migrations
from .middlewares.csp_headers import SecurityHeadersMiddleware
from .middlewares.ratelimit import RateLimitMiddleware
from .routes import admin, auth, device_api, devices, health, shares, vault, vault_keys, webauthn
from .services import mail_service

logger = logging.getLogger("horsesafe")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s | %(message)s"
    )
    logger.info("HorseSafe %s starting", settings.app_version)
    await init_db()
    applied = await run_migrations()
    if applied:
        logger.info("Applied migrations: %s", applied)
    await check_vault_keys_schema()
    mail_service.warn_config()
    settings.vaults_dir.mkdir(parents=True, exist_ok=True)
    logger.info("DB ready at %s; vaults at %s", settings.db_path, settings.vaults_dir)
    yield
    logger.info("HorseSafe stopped")


PRODUCTION_RP_ID = "icthorsecloud.nl"


def create_app() -> FastAPI:
    settings = get_settings()
    # R12 (docs/HARDWARE_KEYS.md §12.4): de attestation-uitzondering is alleen voor tests.
    if settings.test_attestation and settings.webauthn_rp_id == PRODUCTION_RP_ID:
        logger.critical(
            "HORSESAFE_TEST_ATTESTATION staat aan met rpId %s — start geweigerd.", PRODUCTION_RP_ID
        )
        raise RuntimeError(
            "HORSESAFE_TEST_ATTESTATION=1 is niet toegestaan met rpId icthorsecloud.nl"
        )
    # §13.5: idem voor de testvlag van de Android key attestation (telefoon koppelen).
    if settings.test_device_attestation and settings.webauthn_rp_id == PRODUCTION_RP_ID:
        logger.critical(
            "HORSESAFE_TEST_DEVICE_ATTESTATION staat aan met rpId %s — start geweigerd.",
            PRODUCTION_RP_ID,
        )
        raise RuntimeError(
            "HORSESAFE_TEST_DEVICE_ATTESTATION=1 is niet toegestaan met rpId icthorsecloud.nl"
        )
    # OpenAPI-schema + interactieve docs alleen in dev/test. In productie uit:
    # ze onthullen de volledige API-oppervlakte van een zero-knowledge dienst.
    docs_kwargs = (
        {} if settings.docs_enabled else {"docs_url": None, "redoc_url": None, "openapi_url": None}
    )
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Zero-knowledge wachtwoord-vault SaaS (KeePass-KDBX4-compat)",
        lifespan=lifespan,
        **docs_kwargs,
    )
    # Middleware-order: Starlette wrapt in reverse-add-order. Laatst-toegevoegd =
    # outermost. CORS MOET outermost zijn zodat ook 429/423-responses van
    # RateLimitMiddleware de Access-Control-Allow-Origin header krijgen.
    app.add_middleware(SecurityHeadersMiddleware)
    if settings.rate_limit_enabled:
        app.add_middleware(RateLimitMiddleware)
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
            expose_headers=["ETag"],
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> Response:
        """Zelfde 422 als FastAPI, maar ASCII-veilig geserialiseerd. FastAPI echoot de foute invoer;
        een los surrogaat (bv. ``\\ud800`` in een claimveld) is geen UTF-8 en gaf zo alsnog een 500.
        """
        body = json.dumps({"detail": jsonable_encoder(exc.errors())}, ensure_ascii=True)
        return Response(body, status_code=422, media_type="application/json")

    app.include_router(health.router)
    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(vault.router, prefix="/vault", tags=["vault"])
    app.include_router(vault_keys.router, prefix="/vault", tags=["vault-keys"])
    app.include_router(webauthn.router, prefix="/webauthn", tags=["webauthn"])
    app.include_router(devices.router, prefix="/devices", tags=["devices"])
    app.include_router(device_api.router, prefix="/device/v1", tags=["device-api"])
    app.include_router(admin.router, prefix="/admin", tags=["admin"])
    app.include_router(shares.router, tags=["shares"])
    return app


app = create_app()
