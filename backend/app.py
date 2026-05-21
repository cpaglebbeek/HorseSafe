from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .db.init import init_db
from .middlewares.csp_headers import SecurityHeadersMiddleware
from .middlewares.ratelimit import RateLimitMiddleware
from .routes import auth, health, vault

logger = logging.getLogger("horsesafe")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s | %(message)s"
    )
    logger.info("HorseSafe %s starting", settings.app_version)
    await init_db()
    settings.vaults_dir.mkdir(parents=True, exist_ok=True)
    logger.info("DB ready at %s; vaults at %s", settings.db_path, settings.vaults_dir)
    yield
    logger.info("HorseSafe stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Zero-knowledge wachtwoord-vault SaaS (KeePass-KDBX4-compat)",
        lifespan=lifespan,
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
    app.include_router(health.router)
    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(vault.router, prefix="/vault", tags=["vault"])
    return app


app = create_app()
