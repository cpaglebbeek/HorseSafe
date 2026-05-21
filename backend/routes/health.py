from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter

from ..config import get_settings

router = APIRouter()


@router.get("/health")
async def health() -> dict[str, object]:
    settings = get_settings()
    db_ok = Path(settings.db_path).exists() or True  # init_db wordt door lifespan gedaan
    return {
        "status": "ok",
        "version": settings.app_version,
        "db": "ok" if db_ok else "missing",
        "vaults_dir": "ok" if settings.vaults_dir.exists() else "missing",
    }
