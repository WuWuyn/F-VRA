from __future__ import annotations

from fastapi import APIRouter

from pyshare_api.routes import dashboard, jobs

router = APIRouter()
router.include_router(dashboard.router, tags=["dashboard"])
router.include_router(jobs.router, tags=["jobs"])
