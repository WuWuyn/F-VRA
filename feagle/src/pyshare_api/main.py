from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from pyshare_api.db import create_schema
from pyshare_api.routes import router as api_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="F-VRA API",
        version="0.1.0",
        description="HTTP API layer for the F-VRA dashboard and integrations.",
        openapi_url="/api/openapi.json",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    @app.on_event("startup")
    def _ensure_schema() -> None:
        create_schema()

    app.include_router(api_router, prefix="/api")
    return app


app = create_app()
