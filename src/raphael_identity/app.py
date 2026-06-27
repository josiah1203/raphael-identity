"""Raphael identity service."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from raphael_contracts.errors import ErrorResponse
from raphael_contracts.db import ensure_migrations
from raphael_identity.routes import router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    ensure_migrations()
    yield


app = FastAPI(
    title="raphael-identity",
    version="0.1.0",
    openapi_url="/v1/identity/openapi.json",
    lifespan=lifespan,
)
app.include_router(router, prefix="/v1/identity")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "raphael-identity"}


@app.exception_handler(Exception)
async def unhandled(_request, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content=ErrorResponse(code="internal_error", message=str(exc)).model_dump())
