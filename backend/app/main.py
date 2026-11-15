"""
PREVENT-X Main Application Entrypoint
Enterprise Cybersecurity Virtual Patching Platform - Phase 1 Foundation
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.core.exceptions import PreventXException
from backend.app.core.logging import logger
from backend.app.database.base import Base
from backend.app.database.session import SessionLocal, engine
from backend.app.middleware.csrf_middleware import CSRFMiddleware
from backend.app.middleware.rate_limit_middleware import GlobalRateLimitMiddleware
from backend.app.middleware.security_headers import SecurityHeadersMiddleware
from backend.app.services.bootstrap_service import initialize_system_roles_and_permissions


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown hooks."""
    logger.info("Initializing PREVENT-X Core Application...")

    # Ensure tables exist (for SQLite dev/tests; Alembic handles Postgres migrations)
    Base.metadata.create_all(bind=engine)

    # Idempotently seed system permissions and roles
    db = SessionLocal()
    try:
        initialize_system_roles_and_permissions(db)
    finally:
        db.close()

    logger.info("PREVENT-X Phase 1 Foundation Ready.")
    yield
    logger.info("PREVENT-X Application Shutting Down.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "PREVENT-X: AI-Era Virtual Patching for Security Protection of Indian SMB Digital Businesses. "
        "Phase 1: Enterprise-Grade Foundation & Architecture."
    ),
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
    lifespan=lifespan,
)

# 1. Security Headers Middleware (Outermost)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Rate Limiting Middleware
app.add_middleware(GlobalRateLimitMiddleware)

# 3. CSRF Protection Middleware
app.add_middleware(CSRFMiddleware)

# 3. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Retry-After", "X-CSRF-Token"],
)

# Exception Handlers
@app.exception_handler(PreventXException)
async def handle_preventx_exception(request: Request, exc: PreventXException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"code": exc.code, "message": exc.message},
    )


@app.exception_handler(Exception)
async def handle_generic_exception(request: Request, exc: Exception):
    # Log unexpected errors with traceback while concealing internals from client
    logger.error(f"Unhandled system error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected security or operational error occurred. The incident has been logged.",
        },
    )


# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/", include_in_schema=False)
def root_redirect():
    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "OPERATIONAL",
        "docs_url": f"{settings.API_V1_PREFIX}/docs",
    }
