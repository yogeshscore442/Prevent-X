"""
PREVENT-X Core Application Configuration
Handles 12-factor application settings with Pydantic Settings.
"""

from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Core Application Info
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    APP_NAME: str = "PREVENT-X"
    APP_VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"

    # Security & Hashing
    SECRET_KEY: str = "preventx-default-insecure-secret-key-must-be-changed-in-prod-32ch!"
    BOOTSTRAP_TOKEN: str = "preventx-bootstrap-token-change-in-prod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    SESSION_EXPIRE_HOURS: int = 24
    ALGORITHM: str = "HS256"

    # CORS & Cookies
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://localhost:80",
    ]
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    CSRF_PROTECTION_ENABLED: bool = True

    # Database & Storage
    DATABASE_URL: str = "sqlite:///./preventx.db"

    @field_validator("DATABASE_URL", mode="after")
    @classmethod
    def resolve_sqlite_url(cls, v: str) -> str:
        if v.startswith("sqlite:///./"):
            from pathlib import Path
            root_dir = Path(__file__).resolve().parent.parent.parent.parent
            db_path = root_dir / v.replace("sqlite:///./", "")
            return f"sqlite:///{db_path.as_posix()}"
        return v

    # Redis & Asynchronous Tasks
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10

    # Structured Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, list):
            return v
        import json
        try:
            return json.loads(v)
        except Exception:
            return ["http://localhost:5173"]


settings = Settings()
