"""
PREVENT-X Structured Logging Configuration
Provides JSON-structured, security-audit-compliant logging.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from backend.app.core.config import settings


class JsonFormatter(logging.Formatter):
    """
    JSON log formatter for enterprise SIEM and observability ingestion.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process": record.process,
            "thread": record.threadName,
        }
        if hasattr(record, "tenant_id"):
            log_record["tenant_id"] = getattr(record, "tenant_id")
        if hasattr(record, "user_id"):
            log_record["user_id"] = getattr(record, "user_id")
        if hasattr(record, "action"):
            log_record["action"] = getattr(record, "action")
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record)


def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger = logging.getLogger("preventx")
    logger.setLevel(log_level)

    # Avoid duplicate handlers
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(log_level)
        if settings.LOG_FORMAT.lower() == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
                )
            )
        logger.addHandler(handler)

    # Configure root logger level
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    return logger


logger = setup_logging()
