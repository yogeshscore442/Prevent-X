"""
PREVENT-X Redis Integration Client
Provides resilient connection pooling, health checks, and fallback mechanisms.
"""

import time
from typing import Optional, Tuple
import redis
from backend.app.core.config import settings
from backend.app.core.logging import logger

_redis_pool: Optional[redis.ConnectionPool] = None


def get_redis_client() -> Optional[redis.Redis]:
    """Retrieves a thread-safe Redis client instance."""
    global _redis_pool
    try:
        if _redis_pool is None:
            _redis_pool = redis.ConnectionPool.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        return redis.Redis(connection_pool=_redis_pool)
    except Exception as e:
        logger.warning(f"Failed to initialize Redis connection pool: {str(e)}")
        return None


def ping_redis() -> Tuple[bool, float, str]:
    """
    Checks Redis connectivity and response latency.
    Returns: (is_up, latency_ms, details)
    """
    client = get_redis_client()
    if client is None:
        return False, 0.0, "Redis client not initialized"

    start_time = time.perf_counter()
    try:
        res = client.ping()
        latency = (time.perf_counter() - start_time) * 1000.0
        if res:
            return True, round(latency, 2), "Redis cluster/standalone operational"
        return False, round(latency, 2), "Redis ping returned false"
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000.0
        return False, round(latency, 2), f"Redis connection failed: {str(e)}"

