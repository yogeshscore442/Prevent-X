"""
PREVENT-X Advanced Distributed Rate Limiter
Implements Redis-backed Sliding-Window and Token-Bucket algorithms with burst protection,
per-IP, per-endpoint, and per-tenant multi-dimensional enforcement, and in-memory fallbacks.
"""

import fnmatch
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import redis
from redis import Redis

from backend.app.core.config import settings
from backend.app.models.network_defense import (
    RateLimitPolicy,
    RateLimitScope,
    RateLimitingAlgorithm,
)

logger = logging.getLogger("preventx.network_defense.rate_limiting")


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after: int
    limit: int
    scope: RateLimitScope
    algorithm: RateLimitingAlgorithm
    policy_name: str


class AdvancedRateLimiter:
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis_client: Optional[Redis] = None
        self._mem_sliding: Dict[str, List[float]] = defaultdict(list)
        self._mem_tokens: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_update_ts)
        self._lock = threading.Lock()
        self._init_redis()

    def _init_redis(self):
        try:
            client = Redis.from_url(self.redis_url, decode_responses=True, socket_timeout=1.5)
            client.ping()
            self._redis_client = client
            logger.info("Connected to Redis distributed rate limiter backend at %s", self.redis_url)
        except Exception as ex:
            logger.warning("Redis rate limiter unavailable (%s). Falling back to in-memory store.", ex)
            self._redis_client = None

    @property
    def redis_conn(self) -> Optional[Redis]:
        if self._redis_client is None:
            self._init_redis()
        return self._redis_client

    def _build_key(
        self,
        organization_id: str,
        policy_id: str,
        scope: RateLimitScope,
        client_ip: str,
        endpoint: str,
    ) -> str:
        if scope == RateLimitScope.IP:
            return f"px:rl:ip:{organization_id}:{client_ip}:{policy_id}"
        elif scope == RateLimitScope.ENDPOINT:
            cleaned_ep = endpoint.strip("/").replace("/", "_")
            return f"px:rl:ep:{organization_id}:{cleaned_ep}:{policy_id}"
        else:  # TENANT
            return f"px:rl:tenant:{organization_id}:{policy_id}"

    # 1. Sliding Window Algorithm
    def _evaluate_sliding_window_redis(
        self,
        r: Redis,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        now = time.time()
        clear_before = now - window_seconds
        pipe = r.pipeline()
        pipe.zremrangebyscore(key, 0, clear_before)
        pipe.zcard(key)
        pipe.zrange(key, 0, 0, withscores=True)
        results = pipe.execute()

        current_count = results[1]
        oldest_records = results[2]

        if current_count >= max_requests:
            oldest_ts = oldest_records[0][1] if oldest_records else now
            retry_after = max(1, int(oldest_ts + window_seconds - now))
            return False, 0, retry_after

        # Record this request
        pipe = r.pipeline()
        pipe.zadd(key, {f"{now}:{uuid.uuid4().hex}": now})
        pipe.expire(key, window_seconds + 5)
        pipe.execute()

        remaining = max(0, max_requests - current_count - 1)
        return True, remaining, 0

    def _evaluate_sliding_window_mem(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int, int]:
        with self._lock:
            now = time.time()
            cutoff = now - window_seconds
            timestamps = [t for t in self._mem_sliding[key] if t > cutoff]
            self._mem_sliding[key] = timestamps

            if len(timestamps) >= max_requests:
                oldest = timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, 0, retry_after

            timestamps.append(now)
            remaining = max(0, max_requests - len(timestamps))
            return True, remaining, 0

    # 2. Token Bucket Algorithm
    def _evaluate_token_bucket_redis(
        self,
        r: Redis,
        key: str,
        burst_capacity: int,
        refill_rate: float,
    ) -> Tuple[bool, int, int]:
        now = time.time()
        # Redis Lua script for atomic token bucket evaluation
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local capacity = tonumber(ARGV[2])
        local refill_rate = tonumber(ARGV[3])
        local requested = 1

        local data = redis.call('HMGET', key, 'tokens', 'last_updated')
        local tokens = tonumber(data[1])
        local last_updated = tonumber(data[2])

        if tokens == nil then
            tokens = capacity
            last_updated = now
        else
            local delta = math.max(0, now - last_updated)
            tokens = math.min(capacity, tokens + delta * refill_rate)
            last_updated = now
        end

        local allowed = 0
        local retry_after = 0

        if tokens >= requested then
            allowed = 1
            tokens = tokens - requested
        else
            allowed = 0
            retry_after = math.ceil((requested - tokens) / refill_rate)
        end

        redis.call('HMSET', key, 'tokens', tokens, 'last_updated', last_updated)
        redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) + 60)

        return {allowed, math.floor(tokens), retry_after}
        """
        try:
            res = r.eval(lua_script, 1, key, now, burst_capacity, refill_rate)
            allowed = bool(res[0])
            remaining = int(res[1])
            retry_after = int(res[2])
            return allowed, remaining, retry_after
        except Exception:
            # Fall back to in-memory if Lua fails
            return self._evaluate_token_bucket_mem(key, burst_capacity, refill_rate)

    def _evaluate_token_bucket_mem(
        self,
        key: str,
        burst_capacity: int,
        refill_rate: float,
    ) -> Tuple[bool, int, int]:
        with self._lock:
            now = time.time()
            if key not in self._mem_tokens:
                tokens = float(burst_capacity)
                last_updated = now
            else:
                tokens, last_updated = self._mem_tokens[key]
                delta = max(0.0, now - last_updated)
                tokens = min(float(burst_capacity), tokens + delta * refill_rate)
                last_updated = now

            if tokens >= 1.0:
                tokens -= 1.0
                self._mem_tokens[key] = (tokens, last_updated)
                return True, int(tokens), 0
            else:
                retry_after = max(1, int((1.0 - tokens) / refill_rate))
                self._mem_tokens[key] = (tokens, last_updated)
                return False, 0, retry_after

    def evaluate(
        self,
        policy: RateLimitPolicy,
        client_ip: str,
        endpoint: str,
    ) -> RateLimitResult:
        """
        Evaluates a request against a specific policy using either Sliding-Window or Token-Bucket.
        """
        key = self._build_key(
            organization_id=str(policy.organization_id),
            policy_id=policy.id,
            scope=policy.scope,
            client_ip=client_ip,
            endpoint=endpoint,
        )

        r = self.redis_conn
        if policy.algorithm == RateLimitingAlgorithm.SLIDING_WINDOW:
            limit = policy.max_requests
            if r is not None:
                try:
                    allowed, remaining, retry_after = self._evaluate_sliding_window_redis(
                        r, key, policy.max_requests, policy.window_seconds
                    )
                except Exception as ex:
                    logger.warning("Redis error during sliding window: %s. Using memory.", ex)
                    allowed, remaining, retry_after = self._evaluate_sliding_window_mem(
                        key, policy.max_requests, policy.window_seconds
                    )
            else:
                allowed, remaining, retry_after = self._evaluate_sliding_window_mem(
                    key, policy.max_requests, policy.window_seconds
                )
        else:  # TOKEN_BUCKET
            limit = policy.burst_capacity
            if r is not None:
                try:
                    allowed, remaining, retry_after = self._evaluate_token_bucket_redis(
                        r, key, policy.burst_capacity, policy.refill_rate_per_sec
                    )
                except Exception as ex:
                    logger.warning("Redis error during token bucket: %s. Using memory.", ex)
                    allowed, remaining, retry_after = self._evaluate_token_bucket_mem(
                        key, policy.burst_capacity, policy.refill_rate_per_sec
                    )
            else:
                allowed, remaining, retry_after = self._evaluate_token_bucket_mem(
                    key, policy.burst_capacity, policy.refill_rate_per_sec
                )

        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            retry_after=retry_after,
            limit=limit,
            scope=policy.scope,
            algorithm=policy.algorithm,
            policy_name=policy.name,
        )

    def reset_key(self, key_pattern: str) -> None:
        """Resets rate limit counters matching pattern in Redis and memory."""
        with self._lock:
            # Memory reset
            to_del_slide = [k for k in self._mem_sliding if fnmatch.fnmatch(k, key_pattern)]
            for k in to_del_slide:
                del self._mem_sliding[k]

            to_del_token = [k for k in self._mem_tokens if fnmatch.fnmatch(k, key_pattern)]
            for k in to_del_token:
                del self._mem_tokens[k]

        r = self.redis_conn
        if r is not None:
            try:
                keys = r.keys(f"*{key_pattern}*")
                if keys:
                    r.delete(*keys)
            except Exception:
                pass


# Global singleton instance
advanced_rate_limiter = AdvancedRateLimiter()
