"""
PREVENT-X Rate Limiting Management Service
Manages tenant rate limit policies and matches incoming requests against configured limits.
"""

import fnmatch
import logging
import uuid
from typing import List, Optional, Tuple

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from backend.app.models.audit_log import AuditEvent
from backend.app.models.network_defense import (
    RateLimitPolicy,
    RateLimitScope,
    RateLimitingAlgorithm,
)
from backend.app.modules.network_defense.rate_limiting.limiter import (
    AdvancedRateLimiter,
    RateLimitResult,
    advanced_rate_limiter,
)

logger = logging.getLogger("preventx.network_defense.rate_limiting.service")


class RateLimitService:
    def __init__(self, limiter: Optional[AdvancedRateLimiter] = None):
        self.limiter = limiter or advanced_rate_limiter

    def create_policy(
        self,
        db: Session,
        organization_id: uuid.UUID,
        name: str,
        endpoint_pattern: str,
        scope: RateLimitScope = RateLimitScope.IP,
        algorithm: RateLimitingAlgorithm = RateLimitingAlgorithm.SLIDING_WINDOW,
        max_requests: int = 60,
        window_seconds: int = 60,
        burst_capacity: int = 10,
        refill_rate_per_sec: float = 1.0,
    ) -> RateLimitPolicy:
        """Creates a persistent rate limit policy."""
        policy = RateLimitPolicy(
            organization_id=organization_id,
            name=name,
            endpoint_pattern=endpoint_pattern,
            scope=scope,
            algorithm=algorithm,
            max_requests=max_requests,
            window_seconds=window_seconds,
            burst_capacity=burst_capacity,
            refill_rate_per_sec=refill_rate_per_sec,
            is_active=True,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
        return policy

    def list_policies(self, db: Session, organization_id: uuid.UUID) -> List[RateLimitPolicy]:
        return db.execute(
            select(RateLimitPolicy)
            .where(RateLimitPolicy.organization_id == organization_id)
            .order_by(RateLimitPolicy.created_at.desc())
        ).scalars().all()

    def delete_policy(self, db: Session, policy_id: str, organization_id: uuid.UUID) -> bool:
        policy = db.execute(
            select(RateLimitPolicy).where(
                and_(RateLimitPolicy.id == policy_id, RateLimitPolicy.organization_id == organization_id)
            )
        ).scalar_one_or_none()
        if not policy:
            return False
        db.delete(policy)
        db.commit()
        self.limiter.reset_key(f"*{policy_id}*")
        return True

    def check_request(
        self,
        db: Session,
        organization_id: uuid.UUID,
        client_ip: str,
        path: str,
    ) -> Tuple[bool, Optional[RateLimitResult]]:
        """
        Evaluates a request path against all active tenant policies.
        Returns: (is_allowed, most_restrictive_or_tripped_result)
        """
        policies = db.execute(
            select(RateLimitPolicy).where(
                and_(
                    RateLimitPolicy.organization_id == organization_id,
                    RateLimitPolicy.is_active == True,
                )
            )
        ).scalars().all()

        if not policies:
            return True, None

        last_matched_res = None
        for policy in policies:
            # Check pattern match: e.g., "/api/v1/auth/*" matches "/api/v1/auth/login"
            pattern = policy.endpoint_pattern
            if pattern == "*" or fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(f"{path}/", pattern):
                res = self.limiter.evaluate(policy, client_ip, path)
                if not res.allowed:
                    return False, res
                last_matched_res = res

        return True, last_matched_res


# Global rate limit service
rate_limit_service = RateLimitService()
