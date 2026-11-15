"""
PREVENT-X Advanced Rate Limiting REST API
Provides endpoints for managing rate limit policies, evaluating quotas,
and resetting counters across sliding-window and token-bucket algorithms.
"""

import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.database.session import get_db
from backend.app.models.network_defense import (
    RateLimitPolicy,
    RateLimitScope,
    RateLimitingAlgorithm,
)
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.modules.network_defense.rate_limiting.service import (
    rate_limit_service,
)
from backend.app.schemas.network_defense import (
    RateLimitEvaluationResult,
    RateLimitPolicyCreate,
    RateLimitPolicyResponse,
)
from backend.app.security.permissions import (
    PermissionCode,
    get_current_organization,
    get_current_user,
    require_permission,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network-defense/rate-limiting", tags=["Advanced Network Defense - Rate Limiting"])


class RateLimitTestRequest(BaseModel):
    client_ip: str = Field(..., description="Simulated client IP")
    path: str = Field(..., description="Target request path to test")


@router.get(
    "/policies",
    response_model=List[RateLimitPolicyResponse],
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def list_rate_limit_policies(
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Lists all active rate limit policies for the authenticated organization."""
    return rate_limit_service.list_policies(db, org.id)


@router.post(
    "/policies",
    response_model=RateLimitPolicyResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def create_rate_limit_policy(
    payload: RateLimitPolicyCreate,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
    user: User = Depends(get_current_user),
):
    """Creates a new sliding-window or token-bucket rate limit policy."""
    policy = rate_limit_service.create_policy(
        db=db,
        organization_id=org.id,
        name=payload.name,
        endpoint_pattern=payload.endpoint_pattern,
        scope=payload.scope,
        algorithm=payload.algorithm,
        max_requests=payload.max_requests,
        window_seconds=payload.window_seconds,
        burst_capacity=payload.burst_capacity,
        refill_rate_per_sec=payload.refill_rate_per_sec,
    )
    return policy


@router.delete(
    "/policies/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(PermissionCode.RESPONSE_ACTION_EXECUTE))],
)
def delete_rate_limit_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """Deletes a rate limit policy and clears its counters."""
    deleted = rate_limit_service.delete_policy(db, policy_id, org.id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/evaluate",
    response_model=RateLimitEvaluationResult,
    dependencies=[Depends(require_permission(PermissionCode.ZERO_TRUST_READ))],
)
def test_rate_limit_evaluation(
    payload: RateLimitTestRequest,
    response: Response,
    db: Session = Depends(get_db),
    org: Organization = Depends(get_current_organization),
):
    """
    Evaluates an IP and path against active policies and sets standard rate limit headers.
    Returns 429 if the quota is exceeded.
    """
    allowed, result = rate_limit_service.check_request(
        db=db,
        organization_id=org.id,
        client_ip=payload.client_ip,
        path=payload.path,
    )

    if result is not None:
        response.headers["X-RateLimit-Limit"] = str(result.limit)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        response.headers["X-RateLimit-Reset"] = str(result.retry_after)

        if not allowed:
            response.headers["Retry-After"] = str(result.retry_after)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for policy '{result.policy_name}'. Retry in {result.retry_after}s.",
                headers={"Retry-After": str(result.retry_after)},
            )

        return RateLimitEvaluationResult(
            allowed=True,
            remaining=result.remaining,
            retry_after=0,
            limit=result.limit,
            scope=result.scope,
            algorithm=result.algorithm,
        )

    # No matching policy - default allowed
    return RateLimitEvaluationResult(
        allowed=True,
        remaining=999,
        retry_after=0,
        limit=1000,
        scope=RateLimitScope.IP,
        algorithm=RateLimitingAlgorithm.SLIDING_WINDOW,
    )


@router.post(
    "/reset",
    dependencies=[Depends(require_permission(PermissionCode.SYSTEM_WRITE))],
)
def reset_rate_limit_counters(key_pattern: str = Query("*")):
    """Resets rate limit counter keys in Redis and memory."""
    rate_limit_service.limiter.reset_key(key_pattern)
    return {"status": "SUCCESS", "message": f"Counters matching '{key_pattern}' reset."}
