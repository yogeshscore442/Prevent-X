"""
PREVENT-X Standard Application Exceptions
Defines clean, consistent security and operational exceptions.
"""

from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class PreventXException(Exception):
    """Base exception for all PREVENT-X errors."""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR"):
        self.message = message
        self.code = code
        super().__init__(self.message)


class TenantAccessDeniedException(HTTPException):
    """Raised when an authenticated user attempts to access resources from another tenant."""
    def __init__(self, detail: str = "Access denied to cross-tenant resource"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "TENANT_ACCESS_DENIED", "message": detail},
        )


class InsufficientPermissionsException(HTTPException):
    """Raised when a user lacks required RBAC permissions."""
    def __init__(self, required_permission: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "INSUFFICIENT_PERMISSIONS",
                "message": f"Action requires permission: {required_permission}",
            },
        )


class AuthenticationFailedException(HTTPException):
    """Raised when authentication credentials fail."""
    def __init__(self, detail: str = "Invalid credentials or expired session"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTHENTICATION_FAILED", "message": detail},
            headers={"WWW-Authenticate": "Bearer"},
        )


class RateLimitExceededException(HTTPException):
    """Raised when request frequency exceeds security thresholds."""
    def __init__(self, retry_after: int = 60):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "RATE_LIMIT_EXCEEDED",
                "message": f"Too many requests. Please retry in {retry_after} seconds.",
            },
            headers={"Retry-After": str(retry_after)},
        )


class ResourceNotFoundException(HTTPException):
    """Raised when an entity is not found within the tenant scope."""
    def __init__(self, entity_name: str, identifier: Any):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "RESOURCE_NOT_FOUND",
                "message": f"{entity_name} '{identifier}' not found in organization scope",
            },
        )


class ValidationException(HTTPException):
    """Raised when domain business rules fail validation."""
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "VALIDATION_ERROR", "message": detail},
        )
