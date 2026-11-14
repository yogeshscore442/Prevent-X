"""
PREVENT-X Role-Based Access Control (RBAC) and Security Dependencies
"""

import uuid
from typing import Callable, Optional, Set
from fastapi import Depends, Header, Request, status
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.core.exceptions import (
    AuthenticationFailedException,
    InsufficientPermissionsException,
    TenantAccessDeniedException,
)
from backend.app.database.base import utc_now
from backend.app.database.session import get_db
from backend.app.models.organization import Organization
from backend.app.models.session import UserSession
from backend.app.models.user import OrganizationMembership, User
from backend.app.security.tokens import decode_access_token


# Built-in Roles
class SystemRole:
    SUPER_ADMIN = "SUPER_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


# Granular Permissions
class PermissionCode:
    ORG_READ = "org:read"
    ORG_WRITE = "org:write"
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    ROLE_READ = "role:read"
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"
    ASSET_DELETE = "asset:delete"
    AUDIT_READ = "audit:read"
    SYSTEM_READ = "system:read"
    SYSTEM_WRITE = "system:write"


# Default Role-Permission matrix
ROLE_PERMISSIONS_MAP = {
    SystemRole.SUPER_ADMIN: {
        PermissionCode.ORG_READ,
        PermissionCode.ORG_WRITE,
        PermissionCode.USER_READ,
        PermissionCode.USER_WRITE,
        PermissionCode.ROLE_READ,
        PermissionCode.ASSET_READ,
        PermissionCode.ASSET_WRITE,
        PermissionCode.ASSET_DELETE,
        PermissionCode.AUDIT_READ,
        PermissionCode.SYSTEM_READ,
        PermissionCode.SYSTEM_WRITE,
    },
    SystemRole.ORG_ADMIN: {
        PermissionCode.ORG_READ,
        PermissionCode.USER_READ,
        PermissionCode.USER_WRITE,
        PermissionCode.ROLE_READ,
        PermissionCode.ASSET_READ,
        PermissionCode.ASSET_WRITE,
        PermissionCode.ASSET_DELETE,
        PermissionCode.AUDIT_READ,
        PermissionCode.SYSTEM_READ,
    },
    SystemRole.SECURITY_ANALYST: {
        PermissionCode.ORG_READ,
        PermissionCode.USER_READ,
        PermissionCode.ROLE_READ,
        PermissionCode.ASSET_READ,
        PermissionCode.ASSET_WRITE,
        PermissionCode.AUDIT_READ,
        PermissionCode.SYSTEM_READ,
    },
    SystemRole.AUDITOR: {
        PermissionCode.ORG_READ,
        PermissionCode.USER_READ,
        PermissionCode.ROLE_READ,
        PermissionCode.ASSET_READ,
        PermissionCode.AUDIT_READ,
        PermissionCode.SYSTEM_READ,
    },
    SystemRole.VIEWER: {
        PermissionCode.ORG_READ,
        PermissionCode.USER_READ,
        PermissionCode.ASSET_READ,
        PermissionCode.SYSTEM_READ,
    },
}


def extract_token_from_request(request: Request) -> Optional[str]:
    """Extracts authentication token from Authorization header or HttpOnly cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()

    cookie_token = request.cookies.get("preventx_session")
    if cookie_token:
        return cookie_token

    return None


def get_current_user_and_session(
    request: Request,
    db: Session = Depends(get_db),
) -> tuple[User, UserSession]:
    """
    Validates token, ensures active server-side session, checks expiration & revocation.
    """
    token_str = extract_token_from_request(request)
    if not token_str:
        raise AuthenticationFailedException("Authentication required")

    # The token can be a direct session_token or a signed JWT containing a jti/session_id
    session_record: Optional[UserSession] = None

    # First attempt JWT decoding
    payload = decode_access_token(token_str)
    if payload and "sid" in payload:
        try:
            sid = uuid.UUID(payload["sid"])
            session_record = db.query(UserSession).filter(UserSession.id == sid).first()
        except Exception:
            session_record = None

    if not session_record:
        # Check if token matches session_token directly
        session_record = db.query(UserSession).filter(UserSession.session_token == token_str).first()

    if not session_record:
        raise AuthenticationFailedException("Session not found")

    if not session_record.is_valid:
        raise AuthenticationFailedException("Session expired or revoked")

    user = db.query(User).filter(User.id == session_record.user_id).first()
    if not user or not user.is_active:
        raise AuthenticationFailedException("User account inactive or removed")

    return user, session_record


def get_current_user(
    auth_data: tuple[User, UserSession] = Depends(get_current_user_and_session),
) -> User:
    return auth_data[0]


def get_current_session(
    auth_data: tuple[User, UserSession] = Depends(get_current_user_and_session),
) -> UserSession:
    return auth_data[1]


def get_current_organization(
    request: Request,
    user: User = Depends(get_current_user),
    session_record: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
    x_organization_id: Optional[str] = Header(None, alias="X-Organization-Id"),
) -> Organization:
    """
    Resolves active tenant organization for request.
    Enforces strict tenant isolation: rejects any attempt to specify an organization
    to which the authenticated user does not belong (unless superuser).
    """
    target_org_id_str = x_organization_id
    if not target_org_id_str and session_record.organization_id:
        target_org_id_str = str(session_record.organization_id)

    target_org_id: Optional[uuid.UUID] = None
    if target_org_id_str:
        try:
            target_org_id = uuid.UUID(target_org_id_str)
        except ValueError:
            raise TenantAccessDeniedException("Invalid organization identifier format")

    if target_org_id:
        # Check if user is superuser or has membership in requested organization
        if not user.is_superuser:
            membership = (
                db.query(OrganizationMembership)
                .filter(
                    OrganizationMembership.user_id == user.id,
                    OrganizationMembership.organization_id == target_org_id,
                )
                .first()
            )
            if not membership:
                raise TenantAccessDeniedException("User is not a member of the requested organization")

        org = db.query(Organization).filter(Organization.id == target_org_id).first()
        if not org or not org.is_active:
            raise TenantAccessDeniedException("Organization not found or inactive")
        return org

    # If no specific org was requested, pick user's default or first membership
    if user.is_superuser:
        first_org = db.query(Organization).filter(Organization.is_active == True).first()
        if first_org:
            return first_org

    membership = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.user_id == user.id)
        .order_by(OrganizationMembership.is_default.desc(), OrganizationMembership.created_at.asc())
        .first()
    )
    if not membership:
        raise TenantAccessDeniedException("User has no active organization memberships")

    org = db.query(Organization).filter(Organization.id == membership.organization_id).first()
    if not org or not org.is_active:
        raise TenantAccessDeniedException("Organization not found or inactive")
    return org


def require_permission(required_permission: str) -> Callable:
    """
    Dependency factory verifying that current user holds `required_permission`
    within the active tenant organization context.
    """
    def permission_checker(
        user: User = Depends(get_current_user),
        org: Organization = Depends(get_current_organization),
        db: Session = Depends(get_db),
    ) -> bool:
        if user.is_superuser:
            return True

        membership = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.organization_id == org.id,
            )
            .first()
        )
        if not membership or not membership.role:
            raise InsufficientPermissionsException(required_permission)

        user_permissions: Set[str] = {p.code for p in membership.role.permissions}
        if required_permission not in user_permissions:
            raise InsufficientPermissionsException(required_permission)

        return True

    return permission_checker


def require_superuser(
    user: User = Depends(get_current_user),
) -> User:
    """Dependency requiring superuser privileges."""
    if not user.is_superuser:
        raise InsufficientPermissionsException("Superuser administrative privileges required")
    return user

