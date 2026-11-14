"""
PREVENT-X Authentication and Session Service
Orchestrates secure authentication, Argon2id verification, session lifecycle, and audit trails.
"""

import uuid
from datetime import timedelta
from typing import Optional, Tuple
from fastapi import Request
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.exceptions import (
    AuthenticationFailedException,
    ValidationException,
)
from backend.app.database.base import utc_now
from backend.app.models.organization import Organization
from backend.app.models.role import Role
from backend.app.models.session import UserSession
from backend.app.models.user import OrganizationMembership, User
from backend.app.repositories.audit_repo import audit_repo
from backend.app.repositories.organization_repo import organization_repo
from backend.app.repositories.user_repo import user_repo
from backend.app.schemas.auth import (
    BootstrapRequest,
    BootstrapResponse,
    LoginRequest,
    LoginResponse,
    TokenPayload,
    UserMeResponse,
    UserMembershipInfo,
)
from backend.app.security.passwords import hash_password, verify_password
from backend.app.security.permissions import SystemRole
from backend.app.security.rate_limiter import rate_limiter
from backend.app.security.tokens import create_access_token, generate_secure_token
from backend.app.services.bootstrap_service import initialize_system_roles_and_permissions


class AuthService:
    def bootstrap_admin(self, db: Session, req: BootstrapRequest, request: Optional[Request] = None) -> BootstrapResponse:
        """
        Secure administrator bootstrap mechanism.
        Requires correct pre-configured BOOTSTRAP_TOKEN.
        """
        # Validate bootstrap token
        if req.bootstrap_token != settings.BOOTSTRAP_TOKEN:
            audit_repo.log_event(
                db=db,
                action="ADMIN_BOOTSTRAP_FAILED",
                resource_type="SYSTEM",
                status="DENIED",
                ip_address=request.client.host if request and request.client else None,
                details="Invalid bootstrap token provided",
            )
            raise ValidationException("Invalid bootstrap token.")

        # Ensure system roles are seeded
        initialize_system_roles_and_permissions(db)

        # Check if email is already in use
        existing_user = user_repo.get_by_email(db, req.email)
        if existing_user:
            raise ValidationException(f"User with email '{req.email}' already exists.")

        # Check if organization slug is in use
        existing_org = organization_repo.get_by_slug(db, req.initial_organization_slug)
        if existing_org:
            raise ValidationException(f"Organization slug '{req.initial_organization_slug}' is already taken.")

        # Create primary tenant organization
        org = Organization(
            name=req.initial_organization_name,
            slug=req.initial_organization_slug.lower(),
            contact_email=req.email.lower(),
            sector="Cybersecurity Operations",
            is_active=True,
        )
        db.add(org)
        db.flush()

        # Create root administrator
        hashed_pwd = hash_password(req.password)
        admin_user = User(
            email=req.email.lower(),
            hashed_password=hashed_pwd,
            full_name=req.full_name,
            is_active=True,
            is_superuser=True,
        )
        db.add(admin_user)
        db.flush()

        # Assign SUPER_ADMIN role membership
        super_admin_role = db.query(Role).filter(Role.name == SystemRole.SUPER_ADMIN).first()
        if not super_admin_role:
            raise ValidationException("Super admin role not found in system.")

        membership = OrganizationMembership(
            user_id=admin_user.id,
            organization_id=org.id,
            role_id=super_admin_role.id,
            is_default=True,
        )
        db.add(membership)
        db.commit()

        # Audit log the successful bootstrap
        audit_repo.log_event(
            db=db,
            action="ADMIN_BOOTSTRAP_SUCCESS",
            resource_type="USER",
            resource_id=str(admin_user.id),
            organization_id=org.id,
            user_id=admin_user.id,
            status="SUCCESS",
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=f"Admin {admin_user.email} bootstrapped organization {org.name}",
        )

        return BootstrapResponse(
            status="SUCCESS",
            message="Administrator account and initial tenant organization bootstrapped successfully.",
            user_id=admin_user.id,
            organization_id=org.id,
        )

    def login(
        self,
        db: Session,
        req: LoginRequest,
        request: Optional[Request] = None,
    ) -> Tuple[LoginResponse, str, str]:
        """
        Executes secure authentication.
        Enforces rate limiting, Argon2id verification, and session creation.
        Returns: (LoginResponse, session_token, raw_access_token)
        """
        ip = request.client.host if request and request.client else "127.0.0.1"
        rate_limiter_key = f"auth:{ip}:{req.email.lower()}"

        # Rate limit check (e.g. max 10 attempts per minute)
        rate_limiter.enforce(
            rate_limiter_key,
            max_requests=settings.AUTH_RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
        )

        user = user_repo.get_by_email(db, req.email.lower())
        if not user or not verify_password(req.password, user.hashed_password):
            audit_repo.log_event(
                db=db,
                action="AUTH_LOGIN_FAILED",
                resource_type="USER",
                status="FAILURE",
                ip_address=ip,
                user_agent=request.headers.get("user-agent") if request else None,
                details=f"Failed login attempt for {req.email}",
            )
            raise AuthenticationFailedException("Invalid email or password.")

        if not user.is_active:
            audit_repo.log_event(
                db=db,
                action="AUTH_LOGIN_FAILED",
                resource_type="USER",
                resource_id=str(user.id),
                status="DENIED",
                ip_address=ip,
                details="Inactive user account attempted login",
            )
            raise AuthenticationFailedException("Account is deactivated.")

        # Resolve organization context
        active_org: Optional[Organization] = None
        if req.organization_slug:
            active_org = organization_repo.get_by_slug(db, req.organization_slug.lower())
            if not active_org:
                raise AuthenticationFailedException("Specified organization not found.")
        elif user.memberships:
            default_mem = next((m for m in user.memberships if m.is_default), user.memberships[0])
            active_org = default_mem.organization
        elif user.is_superuser:
            active_org = db.query(Organization).filter(Organization.is_active == True).first()

        # Reset rate limiter upon successful credentials
        rate_limiter.reset(rate_limiter_key)

        # Create server-side session
        session_token = generate_secure_token(32)
        expires_at = utc_now() + timedelta(hours=settings.SESSION_EXPIRE_HOURS)

        session_record = UserSession(
            user_id=user.id,
            organization_id=active_org.id if active_org else None,
            session_token=session_token,
            ip_address=ip,
            user_agent=request.headers.get("user-agent") if request else None,
            expires_at=expires_at,
            is_active=True,
        )
        db.add(session_record)

        # Update last login
        user.last_login_at = utc_now()
        db.commit()
        db.refresh(session_record)

        # Generate JWT access token
        access_token_jwt = create_access_token({
            "sub": str(user.id),
            "email": user.email,
            "sid": str(session_record.id),
            "org_id": str(active_org.id) if active_org else None,
            "is_superuser": user.is_superuser,
        })

        # Log successful auth event
        audit_repo.log_event(
            db=db,
            action="AUTH_LOGIN_SUCCESS",
            resource_type="USER",
            resource_id=str(user.id),
            organization_id=active_org.id if active_org else None,
            user_id=user.id,
            status="SUCCESS",
            ip_address=ip,
            user_agent=request.headers.get("user-agent") if request else None,
            details=f"User {user.email} authenticated successfully",
        )

        user_me = self.build_user_me_response(user, active_org.id if active_org else None)
        token_payload = TokenPayload(
            access_token=access_token_jwt,
            token_type="bearer",
            expires_in_seconds=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            session_id=session_record.id,
        )

        return (
            LoginResponse(
                user=user_me,
                tokens=token_payload,
                message="Authentication successful",
            ),
            session_token,
            access_token_jwt,
        )

    def logout(
        self,
        db: Session,
        session_record: UserSession,
        request: Optional[Request] = None,
    ) -> None:
        """Revokes the active session in database."""
        session_record.is_active = False
        session_record.revoked_at = utc_now()
        db.commit()

        audit_repo.log_event(
            db=db,
            action="AUTH_LOGOUT",
            resource_type="SESSION",
            resource_id=str(session_record.id),
            organization_id=session_record.organization_id,
            user_id=session_record.user_id,
            status="SUCCESS",
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            details=f"Session revoked for user {session_record.user_id}",
        )

    def build_user_me_response(
        self,
        user: User,
        current_org_id: Optional[uuid.UUID] = None,
    ) -> UserMeResponse:
        """Assembles user profile with memberships and permissions."""
        membership_infos = []
        for m in user.memberships:
            perms = [p.code for p in m.role.permissions] if m.role else []
            membership_infos.append(
                UserMembershipInfo(
                    organization_id=m.organization.id,
                    organization_name=m.organization.name,
                    organization_slug=m.organization.slug,
                    role_name=m.role.name if m.role else "UNKNOWN",
                    permissions=perms,
                )
            )

        return UserMeResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_superuser=user.is_superuser,
            is_active=user.is_active,
            current_organization_id=current_org_id,
            memberships=membership_infos,
        )


auth_service = AuthService()

