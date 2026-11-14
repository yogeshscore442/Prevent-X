"""
PREVENT-X Authentication API Endpoints
"""

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.database.session import get_db
from backend.app.models.session import UserSession
from backend.app.models.user import User
from backend.app.schemas.auth import (
    BootstrapRequest,
    BootstrapResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    UserMeResponse,
)
from backend.app.security.csrf import generate_csrf_token, verify_csrf_token
from backend.app.security.permissions import (
    get_current_session,
    get_current_user,
)
from backend.app.services.auth_service import auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/bootstrap",
    response_model=BootstrapResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Bootstrap root administrator and initial tenant organization",
)
def bootstrap_admin(
    req: BootstrapRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    return auth_service.bootstrap_admin(db=db, req=req, request=request)


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate user and issue session token / HttpOnly cookies",
)
def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    login_resp, session_token, access_token = auth_service.login(db=db, req=req, request=request)

    # Set secure HttpOnly cookie for web browser session
    cookie_secure = settings.COOKIE_SECURE
    cookie_samesite = settings.COOKIE_SAMESITE.lower()
    max_age_seconds = settings.SESSION_EXPIRE_HOURS * 3600

    response.set_cookie(
        key="preventx_session",
        value=session_token,
        httponly=True,
        secure=cookie_secure,
        samesite=cookie_samesite,
        max_age=max_age_seconds,
        path="/",
    )

    # Generate and set CSRF cookie
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key="preventx_csrf_token",
        value=csrf_token,
        httponly=False,  # Accessible by frontend JavaScript to attach in headers
        secure=cookie_secure,
        samesite=cookie_samesite,
        max_age=max_age_seconds,
        path="/",
    )

    return login_resp


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Revoke active session and clear authentication cookies",
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    session_record: UserSession = Depends(get_current_session),
):
    # Verify CSRF token if cookie authentication is active
    verify_csrf_token(request)

    auth_service.logout(db=db, session_record=session_record, request=request)

    # Delete cookies
    response.delete_cookie(key="preventx_session", path="/")
    response.delete_cookie(key="preventx_csrf_token", path="/")

    return LogoutResponse(status="SUCCESS", message="Session revoked and logged out.")


@router.get(
    "/me",
    response_model=UserMeResponse,
    summary="Retrieve current authenticated user context and tenant memberships",
)
def get_current_user_profile(
    user: User = Depends(get_current_user),
    session_record: UserSession = Depends(get_current_session),
):
    return auth_service.build_user_me_response(
        user=user,
        current_org_id=session_record.organization_id,
    )
