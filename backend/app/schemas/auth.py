"""
PREVENT-X Authentication Pydantic Schemas
"""

import uuid
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    organization_slug: Optional[str] = None


class TokenPayload(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    session_id: uuid.UUID


class UserMembershipInfo(BaseModel):
    organization_id: uuid.UUID
    organization_name: str
    organization_slug: str
    role_name: str
    permissions: List[str]


class UserMeResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str
    is_superuser: bool
    is_active: bool
    current_organization_id: Optional[uuid.UUID] = None
    memberships: List[UserMembershipInfo] = []


class LoginResponse(BaseModel):
    user: UserMeResponse
    tokens: TokenPayload
    message: str = "Authentication successful"


class BootstrapRequest(BaseModel):
    bootstrap_token: str = Field(..., min_length=16)
    email: EmailStr
    password: str = Field(..., min_length=12)
    full_name: str = Field(..., min_length=3)
    initial_organization_name: str = Field(..., min_length=3)
    initial_organization_slug: str = Field(..., min_length=3)


class BootstrapResponse(BaseModel):
    status: str
    message: str
    user_id: uuid.UUID
    organization_id: uuid.UUID


class LogoutResponse(BaseModel):
    status: str
    message: str

