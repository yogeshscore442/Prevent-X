"""
PREVENT-X Organization Schemas
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")
    sector: Optional[str] = Field(None, max_length=100)
    contact_email: EmailStr


class OrganizationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    sector: Optional[str] = Field(None, max_length=100)
    contact_email: Optional[EmailStr] = None
    is_active: Optional[bool] = None


class OrganizationResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    sector: Optional[str]
    contact_email: EmailStr
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationListResponse(BaseModel):
    items: List[OrganizationResponse]
    total: int
