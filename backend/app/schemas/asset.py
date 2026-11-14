"""
PREVENT-X Managed Asset Schemas
"""

import uuid
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class AssetCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    asset_type: str = Field(..., pattern=r"^(WEB_APPLICATION|API_GATEWAY|PUBLIC_IP|INTERNAL_SERVER|DOMAIN)$")
    target: str = Field(..., min_length=3, max_length=255, description="FQDN, URL, or IP address")
    environment: str = Field("PRODUCTION", pattern=r"^(PRODUCTION|STAGING|DEVELOPMENT)$")
    criticality: str = Field("HIGH", pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW)$")
    is_in_scope: bool = Field(True, description="Explicit authorization for monitoring and virtual patch application")


class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    criticality: Optional[str] = Field(None, pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW)$")
    environment: Optional[str] = Field(None, pattern=r"^(PRODUCTION|STAGING|DEVELOPMENT)$")
    is_in_scope: Optional[bool] = None


class AssetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    asset_type: str
    target: str
    environment: str
    criticality: str
    is_in_scope: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    total: int
