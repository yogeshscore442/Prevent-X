"""
PREVENT-X Role and Permission Schemas
"""

import uuid
from typing import List
from pydantic import BaseModel, ConfigDict


class PermissionResponse(BaseModel):
    id: uuid.UUID
    code: str
    name: str
    description: str
    module: str

    model_config = ConfigDict(from_attributes=True)


class RoleResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    is_system_role: bool
    permissions: List[PermissionResponse] = []

    model_config = ConfigDict(from_attributes=True)
