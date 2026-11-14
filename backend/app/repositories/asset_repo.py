"""
PREVENT-X Managed Asset Repository
Enforces tenant isolation for all asset queries.
"""

from backend.app.models.asset import ManagedAsset
from backend.app.repositories.base import TenantScopedRepository


class AssetRepository(TenantScopedRepository[ManagedAsset]):
    def __init__(self):
        super().__init__(ManagedAsset)


asset_repo = AssetRepository()
