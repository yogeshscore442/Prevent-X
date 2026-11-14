"""
PREVENT-X Module Registry
Provides discovery, status tracking, and dependency boundaries across all security engines.
"""

from typing import Dict, List, Optional
from backend.app.modules.definitions import ALL_MODULES
from backend.app.modules.interfaces import BaseSecurityModule
from backend.app.schemas.system import ModuleStatus


class ModuleRegistry:
    def __init__(self):
        self._modules: Dict[str, BaseSecurityModule] = {
            m.module_id: m for m in ALL_MODULES
        }

    def get_module(self, module_id: str) -> Optional[BaseSecurityModule]:
        return self._modules.get(module_id)

    def list_all_modules(self) -> List[BaseSecurityModule]:
        return list(self._modules.values())

    def get_all_statuses(self) -> List[ModuleStatus]:
        return [m.get_status() for m in self._modules.values()]


module_registry = ModuleRegistry()

