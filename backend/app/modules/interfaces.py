"""
PREVENT-X Module Architecture and Common Interfaces
Defines standard contracts and boundaries for all 12 cybersecurity modules.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from backend.app.schemas.system import ModuleStatus


class ModuleOperationalState(str, Enum):
    OPERATIONAL = "OPERATIONAL"
    ARCHITECTURAL_STUB = "ARCHITECTURAL_STUB"
    PLANNED_PHASE = "PLANNED_PHASE"


class BaseSecurityModule(ABC):
    """
    Standard interface for all PREVENT-X cybersecurity engines.
    Establishes contracts for lifecycle, telemetry, and integration.
    """
    @property
    @abstractmethod
    def module_id(self) -> str:
        """Unique identifier, e.g., 'MOD-01'"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable module title."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module functional description and scope."""
        pass

    @property
    @abstractmethod
    def target_phase(self) -> int:
        """Implementation phase (1 through 9)."""
        pass

    @property
    def is_operational(self) -> bool:
        """Returns True only when the module's implementation is active in current phase."""
        return False

    def get_status(self) -> ModuleStatus:
        """Returns structured module status for system health telemetry."""
        state = (
            ModuleOperationalState.OPERATIONAL
            if self.is_operational
            else ModuleOperationalState.PLANNED_PHASE
        )
        return ModuleStatus(
            module_id=self.module_id,
            name=self.name,
            status=state.value,
            phase=self.target_phase,
            description=self.description,
        )

    def initialize(self, db: Session, config: Optional[Dict[str, Any]] = None) -> None:
        """Module startup and hook registration."""
        pass

    def execute_action(self, action_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an engine action.
        Raises NotImplementedError for future phases to prevent fake functionality.
        """
        raise NotImplementedError(
            f"Module {self.module_id} ({self.name}) is planned for Phase {self.target_phase} "
            f"and is not operational in Phase 1."
        )

