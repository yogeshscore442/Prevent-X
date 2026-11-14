"""
PREVENT-X Attack Surface Intelligence Engine (Module MOD-01)
Phase 2 Foundation: Passive External Discovery, DNS Intelligence, CT Logs, and Exposure Findings.
"""

from backend.app.modules.attack_surface.service import AttackSurfaceService
from backend.app.modules.attack_surface.scope_validator import ScopeValidator
from backend.app.modules.attack_surface.discovery_manager import DiscoveryManager
from backend.app.modules.attack_surface.evidence_manager import EvidenceManager
from backend.app.modules.attack_surface.risk_engine import DeterministicRiskEngine

__all__ = [
    "AttackSurfaceService",
    "ScopeValidator",
    "DiscoveryManager",
    "EvidenceManager",
    "DeterministicRiskEngine",
]
