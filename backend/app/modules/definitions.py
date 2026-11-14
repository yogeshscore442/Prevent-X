"""
PREVENT-X Module Architecture Boundaries (Modules 01 - 12)
Establishes clear boundaries and contracts aligned with NASSCOM PS-05.
"""

from typing import List
from backend.app.modules.interfaces import BaseSecurityModule


class AttackSurfaceIntelligenceModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-01"

    @property
    def name(self) -> str:
        return "Attack Surface Intelligence Engine"

    @property
    def description(self) -> str:
        return "Continuously discovers, catalogs, and monitors external SMB digital exposure points and authorized assets."

    @property
    def target_phase(self) -> int:
        return 2

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        if action_name == "calculate_risk":
            from backend.app.modules.attack_surface.risk_engine import DeterministicRiskEngine
            engine = DeterministicRiskEngine()
            return engine.calculate_risk(
                domain_name=payload.get("domain_name", ""),
                subdomains=payload.get("subdomains", []),
                dns_data=payload.get("dns_data", {}),
                certificates=payload.get("certificates", []),
                rdap_data=payload.get("rdap_data"),
            )
        elif action_name == "normalize_domain":
            from backend.app.modules.attack_surface.scope_validator import ScopeValidator
            return {"normalized": ScopeValidator.normalize_target_domain(payload.get("target", ""))}
        else:
            raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")


class AdvancedVulnerabilityMappingModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-02"

    @property
    def name(self) -> str:
        return "Advanced Vulnerability Mapping Engine"

    @property
    def description(self) -> str:
        return "Ingests NVD/CVE feeds and maps security flaws directly to detected asset technology stacks."

    @property
    def target_phase(self) -> int:
        return 3


class AttackPathPrerequisiteAnalysisModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-03"

    @property
    def name(self) -> str:
        return "Attack Path and Prerequisite Analysis Engine"

    @property
    def description(self) -> str:
        return "Graph-based kill-chain modeling to analyze exploit prerequisites and blast radiuses across SMB infrastructure."

    @property
    def target_phase(self) -> int:
        return 4


class ZeroTrustSecurityModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-04"

    @property
    def name(self) -> str:
        return "Zero Trust Security Engine"

    @property
    def description(self) -> str:
        return "Enforces micro-segmentation, continuous identity verification, and contextual access gates."

    @property
    def target_phase(self) -> int:
        return 4


class AIThreatIntelligenceModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-05"

    @property
    def name(self) -> str:
        return "AI Threat Intelligence Engine"

    @property
    def description(self) -> str:
        return "Correlates emerging threat actor tactics, techniques, and procedures (TTPs) with local SMB exposures."

    @property
    def target_phase(self) -> int:
        return 5


class ProactiveSecurityHardeningModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-06"

    @property
    def name(self) -> str:
        return "Proactive Security Hardening Engine"

    @property
    def description(self) -> str:
        return "Recommends configuration baselines, CIS benchmark alignments, and reduces attack vectors prior to exploitation."

    @property
    def target_phase(self) -> int:
        return 5


class ZeroDayUnknownThreatProtectionModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-07"

    @property
    def name(self) -> str:
        return "Zero-Day and Unknown Threat Protection Engine"

    @property
    def description(self) -> str:
        return "Heuristic, behavioral, and anomaly-based traffic inspection targeting unpatched zero-day exploits."

    @property
    def target_phase(self) -> int:
        return 6


class IntelligentVirtualPatchingModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-08"

    @property
    def name(self) -> str:
        return "Intelligent Virtual Patching Engine"

    @property
    def description(self) -> str:
        return "Core PS-05 engine: Synthesizes precise compensating security rules (WAF/Envoy/Nginx/eBPF) without code changes."

    @property
    def target_phase(self) -> int:
        return 6


class RealTimeTrafficMonitoringModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-09"

    @property
    def name(self) -> str:
        return "Real-Time Traffic Monitoring Engine"

    @property
    def description(self) -> str:
        return "Passive and inline flow analysis observing request patterns, error rates, and security enforcement."

    @property
    def target_phase(self) -> int:
        return 7


class AutomatedSecurityValidationModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-10"

    @property
    def name(self) -> str:
        return "Automated Security Validation Engine"

    @property
    def description(self) -> str:
        return "Replays benign and exploit traffic against candidate virtual patches to verify zero false-blocks."

    @property
    def target_phase(self) -> int:
        return 7


class AutomatedResponseReliableRollbackModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-11"

    @property
    def name(self) -> str:
        return "Automated Response and Reliable Rollback Engine"

    @property
    def description(self) -> str:
        return "Orchestrates instant atomic rollback and policy reversion if service degradation or false-positives occur."

    @property
    def target_phase(self) -> int:
        return 8


class CentralizedSMBSecurityPlatformModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-12"

    @property
    def name(self) -> str:
        return "Centralized SMB Security Management Platform"

    @property
    def description(self) -> str:
        return "Multi-tenant orchestration hub, providing unified policy distribution and executive reporting for SMBs."

    @property
    def target_phase(self) -> int:
        return 1

    @property
    def is_operational(self) -> bool:
        # Phase 1 operational foundation represents the core multi-tenant management platform
        return True


# Global registry of all 12 modules
ALL_MODULES: List[BaseSecurityModule] = [
    AttackSurfaceIntelligenceModule(),
    AdvancedVulnerabilityMappingModule(),
    AttackPathPrerequisiteAnalysisModule(),
    ZeroTrustSecurityModule(),
    AIThreatIntelligenceModule(),
    ProactiveSecurityHardeningModule(),
    ZeroDayUnknownThreatProtectionModule(),
    IntelligentVirtualPatchingModule(),
    RealTimeTrafficMonitoringModule(),
    AutomatedSecurityValidationModule(),
    AutomatedResponseReliableRollbackModule(),
    CentralizedSMBSecurityPlatformModule(),
]

