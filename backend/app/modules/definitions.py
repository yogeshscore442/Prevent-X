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

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        if action_name == "sync_feeds":
            from backend.app.database.session import SessionLocal
            from backend.app.modules.vulnerability.feed_ingestion import VulnerabilityFeedIngester
            db = SessionLocal()
            try:
                return VulnerabilityFeedIngester.sync_all_feeds(db, fetch_remote=payload.get("fetch_remote", False))
            finally:
                db.close()
        elif action_name == "calculate_risk":
            from backend.app.modules.vulnerability.risk_engine import VulnerabilityRiskEngine
            return {"status": "READY"}
        else:
            raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")


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

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        if action_name == "analyze_paths":
            from uuid import UUID
            from backend.app.database.session import SessionLocal
            from backend.app.modules.attack_path.service import AttackPathService

            org_id_val = payload.get("organization_id")
            if not org_id_val:
                raise ValueError("organization_id is required for attack path analysis.")
            org_id = UUID(str(org_id_val))
            db = SessionLocal()
            try:
                return AttackPathService.run_analysis_sync(db, org_id)
            finally:
                db.close()
        elif action_name == "calculate_risk":
            from backend.app.modules.attack_path.risk_scorer import AttackPathRiskScorer
            return AttackPathRiskScorer.calculate_risk(
                is_internet_facing=payload.get("is_internet_facing", False),
                has_cisa_kev=payload.get("has_cisa_kev", False),
                max_cvss=payload.get("max_cvss"),
                has_vulnerabilities=payload.get("has_vulnerabilities", False),
                target_criticality=payload.get("target_criticality", "MEDIUM"),
                step_count=payload.get("step_count", 1),
                confidence=payload.get("confidence", "POTENTIAL"),
            )
        else:
            raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")


class ZeroTrustSecurityModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-04"

    @property
    def name(self) -> str:
        return "Zero Trust Security Engine"

    @property
    def description(self) -> str:
        return "Enforces micro-segmentation, continuous identity verification, behavioral anomaly detection, and contextual access gates."

    @property
    def target_phase(self) -> int:
        return 5

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.zero_trust.service import ZeroTrustService

        org_id_val = payload.get("organization_id")
        if not org_id_val:
            raise ValueError("organization_id is required for Zero Trust action.")
        org_id = UUID(str(org_id_val))

        db = SessionLocal()
        try:
            if action_name == "evaluate_posture":
                asset_id_val = payload.get("asset_id")
                if asset_id_val:
                    res = ZeroTrustService.evaluate_asset(db, UUID(str(asset_id_val)), org_id)
                    return {"status": "SUCCESS", "asset_id": str(res.asset_id), "decision": res.trust_decision, "score": res.trust_score}
                else:
                    assessments = ZeroTrustService.evaluate_all_assets(db, org_id)
                    return {"status": "SUCCESS", "evaluated_count": len(assessments)}
            elif action_name == "detect_anomalies":
                anomalies = ZeroTrustService.run_behavioral_evaluation(db, org_id)
                return {"status": "SUCCESS", "anomalies_detected": len(anomalies)}
            else:
                raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")
        finally:
            db.close()


class AIThreatIntelligenceModule(BaseSecurityModule):
    @property
    def module_id(self) -> str:
        return "MOD-05"

    @property
    def name(self) -> str:
        return "AI Threat Intelligence Engine"

    @property
    def description(self) -> str:
        return "Correlates emerging threat actor tactics, techniques, and procedures (TTPs) and indicators with local SMB exposures."

    @property
    def target_phase(self) -> int:
        return 5

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.zero_trust.service import ZeroTrustService

        org_id_val = payload.get("organization_id")
        org_id = UUID(str(org_id_val)) if org_id_val else None

        db = SessionLocal()
        try:
            if action_name == "sync_intel":
                count = ZeroTrustService.sync_threat_intel(db, org_id)
                return {"status": "SUCCESS", "indicators_synced": count}
            elif action_name == "correlate_threats":
                if not org_id:
                    raise ValueError("organization_id is required to correlate threats.")
                res = ZeroTrustService.run_threat_correlation(db, org_id)
                return {"status": "SUCCESS", "correlation_summary": res}
            else:
                raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")
        finally:
            db.close()


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
        return 6

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.virtual_patch.service import VirtualPatchService

        org_id_val = payload.get("organization_id")
        if not org_id_val:
            raise ValueError("organization_id is required.")
        org_id = UUID(str(org_id_val))

        db = SessionLocal()
        try:
            if action_name == "seed_baseline_rules":
                rules = VirtualPatchService.seed_baseline_rules(db, org_id)
                return {"status": "SUCCESS", "rules_created": len(rules)}
            else:
                raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")
        finally:
            db.close()


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

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.virtual_patch.service import VirtualPatchService

        org_id_val = payload.get("organization_id")
        if not org_id_val:
            raise ValueError("organization_id is required.")
        org_id = UUID(str(org_id_val))

        db = SessionLocal()
        try:
            if action_name == "generate_recommendations":
                recs = VirtualPatchService.generate_recommendations_for_organization(db, org_id)
                return {"status": "SUCCESS", "recommendations_count": len(recs)}
            elif action_name == "stage_deployment":
                dep = VirtualPatchService.stage_deployment(
                    db,
                    organization_id=org_id,
                    listen_port=payload.get("listen_port", 8085),
                    upstream_url=payload.get("upstream_url", "http://127.0.0.1:8086"),
                )
                return {"status": "SUCCESS", "deployment_id": str(dep.id), "deployment_status": dep.status}
            elif action_name == "get_stats":
                stats = VirtualPatchService.get_overview_stats(db, org_id)
                return {"status": "SUCCESS", "stats": stats}
            else:
                raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")
        finally:
            db.close()


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

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.monitoring.service import MonitoringService
        from backend.app.modules.monitoring.schemas import (
            BatchSecurityEventIngestRequest,
            SecurityEventCreate,
        )

        org_id_val = payload.get("organization_id")
        if not org_id_val:
            raise ValueError("organization_id is required.")
        org_id = UUID(str(org_id_val))

        db = SessionLocal()
        try:
            if action_name == "ingest_event":
                event_data = SecurityEventCreate(**payload["event"])
                event, is_dup = MonitoringService.ingest_single_event(db, org_id, event_data)
                return {
                    "status": "SUCCESS",
                    "event_id": str(event.id) if event else None,
                    "is_deduplicated": is_dup,
                }
            elif action_name == "ingest_batch":
                batch_req = BatchSecurityEventIngestRequest(**payload)
                res = MonitoringService.ingest_batch(db, org_id, batch_req)
                return res.model_dump()
            elif action_name == "get_events":
                events, total = MonitoringService.get_events(
                    db,
                    org_id,
                    source=payload.get("source"),
                    category=payload.get("category"),
                    severity=payload.get("severity"),
                    page=payload.get("page", 1),
                    size=payload.get("size", 50),
                )
                return {
                    "total": total,
                    "count": len(events),
                    "events": [str(e.id) for e in events],
                }
            else:
                raise ValueError(f"Unknown action '{action_name}' for {self.module_id}")
        finally:
            db.close()


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

    @property
    def is_operational(self) -> bool:
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.security_validation.service import SecurityValidationService
        from backend.app.modules.security_validation.schemas import ValidationJobCreate

        org_id_val = payload.get("organization_id")
        if not org_id_val:
            raise ValueError("organization_id is required.")
        org_id = UUID(str(org_id_val))

        db = SessionLocal()
        try:
            if action_name == "run_validation":
                dep_id = UUID(str(payload["deployment_id"])) if payload.get("deployment_id") else None
                job_data = ValidationJobCreate(
                    deployment_id=dep_id,
                    environment=payload.get("environment", "STAGING"),
                    target_url=payload.get("target_url", "http://127.0.0.1:8085"),
                    canary_percentage=payload.get("canary_percentage", 0),
                    trigger_type=payload.get("trigger_type", "MANUAL"),
                )
                user_id = UUID(str(payload["user_id"])) if payload.get("user_id") else None
                job = SecurityValidationService.create_and_run_validation_job(
                    db, organization_id=org_id, data=job_data, user_id=user_id
                )
                return {
                    "status": "SUCCESS",
                    "job_id": str(job.id),
                    "job_status": job.status,
                    "pass_rate": job.pass_rate_percentage,
                }
            elif action_name == "execute_rollback":
                dep_id = UUID(str(payload["deployment_id"]))
                target_dep_id = UUID(str(payload["target_deployment_id"])) if payload.get("target_deployment_id") else None
                reason = payload.get("rollback_reason", "Automated security validation failure rollback")
                user_id = UUID(str(payload["user_id"])) if payload.get("user_id") else None
                record = SecurityValidationService.execute_rollback(
                    db,
                    organization_id=org_id,
                    deployment_id=dep_id,
                    rollback_reason=reason,
                    target_deployment_id=target_dep_id,
                    operator_user_id=user_id,
                )
                return {
                    "status": "SUCCESS",
                    "rollback_id": str(record.id),
                    "rollback_status": record.status,
                    "verified": record.is_restoration_verified,
                }
            elif action_name == "get_overview":
                stats = SecurityValidationService.get_overview_stats(db, org_id)
                return {"status": "SUCCESS", "overview": stats}
            else:
                raise NotImplementedError(f"Action '{action_name}' is not supported by {self.module_id}.")
        finally:
            db.close()


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
        return True

    def execute_action(self, action_name: str, payload: dict) -> dict:
        from uuid import UUID
        from backend.app.database.session import SessionLocal
        from backend.app.modules.monitoring.service import MonitoringService
        from backend.app.modules.monitoring.schemas import (
            EventRetentionPolicyUpdate,
            SecurityIncidentCreate,
        )

        org_id_val = payload.get("organization_id")
        if not org_id_val:
            raise ValueError("organization_id is required.")
        org_id = UUID(str(org_id_val))

        db = SessionLocal()
        try:
            if action_name == "get_overview":
                stats = MonitoringService.get_security_center_overview(db, org_id)
                return stats.model_dump()
            elif action_name == "create_incident":
                inc_data = SecurityIncidentCreate(**payload["incident"])
                user_id = UUID(str(payload["user_id"])) if payload.get("user_id") else None
                inc = MonitoringService.create_incident(db, org_id, inc_data, actor_user_id=user_id)
                return {
                    "incident_id": str(inc.id),
                    "incident_number": inc.incident_number,
                    "status": inc.status,
                    "severity": inc.severity,
                }
            elif action_name == "update_retention":
                ret_data = EventRetentionPolicyUpdate(**payload["retention"])
                policy = MonitoringService.update_retention_policy(db, org_id, ret_data)
                return {
                    "policy_id": str(policy.id),
                    "retention_days": policy.retention_days,
                    "max_stored_events": policy.max_stored_events,
                    "auto_prune_enabled": policy.auto_prune_enabled,
                }
            elif action_name == "prune_events":
                count = MonitoringService.prune_expired_events(db, org_id)
                return {"pruned_count": count}
            else:
                raise ValueError(f"Unknown action '{action_name}' for {self.module_id}")
        finally:
            db.close()


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

