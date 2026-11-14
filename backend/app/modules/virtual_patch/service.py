"""
PREVENT-X Intelligent Virtual Patching Service (MOD-06, MOD-08)
Orchestrates virtual patch rule generation, versioning, deployment approvals,
Nginx reverse proxy lifecycle, and live enforcement audit logs.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.asset import ManagedAsset
from backend.app.models.organization import Organization
from backend.app.models.user import User
from backend.app.models.virtual_patch import (
    AttackType,
    DeploymentEnvironment,
    DeploymentStatus,
    PatchAction,
    PatchStatus,
    VirtualPatchDeployment,
    VirtualPatchRecommendation,
    VirtualPatchRule,
    VirtualPatchVersion,
    WafEnforcementLog,
)
from backend.app.models.vulnerability import VulnerabilityRecord
from backend.app.modules.virtual_patch.generator import IntelligentVirtualPatchGenerator
from backend.app.modules.virtual_patch.proxy_manager import NginxProxyManager
from backend.app.modules.virtual_patch.schemas import (
    MatchCondition,
    VirtualPatchRuleCreate,
    VirtualPatchRuleUpdate,
)
from backend.app.modules.virtual_patch.waf_compiler import WafConfigCompiler

logger = logging.getLogger("preventx.virtual_patch.service")


class VirtualPatchService:
    """
    Core service managing intelligent virtual patching, human-in-the-loop approvals,
    reverse proxy deployments, and real-time WAF telemetry.
    """

    @classmethod
    def get_overview_stats(cls, db: Session, organization_id: uuid.UUID) -> Dict[str, Any]:
        """
        Gathers aggregate metrics for the Virtual Patching dashboard.
        """
        total_rules = db.scalar(
            select(func.count(VirtualPatchRule.id)).where(VirtualPatchRule.organization_id == organization_id)
        ) or 0

        active_rules = db.scalar(
            select(func.count(VirtualPatchRule.id)).where(
                VirtualPatchRule.organization_id == organization_id,
                VirtualPatchRule.is_active == True,
            )
        ) or 0

        staging_deployments = db.scalar(
            select(func.count(VirtualPatchDeployment.id)).where(
                VirtualPatchDeployment.organization_id == organization_id,
                VirtualPatchDeployment.environment == DeploymentEnvironment.STAGING.value,
            )
        ) or 0

        production_deployments = db.scalar(
            select(func.count(VirtualPatchDeployment.id)).where(
                VirtualPatchDeployment.organization_id == organization_id,
                VirtualPatchDeployment.environment == DeploymentEnvironment.PRODUCTION.value,
            )
        ) or 0

        pending_approval_deployments = db.scalar(
            select(func.count(VirtualPatchDeployment.id)).where(
                VirtualPatchDeployment.organization_id == organization_id,
                VirtualPatchDeployment.status == DeploymentStatus.PENDING_APPROVAL.value,
            )
        ) or 0

        total_blocks = db.scalar(
            select(func.count(WafEnforcementLog.id)).where(
                WafEnforcementLog.organization_id == organization_id,
                WafEnforcementLog.decision == "BLOCKED",
            )
        ) or 0

        false_positives = db.scalar(
            select(func.count(WafEnforcementLog.id)).where(
                WafEnforcementLog.organization_id == organization_id,
                WafEnforcementLog.is_false_positive_reported == True,
            )
        ) or 0

        active_recs = db.scalar(
            select(func.count(VirtualPatchRecommendation.id)).where(
                VirtualPatchRecommendation.organization_id == organization_id,
                VirtualPatchRecommendation.status == "PROPOSED",
            )
        ) or 0

        # Probe reverse proxy health
        listen_port = 8085
        upstream_url = "http://127.0.0.1:8086"
        latest_deployment = db.scalar(
            select(VirtualPatchDeployment)
            .where(
                VirtualPatchDeployment.organization_id == organization_id,
                VirtualPatchDeployment.status == DeploymentStatus.DEPLOYED.value,
            )
            .order_by(VirtualPatchDeployment.deployed_at.desc().nullslast())
            .limit(1)
        )
        if latest_deployment:
            listen_port = latest_deployment.listen_port
            upstream_url = latest_deployment.upstream_url

        proxy_health = NginxProxyManager.check_proxy_health(listen_port)
        proxy_status = "ACTIVE" if proxy_health.get("is_running") else "STOPPED"

        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "staging_deployments": staging_deployments,
            "production_deployments": production_deployments,
            "pending_approval_deployments": pending_approval_deployments,
            "total_blocks_recorded": total_blocks,
            "false_positives_reported": false_positives,
            "active_recommendations_count": active_recs,
            "proxy_status": proxy_status,
            "proxy_listen_port": listen_port,
            "upstream_url": upstream_url,
        }

    # =========================================================================
    # RECOMMENDATIONS LIFECYCLE (AI/Deterministic synthesis)
    # =========================================================================

    @classmethod
    def get_recommendations(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        status: Optional[str] = None,
    ) -> List[VirtualPatchRecommendation]:
        """
        Retrieves patch recommendations for the tenant.
        """
        query = select(VirtualPatchRecommendation).where(
            VirtualPatchRecommendation.organization_id == organization_id
        )
        if status:
            query = query.where(VirtualPatchRecommendation.status == status)

        query = query.order_by(VirtualPatchRecommendation.confidence.desc(), VirtualPatchRecommendation.created_at.desc())
        return list(db.scalars(query).all())

    @classmethod
    def generate_recommendations_for_organization(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[VirtualPatchRecommendation]:
        """
        Analyzes unpatched tenant vulnerabilities and attack paths to propose explainable virtual patches.
        """
        # Find vulnerabilities that don't have recommendations yet
        vulns = db.scalars(
            select(VulnerabilityRecord)
            .where(
                VulnerabilityRecord.organization_id == organization_id,
                VulnerabilityRecord.status.in_(["CONFIRMED", "DETECTED", "OPEN", "ACTIVE"]),
            )
        ).all()

        existing_vuln_ids = set(
            db.scalars(
                select(VirtualPatchRecommendation.vulnerability_id).where(
                    VirtualPatchRecommendation.organization_id == organization_id
                )
            ).all()
        )

        generated = []
        for v in vulns:
            if v.id in existing_vuln_ids:
                continue

            asset = db.get(ManagedAsset, v.asset_id)
            if not asset:
                continue

            rec = IntelligentVirtualPatchGenerator.synthesize_recommendation_for_vulnerability(v, asset)
            if rec:
                db.add(rec)
                generated.append(rec)

        db.commit()
        for r in generated:
            db.refresh(r)
        return generated

    @classmethod
    def accept_recommendation(
        cls,
        db: Session,
        recommendation_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: Optional[uuid.UUID] = None,
    ) -> VirtualPatchRule:
        """
        Accepts a proposed recommendation and materializes it into an active rule with version 1.
        """
        rec = db.scalar(
            select(VirtualPatchRecommendation).where(
                VirtualPatchRecommendation.id == recommendation_id,
                VirtualPatchRecommendation.organization_id == organization_id,
            )
        )
        if not rec:
            raise ValueError("Virtual patch recommendation not found.")

        rule = IntelligentVirtualPatchGenerator.create_rule_from_recommendation(db, rec, user_id=user_id)
        db.commit()
        db.refresh(rule)
        return rule

    @classmethod
    def reject_recommendation(
        cls,
        db: Session,
        recommendation_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> VirtualPatchRecommendation:
        """
        Rejects a proposed recommendation.
        """
        rec = db.scalar(
            select(VirtualPatchRecommendation).where(
                VirtualPatchRecommendation.id == recommendation_id,
                VirtualPatchRecommendation.organization_id == organization_id,
            )
        )
        if not rec:
            raise ValueError("Virtual patch recommendation not found.")

        rec.status = "REJECTED"
        db.commit()
        db.refresh(rec)
        return rec

    # =========================================================================
    # VIRTUAL PATCH RULES & VERSIONING
    # =========================================================================

    @classmethod
    def get_rules(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        is_active: Optional[bool] = None,
        attack_type: Optional[str] = None,
    ) -> List[VirtualPatchRule]:
        """
        Lists virtual patch rules for a tenant.
        """
        query = select(VirtualPatchRule).where(VirtualPatchRule.organization_id == organization_id)
        if is_active is not None:
            query = query.where(VirtualPatchRule.is_active == is_active)
        if attack_type:
            query = query.where(VirtualPatchRule.attack_type == attack_type)

        query = query.order_by(VirtualPatchRule.priority.asc(), VirtualPatchRule.created_at.desc())
        return list(db.scalars(query).all())

    @classmethod
    def get_rule(
        cls,
        db: Session,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> Optional[VirtualPatchRule]:
        """
        Retrieves a single rule scoped by tenant.
        """
        return db.scalar(
            select(VirtualPatchRule).where(
                VirtualPatchRule.id == rule_id,
                VirtualPatchRule.organization_id == organization_id,
            )
        )

    @classmethod
    def create_rule(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        data: VirtualPatchRuleCreate,
        user_id: Optional[uuid.UUID] = None,
    ) -> VirtualPatchRule:
        """
        Creates a custom virtual patch rule and registers version 1.
        """
        conditions_json = json.dumps([c.model_dump() for c in data.match_conditions])
        methods_json = json.dumps(data.http_methods)

        rule = VirtualPatchRule(
            id=uuid.uuid4(),
            organization_id=organization_id,
            asset_id=data.asset_id,
            vulnerability_id=data.vulnerability_id,
            cve_id=data.cve_id,
            cwe_id=data.cwe_id,
            rule_name=data.rule_name,
            attack_type=data.attack_type,
            description=data.description,
            severity=data.severity,
            priority=data.priority,
            action=data.action,
            target_uri_pattern=data.target_uri_pattern or "/.*",
            http_methods=methods_json,
            match_conditions=conditions_json,
            status=PatchStatus.DRAFT.value,
            is_active=True,
            is_system_rule=False,
            version=1,
            expires_at=data.expires_at,
        )

        # Validate syntax
        is_valid, err = WafConfigCompiler.validate_rule_syntax(rule)
        if not is_valid:
            raise ValueError(f"Rule regular expression syntax error: {err}")

        # Compile snippet
        snippet_lines = WafConfigCompiler.compile_rule_to_nginx_directives(rule)
        rule.config_snippet = "\n".join(snippet_lines)

        db.add(rule)
        db.flush()

        # Add version 1
        ver = VirtualPatchVersion(
            id=uuid.uuid4(),
            rule_id=rule.id,
            version_number=1,
            rule_name=rule.rule_name,
            action=rule.action,
            target_uri_pattern=rule.target_uri_pattern,
            match_conditions=rule.match_conditions,
            config_snippet=rule.config_snippet,
            change_summary="Rule created",
            created_by_user_id=user_id,
        )
        db.add(ver)
        db.commit()
        db.refresh(rule)
        return rule

    @classmethod
    def update_rule(
        cls,
        db: Session,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID,
        data: VirtualPatchRuleUpdate,
        user_id: Optional[uuid.UUID] = None,
    ) -> VirtualPatchRule:
        """
        Updates an existing rule and appends an immutable version history record if matching logic changes.
        """
        rule = cls.get_rule(db, rule_id, organization_id)
        if not rule:
            raise ValueError("Virtual patch rule not found.")

        logic_changed = False
        summary = data.change_summary or "Rule configuration updated"

        if data.rule_name is not None and data.rule_name != rule.rule_name:
            rule.rule_name = data.rule_name
            logic_changed = True

        if data.description is not None:
            rule.description = data.description

        if data.severity is not None:
            rule.severity = data.severity

        if data.priority is not None:
            rule.priority = data.priority

        if data.action is not None and data.action != rule.action:
            rule.action = data.action
            logic_changed = True

        if data.target_uri_pattern is not None and data.target_uri_pattern != rule.target_uri_pattern:
            rule.target_uri_pattern = data.target_uri_pattern
            logic_changed = True

        if data.http_methods is not None:
            rule.http_methods = json.dumps(data.http_methods)
            logic_changed = True

        if data.match_conditions is not None:
            rule.match_conditions = json.dumps([c.model_dump() for c in data.match_conditions])
            logic_changed = True

        if data.is_active is not None:
            rule.is_active = data.is_active

        if data.expires_at is not None:
            rule.expires_at = data.expires_at

        # Validate syntax
        is_valid, err = WafConfigCompiler.validate_rule_syntax(rule)
        if not is_valid:
            raise ValueError(f"Rule regular expression syntax error: {err}")

        # Recompile snippet
        snippet_lines = WafConfigCompiler.compile_rule_to_nginx_directives(rule)
        rule.config_snippet = "\n".join(snippet_lines)

        if logic_changed:
            rule.version += 1
            ver = VirtualPatchVersion(
                id=uuid.uuid4(),
                rule_id=rule.id,
                version_number=rule.version,
                rule_name=rule.rule_name,
                action=rule.action,
                target_uri_pattern=rule.target_uri_pattern,
                match_conditions=rule.match_conditions,
                config_snippet=rule.config_snippet,
                change_summary=summary,
                created_by_user_id=user_id,
            )
            db.add(ver)

        db.commit()
        db.refresh(rule)
        return rule

    @classmethod
    def delete_rule(
        cls,
        db: Session,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> bool:
        """
        Deletes a virtual patch rule and its versions.
        """
        rule = cls.get_rule(db, rule_id, organization_id)
        if not rule:
            return False

        db.delete(rule)
        db.commit()
        return True

    @classmethod
    def get_rule_versions(
        cls,
        db: Session,
        rule_id: uuid.UUID,
        organization_id: uuid.UUID,
    ) -> List[VirtualPatchVersion]:
        """
        Lists version history for a given rule.
        """
        rule = cls.get_rule(db, rule_id, organization_id)
        if not rule:
            raise ValueError("Virtual patch rule not found.")

        return list(
            db.scalars(
                select(VirtualPatchVersion)
                .where(VirtualPatchVersion.rule_id == rule.id)
                .order_by(VirtualPatchVersion.version_number.desc())
            ).all()
        )

    @classmethod
    def seed_baseline_rules(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[VirtualPatchRule]:
        """
        Installs standard SMB baseline virtual patch rules if none exist.
        """
        rules = IntelligentVirtualPatchGenerator.create_default_baseline_rules(db, organization_id)
        db.commit()
        return rules

    # =========================================================================
    # DEPLOYMENT LIFECYCLE & HUMAN-IN-THE-LOOP APPROVAL GATE
    # =========================================================================

    @classmethod
    def stage_deployment(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        listen_port: int = 8085,
        upstream_url: str = "http://127.0.0.1:8086",
        user_id: Optional[uuid.UUID] = None,
    ) -> VirtualPatchDeployment:
        """
        Compiles active virtual patch rules, writes and tests Nginx configuration syntax,
        and saves a STAGING deployment record awaiting human approval for production.
        """
        org = db.get(Organization, organization_id)
        org_name = org.name if org else "Default Org"

        # Gather active rules
        rules = list(
            db.scalars(
                select(VirtualPatchRule)
                .where(
                    VirtualPatchRule.organization_id == organization_id,
                    VirtualPatchRule.is_active == True,
                )
                .order_by(VirtualPatchRule.priority.asc())
            ).all()
        )

        config_content, config_hash = WafConfigCompiler.generate_full_nginx_config(
            rules=rules,
            organization_name=org_name,
            listen_port=listen_port,
            upstream_url=upstream_url,
        )

        deployment_id = uuid.uuid4()
        conf_path = NginxProxyManager.write_runtime_config(str(deployment_id), config_content)

        # Validate syntax with Nginx
        is_valid, validation_log = NginxProxyManager.test_configuration(conf_path)
        status = DeploymentStatus.PENDING_APPROVAL.value if is_valid else DeploymentStatus.FAILED.value

        deployment = VirtualPatchDeployment(
            id=deployment_id,
            organization_id=organization_id,
            environment=DeploymentEnvironment.STAGING.value,
            status=status,
            deployed_rules_count=len(rules),
            config_hash=config_hash,
            nginx_config_path=conf_path,
            listen_port=listen_port,
            upstream_url=upstream_url,
            deployment_log=validation_log,
        )
        db.add(deployment)
        db.commit()
        db.refresh(deployment)
        return deployment

    @classmethod
    def approve_deployment(
        cls,
        db: Session,
        deployment_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> VirtualPatchDeployment:
        """
        Strict human authorization gate: an OrgAdmin explicitly signs off on a staged deployment.
        """
        dep = db.scalar(
            select(VirtualPatchDeployment).where(
                VirtualPatchDeployment.id == deployment_id,
                VirtualPatchDeployment.organization_id == organization_id,
            )
        )
        if not dep:
            raise ValueError("Deployment record not found.")

        if dep.status == DeploymentStatus.FAILED.value:
            raise ValueError("Cannot approve a deployment that failed configuration syntax verification.")

        dep.status = DeploymentStatus.APPROVED.value
        dep.approved_by_user_id = user_id
        dep.approved_at = utc_now()
        dep.deployment_log = (dep.deployment_log or "") + f"\nApproved by user {user_id} at {dep.approved_at.isoformat()}."

        db.commit()
        db.refresh(dep)
        return dep

    @classmethod
    def deploy_to_production(
        cls,
        db: Session,
        deployment_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> VirtualPatchDeployment:
        """
        Enforces approved virtual patches onto the live Nginx reverse proxy.
        MANDATORY: Refuses execution unless the deployment was explicitly APPROVED by an OrgAdmin.
        """
        dep = db.scalar(
            select(VirtualPatchDeployment).where(
                VirtualPatchDeployment.id == deployment_id,
                VirtualPatchDeployment.organization_id == organization_id,
            )
        )
        if not dep:
            raise ValueError("Deployment record not found.")

        # HUMAN-IN-THE-LOOP AUTHORIZATION ENFORCEMENT
        if dep.status != DeploymentStatus.APPROVED.value:
            raise ValueError(
                f"Unauthorized production deployment attempt. Status is '{dep.status}'; "
                "Production deployment strictly requires prior human approval (APPROVED status)."
            )

        if not dep.nginx_config_path or not Path(dep.nginx_config_path).is_file():
            raise ValueError(f"Configuration file {dep.nginx_config_path} does not exist.")

        config_content = Path(dep.nginx_config_path).read_text(encoding="utf-8")

        # Activate on Nginx
        success, log_msg = NginxProxyManager.apply_deployment(
            deployment_id=str(dep.id),
            config_content=config_content,
            listen_port=dep.listen_port,
            upstream_url=dep.upstream_url,
        )

        dep.deployment_log = (dep.deployment_log or "") + f"\nProduction Activation: {log_msg}"
        if success:
            dep.status = DeploymentStatus.DEPLOYED.value
            dep.environment = DeploymentEnvironment.PRODUCTION.value
            dep.deployed_at = utc_now()

            # Mark associated rules as PRODUCTION
            db.execute(
                update(VirtualPatchRule)
                .where(
                    VirtualPatchRule.organization_id == organization_id,
                    VirtualPatchRule.is_active == True,
                )
                .values(status=PatchStatus.PRODUCTION.value)
            )
        else:
            dep.status = DeploymentStatus.FAILED.value

        db.commit()
        db.refresh(dep)
        return dep

    @classmethod
    def rollback_deployment(
        cls,
        db: Session,
        deployment_id: uuid.UUID,
        organization_id: uuid.UUID,
        user_id: uuid.UUID,
    ) -> VirtualPatchDeployment:
        """
        Rolls back the current deployment to the previous deployed version or terminates the proxy.
        """
        dep = db.scalar(
            select(VirtualPatchDeployment).where(
                VirtualPatchDeployment.id == deployment_id,
                VirtualPatchDeployment.organization_id == organization_id,
            )
        )
        if not dep:
            raise ValueError("Deployment record not found.")

        # Locate previous stable deployment
        prev_dep = db.scalar(
            select(VirtualPatchDeployment)
            .where(
                VirtualPatchDeployment.organization_id == organization_id,
                VirtualPatchDeployment.id != deployment_id,
                VirtualPatchDeployment.status == DeploymentStatus.DEPLOYED.value,
            )
            .order_by(VirtualPatchDeployment.deployed_at.desc())
            .limit(1)
        )

        if prev_dep and prev_dep.nginx_config_path and Path(prev_dep.nginx_config_path).is_file():
            prev_content = Path(prev_dep.nginx_config_path).read_text(encoding="utf-8")
            success, log_msg = NginxProxyManager.apply_deployment(
                deployment_id=str(prev_dep.id),
                config_content=prev_content,
                listen_port=prev_dep.listen_port,
                upstream_url=prev_dep.upstream_url,
            )
            dep.rollback_target_deployment_id = prev_dep.id
            dep.deployment_log = (dep.deployment_log or "") + f"\nRolled back to deployment {prev_dep.id}: {log_msg}"
        else:
            # No prior configuration to revert to; stop the proxy gracefully
            NginxProxyManager.stop_proxy()
            dep.deployment_log = (dep.deployment_log or "") + "\nNo prior deployment available. Stopped reverse proxy."

        dep.status = DeploymentStatus.ROLLED_BACK.value
        db.commit()
        db.refresh(dep)
        return dep

    @classmethod
    def get_deployments(
        cls,
        db: Session,
        organization_id: uuid.UUID,
    ) -> List[VirtualPatchDeployment]:
        """
        Lists deployment history.
        """
        return list(
            db.scalars(
                select(VirtualPatchDeployment)
                .where(VirtualPatchDeployment.organization_id == organization_id)
                .order_by(VirtualPatchDeployment.created_at.desc())
            ).all()
        )

    # =========================================================================
    # REVERSE PROXY WAF AUDIT TELEMETRY & FALSE-POSITIVE FEEDBACK
    # =========================================================================

    @classmethod
    def get_enforcement_logs(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        limit: int = 100,
        decision: Optional[str] = None,
    ) -> List[WafEnforcementLog]:
        """
        Lists real-time WAF request evaluation logs.
        """
        query = select(WafEnforcementLog).where(WafEnforcementLog.organization_id == organization_id)
        if decision:
            query = query.where(WafEnforcementLog.decision == decision)

        query = query.order_by(WafEnforcementLog.created_at.desc()).limit(limit)
        return list(db.scalars(query).all())

    @classmethod
    def log_enforcement_event(
        cls,
        db: Session,
        organization_id: uuid.UUID,
        client_ip: str,
        http_method: str,
        uri: str,
        decision: str,
        block_reason: str,
        rule_id: Optional[uuid.UUID] = None,
        query_string: Optional[str] = None,
        headers_snippet: Optional[str] = None,
        body_snippet: Optional[str] = None,
        matched_pattern: Optional[str] = None,
        response_status_code: int = 403,
    ) -> WafEnforcementLog:
        """
        Records an empirical request evaluation by the reverse proxy WAF.
        """
        log_entry = WafEnforcementLog(
            id=uuid.uuid4(),
            organization_id=organization_id,
            rule_id=rule_id,
            client_ip=client_ip,
            http_method=http_method,
            uri=uri,
            query_string=query_string,
            headers_snippet=headers_snippet,
            body_snippet=body_snippet,
            decision=decision,
            matched_pattern=matched_pattern,
            block_reason=block_reason,
            response_status_code=response_status_code,
            is_false_positive_reported=False,
        )
        db.add(log_entry)

        if rule_id and decision == "BLOCKED":
            rule = db.get(VirtualPatchRule, rule_id)
            if rule:
                rule.enforcement_count += 1

        db.commit()
        db.refresh(log_entry)
        return log_entry

    @classmethod
    def report_false_positive(
        cls,
        db: Session,
        log_id: uuid.UUID,
        organization_id: uuid.UUID,
        notes: str,
    ) -> WafEnforcementLog:
        """
        Allows security analysts and SMB admins to flag false positives and fine-tune rules.
        """
        log_entry = db.scalar(
            select(WafEnforcementLog).where(
                WafEnforcementLog.id == log_id,
                WafEnforcementLog.organization_id == organization_id,
            )
        )
        if not log_entry:
            raise ValueError("Enforcement log not found.")

        log_entry.is_false_positive_reported = True
        log_entry.false_positive_notes = notes

        if log_entry.rule_id:
            rule = db.get(VirtualPatchRule, log_entry.rule_id)
            if rule:
                rule.false_positive_count += 1

        db.commit()
        db.refresh(log_entry)
        return log_entry
