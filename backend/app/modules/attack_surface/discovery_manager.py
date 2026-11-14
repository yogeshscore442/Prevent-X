"""
PREVENT-X Discovery Manager
Orchestrates passive intelligence collection stages, handles network resilience, and updates job state.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Optional, List, Dict, Any
from uuid import UUID
from sqlalchemy.orm import Session

from backend.app.models.attack_surface import (
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveredDomain,
    DNSRecord,
    CertificateEvidence,
    RDAPRecord,
    ExposureFinding,
)
from backend.app.models.asset import ManagedAsset
from backend.app.modules.attack_surface.adapters.certificate_transparency import CertificateTransparencyAdapter
from backend.app.modules.attack_surface.adapters.dns_intelligence import DNSIntelligenceAdapter
from backend.app.modules.attack_surface.adapters.rdap import RDAPAdapter
from backend.app.modules.attack_surface.risk_engine import DeterministicRiskEngine
from backend.app.modules.attack_surface.evidence_manager import EvidenceManager
from backend.app.modules.attack_surface.scope_validator import ScopeValidator, WorkerAuthorizationError

logger = logging.getLogger("preventx.attack_surface.manager")


class DiscoveryManager:
    """Manages the full discovery execution lifecycle and state machine."""

    def __init__(
        self,
        ct_adapter: Optional[CertificateTransparencyAdapter] = None,
        dns_adapter: Optional[DNSIntelligenceAdapter] = None,
        rdap_adapter: Optional[RDAPAdapter] = None,
        risk_engine: Optional[DeterministicRiskEngine] = None,
    ):
        self.ct_adapter = ct_adapter or CertificateTransparencyAdapter()
        self.dns_adapter = dns_adapter or DNSIntelligenceAdapter()
        self.rdap_adapter = rdap_adapter or RDAPAdapter()
        self.risk_engine = risk_engine or DeterministicRiskEngine()

    def run_discovery(self, db: Session, job_id: UUID) -> DiscoveryJob:
        """
        Executes end-to-end passive discovery job.
        """
        job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
        if not job:
            raise ValueError(f"Discovery job {job_id} does not exist.")

        # Check if already cancelled
        if job.status == DiscoveryJobStatus.CANCELLED:
            logger.info(f"Discovery job {job_id} was cancelled before starting.")
            return job

        # Re-verify complete authorization boundaries prior to worker execution
        try:
            ScopeValidator.validate_worker_execution_authorization(db, job)
        except WorkerAuthorizationError as auth_err:
            logger.error(f"Worker authorization failed for job {job_id}: {auth_err.detail}")
            now = datetime.now(timezone.utc)
            job.status = DiscoveryJobStatus.FAILED
            job.error_message = f"Worker authorization rejected: {auth_err.detail}"
            job.completed_at = now
            db.commit()
            raise auth_err

        now = datetime.now(timezone.utc)
        job.status = DiscoveryJobStatus.RUNNING
        job.started_at = now
        job.progress_percent = 5
        job.current_stage = "VALIDATION"
        db.commit()

        stage_errors: Dict[str, str] = {}
        all_discovered_domains: List[str] = [job.target_domain]
        parsed_certificates: List[Dict[str, Any]] = []
        dns_summary: Dict[str, Any] = {}
        rdap_summary: Optional[Dict[str, Any]] = None

        try:
            # Stage 1: Validation (10%)
            self._check_cancellation(db, job_id)
            job.progress_percent = 10
            job.current_stage = "CERTIFICATE_TRANSPARENCY"
            db.commit()

            # Stage 2: Certificate Transparency (30%)
            if getattr(job, "discovery_policy", "PUBLIC_PASSIVE") == "PUBLIC_PASSIVE":
                try:
                    raw_certs = self.ct_adapter.fetch_certificates(job.target_domain)
                    parsed_certs, discovered_set = self.ct_adapter.parse_certificates_and_domains(
                        job.target_domain, raw_certs
                    )
                    parsed_certificates = parsed_certs
                    all_discovered_domains = sorted(list(discovered_set))
                except Exception as e:
                    logger.warning(f"Certificate Transparency stage warning: {e}")
                    stage_errors["CERTIFICATE_TRANSPARENCY"] = str(e)
            else:
                logger.info(f"Skipping public CT logs for AUTHORIZED_INTERNAL discovery job {job_id}")

            self._check_cancellation(db, job_id)
            job.progress_percent = 40
            job.current_stage = "DNS_ENUMERATION"
            db.commit()

            # Stage 3: DNS Enumeration (60%)
            dns_records_to_insert: List[DNSRecord] = []
            try:
                # Query target domain
                target_dns = self.dns_adapter.resolve_domain(job.target_domain)
                dns_summary = target_dns

                # Query top discovered subdomains (limit up to 15 to preserve responsiveness)
                subdomains_to_probe = [d for d in all_discovered_domains if d != job.target_domain][:15]
                for sub in subdomains_to_probe:
                    sub_dns = self.dns_adapter.resolve_domain(sub)
                    # Merge discovered public/internal IPs and CNAMEs
                    dns_summary["public_ips"] = sorted(list(set(dns_summary.get("public_ips", []) + sub_dns.get("public_ips", []))))
                    dns_summary["internal_ips_detected"] = sorted(list(set(dns_summary.get("internal_ips_detected", []) + sub_dns.get("internal_ips_detected", []))))
                    dns_summary["dangling_cname_candidates"] = sorted(list(set(dns_summary.get("dangling_cname_candidates", []) + sub_dns.get("dangling_cname_candidates", []))))
            except Exception as e:
                logger.warning(f"DNS Enumeration stage warning: {e}")
                stage_errors["DNS_ENUMERATION"] = str(e)

            self._check_cancellation(db, job_id)
            job.progress_percent = 70
            job.current_stage = "RDAP_ANALYSIS"
            db.commit()

            # Stage 4: RDAP Analysis (80%)
            if getattr(job, "discovery_policy", "PUBLIC_PASSIVE") == "PUBLIC_PASSIVE":
                try:
                    rdap_summary = self.rdap_adapter.fetch_domain_profile(job.target_domain)
                except Exception as e:
                    logger.warning(f"RDAP Analysis stage warning: {e}")
                    stage_errors["RDAP_ANALYSIS"] = str(e)
            else:
                logger.info(f"Skipping public RDAP for AUTHORIZED_INTERNAL discovery job {job_id}")

            self._check_cancellation(db, job_id)
            job.progress_percent = 85
            job.current_stage = "RISK_EVALUATION"
            db.commit()

            # Stage 5: Risk Evaluation & Findings Generation (95%)
            risk_calc = self.risk_engine.calculate_risk(
                domain_name=job.target_domain,
                subdomains=all_discovered_domains,
                dns_data=dns_summary,
                certificates=parsed_certificates,
                rdap_data=rdap_summary,
            )

            # Query known assets in organization to identify uncataloged subdomains
            known_assets = db.query(ManagedAsset.target).filter(
                ManagedAsset.organization_id == job.organization_id
            ).all()
            known_targets = [a[0].lower() for a in known_assets]

            findings = EvidenceManager.generate_findings_for_job(
                organization_id=job.organization_id,
                asset_id=job.asset_id,
                job_id=job.id,
                target_domain=job.target_domain,
                discovered_domains=all_discovered_domains,
                dns_data=dns_summary,
                certificates=parsed_certificates,
                rdap_data=rdap_summary,
                known_asset_targets=known_targets,
            )

            # Persist All Entities into Database
            # 1. Save Discovered Domains
            domain_db_records: Dict[str, DiscoveredDomain] = {}
            for dom_name in all_discovered_domains:
                existing = db.query(DiscoveredDomain).filter(
                    DiscoveredDomain.organization_id == job.organization_id,
                    DiscoveredDomain.domain_name == dom_name,
                ).first()
                if not existing:
                    dom_obj = DiscoveredDomain(
                        organization_id=job.organization_id,
                        asset_id=job.asset_id,
                        job_id=job.id,
                        domain_name=dom_name,
                        parent_domain=job.target_domain if dom_name != job.target_domain else None,
                        is_subdomain=(dom_name != job.target_domain),
                        discovery_source="CERTIFICATE_TRANSPARENCY" if dom_name != job.target_domain else "PRIMARY_ASSET",
                        confidence_score=1.0,
                        first_observed_at=now,
                        last_observed_at=now,
                    )
                    db.add(dom_obj)
                    db.flush()
                    domain_db_records[dom_name] = dom_obj
                else:
                    existing.last_observed_at = now
                    domain_db_records[dom_name] = existing

            # 2. Save DNS Records
            primary_domain_obj = domain_db_records.get(job.target_domain)
            if primary_domain_obj:
                for rec in dns_summary.get("records", []):
                    dns_entity = DNSRecord(
                        organization_id=job.organization_id,
                        domain_id=primary_domain_obj.id,
                        domain_name=job.target_domain,
                        record_type=rec["record_type"],
                        record_value=rec["record_value"],
                        ttl=rec.get("ttl"),
                        source=rec.get("source", "DNS_RESOLVER"),
                        resolution_status=rec.get("resolution_status", "RESOLVED"),
                        collected_at=now,
                    )
                    db.add(dns_entity)

            # 3. Save Certificate Evidence
            if primary_domain_obj:
                for cert in parsed_certificates:
                    cert_entity = CertificateEvidence(
                        organization_id=job.organization_id,
                        domain_id=primary_domain_obj.id,
                        issuer_name=cert.get("issuer_name"),
                        common_name=cert.get("common_name"),
                        subject_alt_names=cert.get("subject_alt_names"),
                        not_before=cert.get("not_before"),
                        not_after=cert.get("not_after"),
                        is_expired=cert.get("is_expired", False),
                        is_wildcard=cert.get("is_wildcard", False),
                        serial_number=cert.get("serial_number"),
                        logged_at=cert.get("logged_at"),
                        source=cert.get("source", "CRT_SH"),
                        raw_evidence=cert.get("raw_evidence"),
                    )
                    db.add(cert_entity)

            # 4. Save RDAP Record
            if rdap_summary and primary_domain_obj:
                existing_rdap = db.query(RDAPRecord).filter(RDAPRecord.domain_id == primary_domain_obj.id).first()
                if not existing_rdap:
                    rdap_entity = RDAPRecord(
                        organization_id=job.organization_id,
                        domain_id=primary_domain_obj.id,
                        handle=rdap_summary.get("handle"),
                        registrar_name=rdap_summary.get("registrar_name"),
                        whois_server=rdap_summary.get("whois_server"),
                        registration_date=rdap_summary.get("registration_date"),
                        expiration_date=rdap_summary.get("expiration_date"),
                        last_updated_date=rdap_summary.get("last_updated_date"),
                        nameservers=rdap_summary.get("nameservers"),
                        status_codes=rdap_summary.get("status_codes"),
                        asn=rdap_summary.get("asn"),
                        raw_data=rdap_summary.get("raw_data"),
                    )
                    db.add(rdap_entity)
                else:
                    existing_rdap.registrar_name = rdap_summary.get("registrar_name")
                    existing_rdap.expiration_date = rdap_summary.get("expiration_date")
                    existing_rdap.nameservers = rdap_summary.get("nameservers")

            # 5. Save Findings
            for f in findings:
                db.add(f)

            # Update Job Final State
            job.progress_percent = 100
            job.completed_at = datetime.now(timezone.utc)
            job.domains_discovered_count = len(all_discovered_domains)
            job.findings_count = len(findings)
            job.initial_exposure_score = risk_calc["total_score"]
            job.risk_score_details = json.dumps(risk_calc)

            if stage_errors:
                job.status = DiscoveryJobStatus.PARTIALLY_COMPLETED
                job.stage_errors = json.dumps(stage_errors)
                job.current_stage = "COMPLETED_WITH_WARNINGS"
            else:
                job.status = DiscoveryJobStatus.COMPLETED
                job.current_stage = "COMPLETED"

            db.commit()
            db.refresh(job)
            return job

        except Exception as fatal_e:
            db.rollback()
            logger.error(f"Fatal error during discovery execution for job {job_id}: {fatal_e}", exc_info=True)
            # Re-fetch job to update failure status
            job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
            if job and job.status != DiscoveryJobStatus.CANCELLED:
                job.status = DiscoveryJobStatus.FAILED
                job.error_message = str(fatal_e)
                job.completed_at = datetime.now(timezone.utc)
                job.current_stage = "FAILED"
                db.commit()
            raise fatal_e

    @staticmethod
    def _check_cancellation(db: Session, job_id: UUID) -> None:
        """Checks if the job was flagged for cancellation by a user request."""
        status_val = db.query(DiscoveryJob.status).filter(DiscoveryJob.id == job_id).scalar()
        if status_val == DiscoveryJobStatus.CANCELLED:
            raise RuntimeError(f"Discovery job {job_id} was cancelled by user.")

