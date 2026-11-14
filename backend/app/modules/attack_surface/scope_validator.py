"""
PREVENT-X Attack Surface Scope Validator
Enforces multi-tenant boundaries, SSRF prevention, asset scope verification,
and separate PUBLIC_PASSIVE vs. AUTHORIZED_INTERNAL discovery policies.
"""

from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Optional, Tuple, List, Dict, Any
from urllib.parse import urlparse
from uuid import UUID
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from backend.app.models.asset import ManagedAsset
from backend.app.models.attack_surface import DiscoveryPolicy
from backend.app.modules.attack_surface.ssrf_defense import SSRFDefense, SSRFValidationError

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class ScopeValidationError(HTTPException):
    """Specific HTTP exception for scope validation failures."""
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class WorkerAuthorizationError(Exception):
    """Specific exception raised when Celery worker authorization revalidation fails."""
    def __init__(self, detail: str, code: str = "WORKER_AUTH_REJECTED"):
        self.detail = detail
        self.code = code
        super().__init__(detail)


class ScopeValidator:
    """Validates authorization, boundaries, and scope constraints for attack surface discovery."""

    @staticmethod
    def normalize_target(raw_target: str) -> str:
        """
        Cleans and extracts pure FQDN, IP, or network target string.
        """
        if not raw_target or not isinstance(raw_target, str):
            raise ScopeValidationError("Target cannot be empty.")

        cleaned = raw_target.strip().lower()

        # Handle URI schemes (http://, https://, etc.)
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.netloc or parsed.path
        elif "/" in cleaned and not cleaned.endswith(tuple(f"/{i}" for i in range(1, 129))):
            cleaned = cleaned.split("/")[0]

        # Strip standard port suffixes if present (e.g. example.com:443 or 10.0.0.1:8080)
        if ":" in cleaned and not cleaned.startswith("[") and cleaned.count(":") == 1:
            cleaned = cleaned.split(":")[0]

        cleaned = cleaned.rstrip(".")

        if not cleaned:
            raise ScopeValidationError("Extracted target is empty after normalization.")

        if len(cleaned) > 255:
            raise ScopeValidationError("Target exceeds maximum length of 255 characters.")

        return cleaned

    # Alias for backward compatibility
    normalize_target_domain = normalize_target

    @classmethod
    def extract_apex_domain(cls, domain: str) -> str:
        """
        Extracts base registered apex domain (e.g. sub.example.co.uk -> example.co.uk, portal.example.com -> example.com).
        """
        parts = domain.split(".")
        if len(parts) <= 2:
            return domain

        # Multi-part ccTLDs common in SMB markets
        multipart_cctlds = {"co.in", "com.in", "org.in", "gen.in", "net.in", "co.uk", "org.uk", "com.au", "net.au"}
        last_two = f"{parts[-2]}.{parts[-1]}"

        if last_two in multipart_cctlds:
            if len(parts) >= 3:
                return ".".join(parts[-3:])
            return domain

        return ".".join(parts[-2:])

    @classmethod
    def validate_and_authorize_job(
        cls,
        db: Session,
        organization_id: UUID,
        asset_id: UUID,
        target_domain: Optional[str],
        authorization_confirmed: bool,
        discovery_policy: str = DiscoveryPolicy.PUBLIC_PASSIVE,
        user_permissions: Optional[List[str]] = None,
        user_has_internal_permission: Optional[bool] = None,
    ) -> Tuple[ManagedAsset, str, str, Dict[str, Any]]:
        """
        Performs the complete authorization and scope boundary check.
        Enforces separate rules for PUBLIC_PASSIVE vs. AUTHORIZED_INTERNAL discovery.
        Returns:
            Tuple[ManagedAsset, str, str, Dict[str, Any]]: (validated_asset, effective_target, effective_policy, validation_evidence)
        """
        # 1. Mandatory authorization confirmation checkbox
        if not authorization_confirmed:
            raise ScopeValidationError(
                "Explicit authorization confirmation is mandatory prior to initiating attack surface discovery.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # 2. Fetch asset with strict tenant organization scoping
        asset = db.query(ManagedAsset).filter(
            ManagedAsset.id == asset_id,
            ManagedAsset.organization_id == organization_id,
        ).first()

        if not asset:
            # Check if asset belongs to another org to prevent cross-tenant enumeration
            cross_org_asset = db.query(ManagedAsset).filter(ManagedAsset.id == asset_id).first()
            if cross_org_asset:
                raise ScopeValidationError(
                    "Cross-tenant access violation: Asset belongs to another organization.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            raise ScopeValidationError(
                "Target asset not found in active organization.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # 3. Verify asset is marked in scope
        if not asset.is_in_scope:
            raise ScopeValidationError(
                f"Asset '{asset.name}' is flagged out-of-scope for security assessments.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        # 4. Normalize asset target
        normalized_asset_target = cls.normalize_target(asset.target)
        effective_policy = discovery_policy or DiscoveryPolicy.PUBLIC_PASSIVE

        # 5. Policy enforcement
        if effective_policy == DiscoveryPolicy.AUTHORIZED_INTERNAL:
            # Verify user has internal discovery authorization
            has_internal = user_has_internal_permission
            if has_internal is None:
                has_internal = bool(
                    user_permissions and (
                        PermissionCode.DISCOVERY_INTERNAL in user_permissions or
                        "discovery:internal" in user_permissions or
                        "*" in user_permissions
                    )
                )
            if not has_internal:
                raise ScopeValidationError(
                    "User lacks the required 'discovery:internal' permission to initiate internal network discovery.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )

            # Ensure asset is explicitly configured as internal
            if asset.asset_type not in ("INTERNAL_SERVER", "PRIVATE_NETWORK", "INTERNAL_NETWORK"):
                # Also accept if asset target is an RFC1918 private IP or CIDR
                if "/" not in normalized_asset_target:
                    ip_check = SSRFDefense.parse_and_normalize_ip(normalized_asset_target)
                    if not (ip_check and ip_check.is_private):
                        raise ScopeValidationError(
                            f"Asset '{asset.name}' is not registered as an internal asset type (asset_type={asset.asset_type}). "
                            "AUTHORIZED_INTERNAL discovery is restricted to explicitly registered internal assets.",
                            status_code=status.HTTP_403_FORBIDDEN,
                        )

            # Build CIDR allowlist from registered asset target
            allowlist_cidrs = []
            if "/" in normalized_asset_target:
                allowlist_cidrs.append(normalized_asset_target)
            else:
                asset_ip_obj = SSRFDefense.parse_and_normalize_ip(normalized_asset_target)
                if asset_ip_obj:
                    allowlist_cidrs.append(f"{asset_ip_obj}/32" if isinstance(asset_ip_obj, ipaddress.IPv4Address) else f"{asset_ip_obj}/128")

            # Evaluate effective target
            candidate = cls.normalize_target(target_domain) if target_domain and target_domain.strip() else normalized_asset_target

            # Validate target against SSRF with allow_private=True and strict allowlist
            candidate_ip = SSRFDefense.parse_and_normalize_ip(candidate)
            if candidate_ip:
                forbidden, reason = SSRFDefense.is_ip_forbidden(
                    candidate_ip, allow_private=True, allowlist_cidrs=allowlist_cidrs
                )
                if forbidden:
                    raise ScopeValidationError(reason, status_code=status.HTTP_403_FORBIDDEN)
            else:
                # If candidate is a hostname, resolve it and ensure all IPs are within internal allowlist
                SSRFDefense.validate_hostname(candidate)
                SSRFDefense.validate_dns_resolution(candidate, allow_private=True, allowlist_cidrs=allowlist_cidrs)

            effective_target = candidate

        else:
            # PUBLIC_PASSIVE Policy:
            # Strictly reject private IPs, loopback, link-local, cloud metadata, and internal TLDs
            candidate = cls.normalize_target(target_domain) if target_domain and target_domain.strip() else normalized_asset_target

            try:
                candidate_ip = SSRFDefense.parse_and_normalize_ip(candidate)
                if candidate_ip:
                    forbidden, reason = SSRFDefense.is_ip_forbidden(candidate_ip, allow_private=False)
                    if forbidden:
                        raise ScopeValidationError(reason, status_code=status.HTTP_403_FORBIDDEN)
                else:
                    SSRFDefense.validate_hostname(candidate)
                    # Check domain regex
                    if not DOMAIN_REGEX.match(candidate):
                        raise ScopeValidationError(f"Target '{candidate}' is not a valid fully qualified domain name (FQDN).")

                    # Enforce scope hierarchy: candidate must match or be a subdomain of the approved asset scope
                    asset_apex = cls.extract_apex_domain(normalized_asset_target)
                    candidate_apex = cls.extract_apex_domain(candidate)

                    if candidate_apex != asset_apex and not candidate.endswith(f".{normalized_asset_target}") and candidate != normalized_asset_target:
                        raise ScopeValidationError(
                            f"Requested discovery domain '{candidate}' is outside the authorized scope of asset '{asset.name}' ({normalized_asset_target}).",
                            status_code=status.HTTP_403_FORBIDDEN,
                        )
            except SSRFValidationError as e:
                raise ScopeValidationError(detail=e.detail, status_code=e.status_code) from e

            effective_target = candidate

        now_utc = datetime.now(timezone.utc)
        candidate_is_ip = bool(SSRFDefense.parse_and_normalize_ip(effective_target))
        validation_evidence = {
            "status": "APPROVED",
            "organization_id": str(organization_id),
            "asset_id": str(asset.id),
            "asset_name": asset.name,
            "asset_type": asset.asset_type,
            "authorized_scope": asset.target,
            "requested_target": target_domain,
            "effective_target": effective_target,
            "discovery_policy": effective_policy,
            "authorization_confirmed": True,
            "validated_at": now_utc.isoformat(),
            "apex_domain": cls.extract_apex_domain(effective_target) if not candidate_is_ip else None,
            "allowlist_cidrs": allowlist_cidrs if effective_policy == DiscoveryPolicy.AUTHORIZED_INTERNAL else [],
        }

        return asset, effective_target, effective_policy, validation_evidence

    @classmethod
    def validate_worker_execution_authorization(
        cls,
        db: Session,
        job: Any,
        max_queue_ttl_seconds: int = 86400,
    ) -> Dict[str, Any]:
        """
        Revalidates authorization boundaries immediately prior to Celery worker job execution:
        1. Explicit authorization confirmation check (job.authorization_confirmed).
        2. Job queue expiration / TTL window check (default 24 hours).
        3. Target asset existence and current is_in_scope status.
        4. Strict organization / cross-tenant boundary verification.
        5. Scope validation result evidence trace verification & anti-tampering.
        6. Initiating user existence, active status, and active organization membership.
        7. Re-evaluation of discovery policy against asset configuration and SSRF constraints.
        """
        from backend.app.models.user import User, OrganizationMembership

        if not getattr(job, "authorization_confirmed", False):
            raise WorkerAuthorizationError("Job lacks mandatory user authorization confirmation.")

        # 1. Job Queue Expiration (24 hour TTL)
        now_utc = datetime.now(timezone.utc)
        created_at = getattr(job, "created_at", None)
        if created_at is not None:
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            age_seconds = (now_utc - created_at).total_seconds()
            if age_seconds > max_queue_ttl_seconds:
                raise WorkerAuthorizationError(
                    f"Job authorization has expired. Queued age ({int(age_seconds)}s) exceeds maximum allowed TTL ({max_queue_ttl_seconds}s)."
                )

        # 2. Asset existence and active in-scope status
        asset_id = getattr(job, "asset_id", None)
        if not asset_id:
            raise WorkerAuthorizationError("Job is not linked to any registered asset ID.")

        asset = db.query(ManagedAsset).filter(ManagedAsset.id == asset_id).first()
        if not asset:
            raise WorkerAuthorizationError(f"Target asset '{asset_id}' does not exist or has been deleted.")

        # 3. Cross-tenant asset ownership validation
        if asset.organization_id != job.organization_id:
            raise WorkerAuthorizationError(
                f"Cross-tenant authorization violation: Asset '{asset.id}' belongs to organization '{asset.organization_id}', "
                f"but execution was requested under organization '{job.organization_id}'."
            )

        if not asset.is_in_scope:
            raise WorkerAuthorizationError(
                f"Authorization revoked: Asset '{asset.name}' is currently flagged out-of-scope."
            )

        # 4. Scope validation result evidence tampering & anti-drift checks
        scope_evidence_str = getattr(job, "scope_validation_result", None)
        if not scope_evidence_str:
            raise WorkerAuthorizationError("Missing mandatory scope validation evidence trace.")

        try:
            scope_evidence = json.loads(scope_evidence_str) if isinstance(scope_evidence_str, str) else scope_evidence_str
        except Exception:
            raise WorkerAuthorizationError("Corrupted or malformed scope validation evidence trace.")

        if scope_evidence.get("status") != "APPROVED":
            raise WorkerAuthorizationError(f"Scope validation evidence has non-approved status: '{scope_evidence.get('status')}'.")

        if scope_evidence.get("organization_id") != str(job.organization_id):
            raise WorkerAuthorizationError("Organization ID mismatch in scope validation evidence.")

        if scope_evidence.get("asset_id") != str(job.asset_id):
            raise WorkerAuthorizationError("Asset ID mismatch in scope validation evidence.")

        # Prevent queued jobs from changing their authorized target
        if scope_evidence.get("effective_target") != job.target_domain:
            raise WorkerAuthorizationError(
                f"Target tampering detected: Queued job target '{job.target_domain}' does not match "
                f"validated scope target '{scope_evidence.get('effective_target')}'."
            )

        # Prevent queued jobs from changing their authorized policy
        if scope_evidence.get("discovery_policy") != job.discovery_policy:
            raise WorkerAuthorizationError(
                f"Policy tampering detected: Queued job policy '{job.discovery_policy}' does not match "
                f"validated scope policy '{scope_evidence.get('discovery_policy')}'."
            )

        # 5. Initiating user and membership verification
        user_id = getattr(job, "initiated_by_user_id", None) or getattr(job, "created_by", None)
        if not user_id:
            raise WorkerAuthorizationError("Job lacks recorded initiating user ID.")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise WorkerAuthorizationError(f"Initiating user '{user_id}' does not exist.")

        if not user.is_active:
            raise WorkerAuthorizationError(f"Initiating user '{user.email}' is deactivated or suspended.")

        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == job.organization_id,
        ).first()
        if not membership:
            raise WorkerAuthorizationError(
                f"Initiating user '{user.email}' is no longer an active member of organization '{job.organization_id}'."
            )

        # 6. Scope hierarchy revalidation against current asset target
        normalized_asset_target = cls.normalize_target(asset.target)
        candidate = cls.normalize_target(job.target_domain)
        effective_policy = job.discovery_policy

        if effective_policy == DiscoveryPolicy.AUTHORIZED_INTERNAL:
            if asset.asset_type not in ("INTERNAL_SERVER", "PRIVATE_NETWORK", "INTERNAL_NETWORK"):
                if "/" not in normalized_asset_target:
                    ip_check = SSRFDefense.parse_and_normalize_ip(normalized_asset_target)
                    if not (ip_check and ip_check.is_private):
                        raise WorkerAuthorizationError(
                            f"Asset '{asset.name}' is no longer registered as an internal asset type (asset_type={asset.asset_type})."
                        )
        else:
            # PUBLIC_PASSIVE: target must be within asset apex and must not be private
            candidate_ip = SSRFDefense.parse_and_normalize_ip(candidate)
            if candidate_ip:
                forbidden, reason = SSRFDefense.is_ip_forbidden(candidate_ip, allow_private=False)
                if forbidden:
                    raise WorkerAuthorizationError(f"Target '{candidate}' violates PUBLIC_PASSIVE boundary: {reason}")
            else:
                asset_apex = cls.extract_apex_domain(normalized_asset_target)
                candidate_apex = cls.extract_apex_domain(candidate)
                if candidate_apex != asset_apex and not candidate.endswith(f".{normalized_asset_target}") and candidate != normalized_asset_target:
                    raise WorkerAuthorizationError(
                        f"Target '{candidate}' is outside the authorized scope of asset '{asset.name}' ({normalized_asset_target})."
                    )

        return {
            "status": "WORKER_AUTH_VERIFIED",
            "verified_at": now_utc.isoformat(),
            "job_id": str(getattr(job, "id", "")),
            "asset_id": str(asset.id),
            "organization_id": str(job.organization_id),
            "target": candidate,
            "policy": effective_policy,
        }

    # Backward compatibility helper for existing callers
    @classmethod
    def check_ssrf_and_forbidden_networks(cls, domain_or_ip: str) -> None:
        try:
            ip_obj = SSRFDefense.parse_and_normalize_ip(domain_or_ip)
            if ip_obj:
                forbidden, reason = SSRFDefense.is_ip_forbidden(ip_obj, allow_private=False)
                if forbidden:
                    raise ScopeValidationError(reason, status_code=status.HTTP_403_FORBIDDEN)
            else:
                SSRFDefense.validate_hostname(domain_or_ip)
                if not DOMAIN_REGEX.match(domain_or_ip):
                    raise ScopeValidationError(f"Target '{domain_or_ip}' is not a valid fully qualified domain name (FQDN).")
        except SSRFValidationError as e:
            raise ScopeValidationError(detail=e.detail, status_code=e.status_code) from e
