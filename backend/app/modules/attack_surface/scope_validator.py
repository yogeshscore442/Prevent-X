"""
PREVENT-X Attack Surface Scope Validator
Enforces mandatory multi-tenant boundaries, SSRF prevention, asset scope verification, and authorization confirmation.
"""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse
from uuid import UUID
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from backend.app.models.asset import ManagedAsset


FORBIDDEN_TLDS = {
    "local", "internal", "localhost", "lan", "home", "corp",
    "test", "example", "invalid", "onion", "arpa"
}

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class ScopeValidationError(HTTPException):
    """Specific HTTP exception for scope validation failures."""
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class ScopeValidator:
    """Validates authorization, boundaries, and scope constraints for attack surface discovery."""

    @staticmethod
    def normalize_target_domain(raw_target: str) -> str:
        """
        Cleans and extracts the pure FQDN/domain from a user target string, URL, or URI.
        """
        if not raw_target or not isinstance(raw_target, str):
            raise ScopeValidationError("Target domain cannot be empty.")

        cleaned = raw_target.strip().lower()

        # Handle URI schemes (http://, https://, etc.)
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            cleaned = parsed.netloc or parsed.path
        elif "/" in cleaned:
            cleaned = cleaned.split("/")[0]

        # Strip standard port suffixes if present (e.g. example.com:443)
        if ":" in cleaned:
            cleaned = cleaned.split(":")[0]

        cleaned = cleaned.rstrip(".")

        if not cleaned:
            raise ScopeValidationError("Extracted target domain is empty after normalization.")

        if len(cleaned) > 255:
            raise ScopeValidationError("Target domain exceeds maximum length of 255 characters.")

        return cleaned

    @classmethod
    def check_ssrf_and_forbidden_networks(cls, domain_or_ip: str) -> None:
        """
        Verifies that the target does not represent an internal, private, loopback, or cloud metadata address.
        """
        # 1. Check if raw value is an IP address
        try:
            ip_obj = ipaddress.ip_address(domain_or_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved:
                raise ScopeValidationError(
                    f"Direct discovery against private, loopback, or reserved IP addresses ({domain_or_ip}) is strictly forbidden by policy.",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            # Prevent scanning internal AWS/GCP/Azure link-local metadata (169.254.169.254)
            if domain_or_ip == "169.254.169.254":
                raise ScopeValidationError(
                    "Cloud metadata address scanning is strictly prohibited.",
                    status_code=status.HTTP_403_FORBIDDEN
                )
        except ValueError:
            # Not an IP address string, continue domain validation
            pass

        # 2. Check forbidden internal TLDs
        parts = domain_or_ip.split(".")
        if len(parts) >= 1:
            tld = parts[-1]
            if tld in FORBIDDEN_TLDS:
                raise ScopeValidationError(
                    f"Domain with non-routable or internal TLD (.{tld}) is excluded from external attack surface discovery.",
                    status_code=status.HTTP_403_FORBIDDEN
                )

        # 3. Check for valid domain format
        if not DOMAIN_REGEX.match(domain_or_ip):
            raise ScopeValidationError(
                f"Target '{domain_or_ip}' is not a valid fully qualified domain name (FQDN)."
            )

    @classmethod
    def extract_apex_domain(cls, domain: str) -> str:
        """
        Extracts base registered apex domain (e.g. sub.example.co.uk -> example.co.uk, portal.example.com -> example.com).
        """
        parts = domain.split(".")
        if len(parts) <= 2:
            return domain

        # Multi-part ccTLDs common in SMB markets (.co.in, .com.au, .co.uk, .org.in, .gov.in, .edu.in)
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
    ) -> Tuple[ManagedAsset, str]:
        """
        Performs the complete authorization and scope boundary check.
        Returns:
            Tuple[ManagedAsset, str]: The validated asset record and normalized target domain.
        Raises:
            HTTPException (403, 404, or 400) if boundary criteria are not met.
        """
        # 1. Mandatory authorization confirmation checkbox
        if not authorization_confirmed:
            raise ScopeValidationError(
                "Explicit authorization confirmation is mandatory prior to initiating attack surface discovery.",
                status_code=status.HTTP_403_FORBIDDEN
            )

        # 2. Fetch asset with strict tenant organization scoping
        asset = db.query(ManagedAsset).filter(
            ManagedAsset.id == asset_id,
            ManagedAsset.organization_id == organization_id,
        ).first()

        if not asset:
            # Check if asset belongs to another org to raise appropriate error
            cross_org_asset = db.query(ManagedAsset).filter(ManagedAsset.id == asset_id).first()
            if cross_org_asset:
                raise ScopeValidationError(
                    "Cross-tenant access violation: Asset belongs to another organization.",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            raise ScopeValidationError(
                "Target asset not found in active organization.",
                status_code=status.HTTP_404_NOT_FOUND
            )

        # 3. Verify asset is marked in scope
        if not asset.is_in_scope:
            raise ScopeValidationError(
                f"Asset '{asset.name}' is flagged out-of-scope for external security assessments.",
                status_code=status.HTTP_403_FORBIDDEN
            )

        # 4. Resolve and normalize target domain
        normalized_asset_target = cls.normalize_target_domain(asset.target)
        cls.check_ssrf_and_forbidden_networks(normalized_asset_target)

        effective_target = normalized_asset_target
        if target_domain and target_domain.strip():
            candidate = cls.normalize_target_domain(target_domain)
            cls.check_ssrf_and_forbidden_networks(candidate)

            # 5. Enforce scope hierarchy: target domain must match or be a subdomain of the approved asset scope
            asset_apex = cls.extract_apex_domain(normalized_asset_target)
            candidate_apex = cls.extract_apex_domain(candidate)

            if candidate_apex != asset_apex and not candidate.endswith(f".{normalized_asset_target}") and candidate != normalized_asset_target:
                raise ScopeValidationError(
                    f"Requested discovery domain '{candidate}' is outside the authorized scope of asset '{asset.name}' ({normalized_asset_target}).",
                    status_code=status.HTTP_403_FORBIDDEN
                )
            effective_target = candidate

        return asset, effective_target
