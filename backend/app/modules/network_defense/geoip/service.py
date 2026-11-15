"""
PREVENT-X GeoIP Policy Engine
Provides ISO-3166-1 country-level access policies, CIDR exceptions,
offline IP geolocation lookup, and Zero Trust risk score signal adjustments.
"""

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from backend.app.models.audit_log import AuditEvent
from backend.app.models.network_defense import (
    GeoIPPolicy,
    GeoIPPolicyAction,
)
from backend.app.schemas.network_defense import (
    GeoIPLookupResponse,
    GeoIPPolicyCreate,
)

logger = logging.getLogger("preventx.network_defense.geoip")

GEOIP_DB_VERSION = "v2026.11-embedded-offline"

# Static curated offline IP network prefix mapping for high-speed resolution
OFFLINE_GEOIP_RANGES: List[Tuple[ipaddress.IPv4Network, str, str]] = [
    (ipaddress.IPv4Network("103.0.0.0/8"), "IN", "India"),
    (ipaddress.IPv4Network("115.0.0.0/8"), "IN", "India"),
    (ipaddress.IPv4Network("117.0.0.0/8"), "IN", "India"),
    (ipaddress.IPv4Network("122.160.0.0/11"), "IN", "India"),
    (ipaddress.IPv4Network("182.64.0.0/10"), "IN", "India"),
    (ipaddress.IPv4Network("8.8.8.0/24"), "US", "United States"),
    (ipaddress.IPv4Network("1.1.1.0/24"), "US", "United States"),
    (ipaddress.IPv4Network("3.0.0.0/8"), "US", "United States"),
    (ipaddress.IPv4Network("13.0.0.0/8"), "US", "United States"),
    (ipaddress.IPv4Network("52.0.0.0/8"), "US", "United States"),
    (ipaddress.IPv4Network("54.0.0.0/8"), "US", "United States"),
    (ipaddress.IPv4Network("25.0.0.0/8"), "GB", "United Kingdom"),
    (ipaddress.IPv4Network("51.0.0.0/8"), "GB", "United Kingdom"),
    (ipaddress.IPv4Network("46.0.0.0/8"), "DE", "Germany"),
    (ipaddress.IPv4Network("84.0.0.0/8"), "DE", "Germany"),
    (ipaddress.IPv4Network("1.0.0.0/8"), "CN", "China"),
    (ipaddress.IPv4Network("14.0.0.0/8"), "CN", "China"),
    (ipaddress.IPv4Network("36.0.0.0/8"), "CN", "China"),
    (ipaddress.IPv4Network("58.0.0.0/8"), "CN", "China"),
    (ipaddress.IPv4Network("202.0.0.0/8"), "CN", "China"),
    (ipaddress.IPv4Network("77.0.0.0/8"), "RU", "Russia"),
    (ipaddress.IPv4Network("95.0.0.0/8"), "RU", "Russia"),
    (ipaddress.IPv4Network("178.0.0.0/8"), "RU", "Russia"),
    (ipaddress.IPv4Network("175.45.176.0/22"), "KP", "North Korea"),
]

# Standard ISO country names dictionary
COUNTRY_NAMES: Dict[str, str] = {
    "IN": "India",
    "US": "United States",
    "GB": "United Kingdom",
    "DE": "Germany",
    "CN": "China",
    "RU": "Russia",
    "KP": "North Korea",
    "JP": "Japan",
    "FR": "France",
    "CA": "Canada",
    "AU": "Australia",
    "BR": "Brazil",
    "ZZ": "Private / Local Network",
    "XX": "Unknown / Unmapped Location",
}


class GeoIPService:
    """
    Evaluates client IPs against geographic policies and manages tenant rules.
    """

    def resolve_ip_location(self, ip_str: str) -> Tuple[str, str]:
        """
        Resolves an IPv4/IPv6 string to (country_code, country_name).
        Gracefully handles RFC 1918 private subnets, loopbacks, and unmapped IPs.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return "XX", COUNTRY_NAMES["XX"]

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return "ZZ", COUNTRY_NAMES["ZZ"]

        if isinstance(ip_obj, ipaddress.IPv4Address):
            for network, code, name in OFFLINE_GEOIP_RANGES:
                if ip_obj in network:
                    return code, name

        return "XX", COUNTRY_NAMES["XX"]

    def create_policy(
        self,
        db: Session,
        organization_id: uuid.UUID,
        data: GeoIPPolicyCreate,
    ) -> GeoIPPolicy:
        """Creates or updates a country policy for a tenant."""
        code = data.country_code.strip().upper()
        country_name = data.country_name or COUNTRY_NAMES.get(code, code)

        # Check if policy already exists
        existing = db.execute(
            select(GeoIPPolicy).where(
                and_(
                    GeoIPPolicy.organization_id == organization_id,
                    GeoIPPolicy.country_code == code,
                )
            )
        ).scalar_one_or_none()

        if existing:
            existing.action = data.action
            existing.country_name = country_name
            existing.exception_cidrs = data.exception_cidrs
            existing.risk_score_modifier = data.risk_score_modifier
            existing.is_active = True
            db.commit()
            db.refresh(existing)
            return existing

        policy = GeoIPPolicy(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            country_code=code,
            country_name=country_name,
            action=data.action,
            exception_cidrs=data.exception_cidrs,
            risk_score_modifier=data.risk_score_modifier,
            is_active=True,
        )
        db.add(policy)

        audit = AuditEvent(
            organization_id=organization_id,
            action="geoip_policy_create",
            resource_type="geoip_policy",
            resource_id=policy.id,
            status="SUCCESS",
            details=f"Country: {code} ({country_name}), Action: {data.action.value}, Exceptions: {data.exception_cidrs}",
        )
        db.add(audit)
        db.commit()
        db.refresh(policy)
        return policy

    def list_policies(self, db: Session, organization_id: uuid.UUID) -> List[GeoIPPolicy]:
        """Lists all GeoIP policies for an organization."""
        return db.execute(
            select(GeoIPPolicy)
            .where(GeoIPPolicy.organization_id == organization_id)
            .order_by(desc(GeoIPPolicy.created_at))
        ).scalars().all()

    def get_policy(self, db: Session, policy_id: str, organization_id: uuid.UUID) -> Optional[GeoIPPolicy]:
        """Gets a single policy by ID."""
        return db.execute(
            select(GeoIPPolicy).where(
                and_(GeoIPPolicy.id == policy_id, GeoIPPolicy.organization_id == organization_id)
            )
        ).scalar_one_or_none()

    def delete_policy(self, db: Session, policy_id: str, organization_id: uuid.UUID) -> bool:
        """Deletes a policy by ID."""
        policy = self.get_policy(db, policy_id, organization_id)
        if not policy:
            return False
        db.delete(policy)
        db.commit()
        return True

    def evaluate_ip(
        self,
        db: Session,
        organization_id: uuid.UUID,
        ip_str: str,
    ) -> GeoIPLookupResponse:
        """
        Evaluates an IP address against active tenant GeoIP policies.
        Checks exception CIDRs and returns an advisory risk score signal.
        """
        country_code, country_name = self.resolve_ip_location(ip_str)

        # Look up policy for this country in the organization
        policy = db.execute(
            select(GeoIPPolicy).where(
                and_(
                    GeoIPPolicy.organization_id == organization_id,
                    GeoIPPolicy.country_code == country_code,
                    GeoIPPolicy.is_active == True,
                )
            )
        ).scalar_one_or_none()

        is_exception = False
        is_denied = False
        action = None
        risk_score = 0.0

        if policy:
            action = policy.action.value
            # Check CIDR exceptions
            if policy.exception_cidrs:
                try:
                    ip_obj = ipaddress.ip_address(ip_str.strip())
                    for cidr in policy.exception_cidrs.split(","):
                        cidr_clean = cidr.strip()
                        if not cidr_clean:
                            continue
                        if "/" not in cidr_clean:
                            cidr_clean = f"{cidr_clean}/32"
                        if ip_obj in ipaddress.ip_network(cidr_clean, strict=False):
                            is_exception = True
                            break
                except ValueError:
                    pass

            if policy.action == GeoIPPolicyAction.DENY and not is_exception:
                is_denied = True
                risk_score = policy.risk_score_modifier

        return GeoIPLookupResponse(
            ip_address=ip_str,
            country_code=country_code,
            country_name=country_name,
            is_denied=is_denied,
            policy_action=action,
            risk_score_modifier=risk_score,
            is_exception_cidr=is_exception,
            database_version=GEOIP_DB_VERSION,
            is_advisory_only=True,
        )


# Global instance
geoip_service = GeoIPService()
