"""
PREVENT-X Network Defense Data Models
Provides persistent database entities for OS Firewall rules, Dynamic IP blocking,
Rate Limiting policies, Honeypot tracking, GeoIP policies, Traffic Replay, and ML classifications.
All entities strictly enforce multi-tenant isolation through organization_id.
"""

import enum
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from backend.app.database.base import Base, TimestampMixin
from backend.app.database.guid import GUID


class FirewallRuleDirection(str, enum.Enum):
    INBOUND = "in"
    OUTBOUND = "out"


class FirewallRuleAction(str, enum.Enum):
    BLOCK = "block"
    ALLOW = "allow"


class FirewallRuleProtocol(str, enum.Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMPV4 = "ICMPv4"
    ICMPV6 = "ICMPv6"
    ANY = "ANY"


class FirewallEnforcementStatus(str, enum.Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    REMOVED = "REMOVED"
    ROLLED_BACK = "ROLLED_BACK"


class FirewallRule(Base, TimestampMixin):
    """
    Genuine OS Firewall rule record synchronized with Windows Defender Firewall.
    Never marked VERIFIED unless Windows explicitly confirms its active status.
    """
    __tablename__ = "network_firewall_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(128), nullable=False, unique=True, index=True)
    display_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    direction = Column(Enum(FirewallRuleDirection), default=FirewallRuleDirection.INBOUND, nullable=False)
    action = Column(Enum(FirewallRuleAction), default=FirewallRuleAction.BLOCK, nullable=False)
    protocol = Column(Enum(FirewallRuleProtocol), default=FirewallRuleProtocol.ANY, nullable=False)

    remote_ip_or_cidr = Column(String(128), nullable=False)  # IPv4, IPv6, or CIDR block
    local_ports = Column(String(64), nullable=True)         # e.g., "80,443" or "ANY"
    remote_ports = Column(String(64), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    verified_active = Column(Boolean, default=False, nullable=False)
    enforcement_status = Column(
        Enum(FirewallEnforcementStatus),
        default=FirewallEnforcementStatus.PENDING,
        nullable=False,
    )
    verification_details = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)

    created_by_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    @property
    def is_os_enforced(self) -> bool:
        """
        Actual operating-system enforcement state.
        True ONLY when authentic OS kernel query confirmed the rule is active in the firewall table.
        Distinguishes actual OS packet blocking from logical policy enablement (is_active).
        """
        return bool(self.verified_active and self.enforcement_status == FirewallEnforcementStatus.VERIFIED)

    @property
    def is_logical_enabled(self) -> bool:
        """
        Logical policy state.
        True if the policy is enabled in PREVENT-X configuration and not rolled back or removed.
        """
        return bool(self.is_active and self.enforcement_status not in (
            FirewallEnforcementStatus.ROLLED_BACK,
            FirewallEnforcementStatus.REMOVED,
        ))

    __table_args__ = (
        Index("ix_fw_org_status", "organization_id", "enforcement_status"),
        Index("ix_fw_org_remote", "organization_id", "remote_ip_or_cidr"),
    )


class DynamicIPBlockStatus(str, enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    UNBLOCKED = "UNBLOCKED"
    REJECTED = "REJECTED"


class DynamicIPBlock(Base, TimestampMixin):
    """
    Dynamic IP block entity with automatic expiration and incident correlation.
    """
    __tablename__ = "network_dynamic_ip_blocks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_or_cidr = Column(String(128), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    incident_id = Column(String(36), nullable=True, index=True)
    threat_intel_score = Column(Float, nullable=True)

    status = Column(
        Enum(DynamicIPBlockStatus),
        default=DynamicIPBlockStatus.PENDING_APPROVAL,
        nullable=False,
        index=True,
    )
    firewall_rule_id = Column(String(36), ForeignKey("network_firewall_rules.id", ondelete="SET NULL"), nullable=True)
    
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    unblocked_at = Column(DateTime(timezone=True), nullable=True)
    unblocked_reason = Column(String(255), nullable=True)

    created_by_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    approved_by_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_dynblock_org_ip", "organization_id", "ip_or_cidr"),
    )


class RateLimitingAlgorithm(str, enum.Enum):
    SLIDING_WINDOW = "SLIDING_WINDOW"
    TOKEN_BUCKET = "TOKEN_BUCKET"


class RateLimitScope(str, enum.Enum):
    IP = "IP"
    ENDPOINT = "ENDPOINT"
    TENANT = "TENANT"


class RateLimitPolicy(Base, TimestampMixin):
    """
    Configurable Rate Limiting Policy for distributed sliding-window & token-bucket algorithms.
    """
    __tablename__ = "network_rate_limit_policies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name = Column(String(128), nullable=False)
    endpoint_pattern = Column(String(255), nullable=False)  # e.g., "/api/v1/auth/*" or "*"
    scope = Column(Enum(RateLimitScope), default=RateLimitScope.IP, nullable=False)
    algorithm = Column(Enum(RateLimitingAlgorithm), default=RateLimitingAlgorithm.SLIDING_WINDOW, nullable=False)

    max_requests = Column(Integer, nullable=False, default=60)
    window_seconds = Column(Integer, nullable=False, default=60)
    burst_capacity = Column(Integer, nullable=False, default=10)
    refill_rate_per_sec = Column(Float, nullable=False, default=1.0)

    is_active = Column(Boolean, default=True, nullable=False)


class HoneypotProbe(Base, TimestampMixin):
    """
    Records probes against deceptive decoy honeypot endpoints.
    """
    __tablename__ = "network_honeypot_probes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    trap_path = Column(String(255), nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    http_method = Column(String(16), nullable=False)
    user_agent = Column(Text, nullable=True)
    query_string = Column(Text, nullable=True)
    payload_preview = Column(Text, nullable=True)

    correlated_incident_id = Column(String(36), nullable=True)
    recommended_block_id = Column(String(36), nullable=True)


class GeoIPPolicyAction(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class GeoIPPolicy(Base, TimestampMixin):
    """
    Geographical location policy based on ISO-3166-1 alpha-2 country codes.
    """
    __tablename__ = "network_geoip_policies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    country_code = Column(String(4), nullable=False, index=True)  # e.g., "US", "IN", "CN"
    country_name = Column(String(64), nullable=False)
    action = Column(Enum(GeoIPPolicyAction), default=GeoIPPolicyAction.DENY, nullable=False)
    exception_cidrs = Column(Text, nullable=True)  # Comma-separated CIDRs
    risk_score_modifier = Column(Float, default=30.0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


class TrafficReplayReport(Base, TimestampMixin):
    """
    Results of differential traffic replay validation against patches.
    """
    __tablename__ = "network_replay_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id = Column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    virtual_patch_id = Column(
        GUID(),
        ForeignKey("virtual_patch_rules.id", ondelete="CASCADE"),
        nullable=True,
    )
    total_replayed = Column(Integer, nullable=False, default=0)
    passed_benign = Column(Integer, nullable=False, default=0)
    false_positives = Column(Integer, nullable=False, default=0)
    missed_threats = Column(Integer, nullable=False, default=0)
    fp_rate = Column(Float, nullable=False, default=0.0)
    is_regression_free = Column(Boolean, nullable=False, default=False)
    report_details = Column(Text, nullable=True)  # JSON-serialized findings
