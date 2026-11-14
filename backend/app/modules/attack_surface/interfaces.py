"""
PREVENT-X Attack Surface Engine Interfaces
Abstract protocols and contracts for passive intelligence collectors, scope validators, and risk engines.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime


class CertificateTransparencyProvider(ABC):
    """Protocol for fetching certificate transparency logs."""

    @abstractmethod
    def fetch_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Retrieves certificate transparency entries for target domain.
        Returns list of dicts with keys:
            - common_name: str
            - subject_alt_names: List[str]
            - issuer_name: str
            - not_before: Optional[datetime]
            - not_after: Optional[datetime]
            - is_expired: bool
            - is_wildcard: bool
            - serial_number: Optional[str]
            - logged_at: Optional[datetime]
            - raw: Any
        """
        pass


class DNSIntelligenceProvider(ABC):
    """Protocol for active/passive DNS record enumeration and security evaluation."""

    @abstractmethod
    def resolve_domain(self, domain: str) -> Dict[str, Any]:
        """
        Resolves standard DNS records for domain.
        Returns dict containing:
            - records: List[Dict[str, Any]] (type, value, ttl, status)
            - spf_record: Optional[str]
            - dmarc_record: Optional[str]
            - public_ips: List[str]
            - internal_ips_detected: List[str]
            - cname_targets: List[str]
        """
        pass


class RDAPIntelligenceProvider(ABC):
    """Protocol for privacy-preserving domain registration inspection."""

    @abstractmethod
    def fetch_domain_profile(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Queries RDAP registration metadata with PII stripping.
        Returns dict containing:
            - handle: Optional[str]
            - registrar_name: Optional[str]
            - whois_server: Optional[str]
            - registration_date: Optional[datetime]
            - expiration_date: Optional[datetime]
            - last_updated_date: Optional[datetime]
            - nameservers: List[str]
            - status_codes: List[str]
            - asn: Optional[str]
        """
        pass


class RiskScoringEngineInterface(ABC):
    """Protocol for deterministic, explainable exposure risk scoring."""

    @abstractmethod
    def calculate_risk(
        self,
        domain_name: str,
        subdomains: List[str],
        dns_data: Dict[str, Any],
        certificates: List[Dict[str, Any]],
        rdap_data: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Computes score (0.0-100.0) and factor breakdown.
        """
        pass
