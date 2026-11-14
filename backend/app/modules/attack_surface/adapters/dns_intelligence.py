"""
PREVENT-X DNS Intelligence Adapter
Executes passive DNS enumeration using dnspython for A, AAAA, CNAME, MX, NS, TXT, SPF, and DMARC.
"""

from datetime import datetime, timezone
import ipaddress
import logging
from typing import List, Dict, Any, Optional, Set, Tuple
import dns.resolver
import dns.exception
from backend.app.modules.attack_surface.interfaces import DNSIntelligenceProvider
from backend.app.models.attack_surface import TakeoverVerificationStatus
from backend.app.modules.attack_surface.cname_verifier import CNAMEVerifier, CNAMEVerificationResult

logger = logging.getLogger("preventx.attack_surface.dns")

DANGLING_CNAME_PATTERNS = [
    "s3.amazonaws.com",
    "github.io",
    "azurewebsites.net",
    "cloudapp.net",
    "herokuapp.com",
    "pantheonsite.io",
    "ghost.io",
    "wordpress.com",
    "bitbucket.io",
    "surge.sh",
    "elasticbeanstalk.com",
    "readme.io",
    "fly.dev",
]


class DNSIntelligenceAdapter(DNSIntelligenceProvider):
    """Enumerates DNS infrastructure and extracts exposure signals."""

    def __init__(self, nameservers: Optional[List[str]] = None, timeout: float = 4.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.cname_verifier = CNAMEVerifier(resolver_timeout=timeout)
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            # Fallback to reliable public resolvers alongside system resolver
            self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "8.8.4.4"]

    def resolve_domain(self, domain: str) -> Dict[str, Any]:
        """
        Executes comprehensive DNS queries for target domain.
        """
        records: List[Dict[str, Any]] = []
        public_ips: Set[str] = set()
        internal_ips: Set[str] = set()
        cname_targets: List[str] = []
        dangling_candidates: List[str] = []
        spf_record: Optional[str] = None
        dmarc_record: Optional[str] = None
        now = datetime.now(timezone.utc)

        # 1. Query A records
        a_records = self._query_records(domain, "A")
        for val, ttl in a_records:
            records.append({
                "record_type": "A",
                "record_value": val,
                "ttl": ttl,
                "source": "DNS_RESOLVER",
                "resolution_status": "RESOLVED",
                "collected_at": now,
            })
            self._categorize_ip(val, public_ips, internal_ips)

        # 2. Query AAAA records
        aaaa_records = self._query_records(domain, "AAAA")
        for val, ttl in aaaa_records:
            records.append({
                "record_type": "AAAA",
                "record_value": val,
                "ttl": ttl,
                "source": "DNS_RESOLVER",
                "resolution_status": "RESOLVED",
                "collected_at": now,
            })
            self._categorize_ip(val, public_ips, internal_ips)

        # 3. Query CNAME records
        cname_recs = self._query_records(domain, "CNAME")
        cname_status = "NONE"

        for val, ttl in cname_recs:
            clean_cname = val.rstrip(".")
            cname_targets.append(clean_cname)
            records.append({
                "record_type": "CNAME",
                "record_value": clean_cname,
                "ttl": ttl,
                "source": "DNS_RESOLVER",
                "resolution_status": "RESOLVED",
                "collected_at": now,
            })
            # Check dangling CNAME patterns via CNAMEVerifier
            verif = self.cname_verifier.verify_cname(domain, clean_cname, allow_http_probe=True)
            if verif.provider:
                dangling_candidates.append(clean_cname)
                cname_status = verif.status

        # 4. Query MX records
        mx_records = self._query_records(domain, "MX")
        for val, ttl in mx_records:
            records.append({
                "record_type": "MX",
                "record_value": val.rstrip("."),
                "ttl": ttl,
                "source": "DNS_RESOLVER",
                "resolution_status": "RESOLVED",
                "collected_at": now,
            })

        # 5. Query NS records
        ns_records = self._query_records(domain, "NS")
        for val, ttl in ns_records:
            records.append({
                "record_type": "NS",
                "record_value": val.rstrip("."),
                "ttl": ttl,
                "source": "DNS_RESOLVER",
                "resolution_status": "RESOLVED",
                "collected_at": now,
            })

        # 6. Query TXT records (inspect for SPF)
        txt_records = self._query_records(domain, "TXT")
        for val, ttl in txt_records:
            clean_txt = val.strip('"')
            records.append({
                "record_type": "TXT",
                "record_value": clean_txt,
                "ttl": ttl,
                "source": "DNS_RESOLVER",
                "resolution_status": "RESOLVED",
                "collected_at": now,
            })
            if clean_txt.startswith("v=spf1"):
                spf_record = clean_txt

        # 7. Query DMARC record (_dmarc.domain)
        dmarc_recs = self._query_records(f"_dmarc.{domain}", "TXT")
        for val, ttl in dmarc_recs:
            clean_dmarc = val.strip('"')
            if clean_dmarc.startswith("v=DMARC1"):
                dmarc_record = clean_dmarc
                records.append({
                    "record_type": "TXT",
                    "record_value": clean_dmarc,
                    "ttl": ttl,
                    "source": "DNS_RESOLVER",
                    "resolution_status": "RESOLVED",
                    "collected_at": now,
                })
                break

        return {
            "records": records,
            "public_ips": sorted(list(public_ips)),
            "internal_ips_detected": sorted(list(internal_ips)),
            "cname_targets": cname_targets,
            "dangling_cname_candidates": dangling_candidates,
            "cname_takeover_status": cname_status,
            "spf_record": spf_record,
            "dmarc_record": dmarc_record,
            "has_mx": len(mx_records) > 0,
            "has_ns": len(ns_records) > 0,
        }

    def _check_cname_target_status(self, cname_target: str, domain: str = "sub.domain.local") -> str:
        """
        Safely inspects CNAME target resolution and provider signatures via CNAMEVerifier.
        """
        verif = self.cname_verifier.verify_cname(domain, cname_target, allow_http_probe=False)
        return verif.status

    def _query_records(self, domain: str, rtype: str) -> List[Tuple[str, Optional[int]]]:
        results: List[Tuple[str, Optional[int]]] = []
        try:
            answers = self.resolver.resolve(domain, rtype)
            for rdata in answers:
                ttl = answers.rrset.ttl if answers.rrset else None
                results.append((str(rdata), ttl))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except (dns.resolver.Timeout, dns.exception.DNSException) as e:
            logger.debug(f"DNS query {rtype} for {domain} error: {e}")
        return results

    @staticmethod
    def _categorize_ip(ip_str: str, public_ips: Set[str], internal_ips: Set[str]) -> None:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                internal_ips.add(ip_str)
            else:
                public_ips.add(ip_str)
        except ValueError:
            pass
