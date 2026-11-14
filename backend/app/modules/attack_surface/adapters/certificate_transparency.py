"""
PREVENT-X Certificate Transparency Adapter
Queries public CT logs via crt.sh to passively discover subdomains, wildcards, and certificate timelines.
"""

from datetime import datetime, timezone
import json
import logging
from typing import List, Dict, Any, Set, Tuple, Optional
import httpx
from backend.app.modules.attack_surface.interfaces import CertificateTransparencyProvider

logger = logging.getLogger("preventx.attack_surface.crt")


class CertificateTransparencyAdapter(CertificateTransparencyProvider):
    """Integrates with public Certificate Transparency logs using HTTPX."""

    CRT_SH_URL = "https://crt.sh/"

    def __init__(self, timeout_seconds: float = 12.0, max_retries: int = 2):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def fetch_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Retrieves raw certificate records from crt.sh.
        """
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": "PREVENT-X-AttackSurfaceEngine/1.0 (+https://preventx.smb.in)"}

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                    response = client.get(self.CRT_SH_URL, params=params, headers=headers)
                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")
                        if "json" in content_type or response.text.startswith("["):
                            try:
                                return response.json()
                            except json.JSONDecodeError:
                                logger.warning(f"Failed to parse crt.sh JSON for {domain}")
                                return []
                        else:
                            logger.warning(f"crt.sh returned non-JSON payload for {domain}: {response.status_code}")
                            return []
                    elif response.status_code in (502, 503, 504):
                        logger.warning(f"crt.sh temporary server error {response.status_code} (attempt {attempt}/{self.max_retries})")
                    else:
                        logger.warning(f"crt.sh returned unexpected HTTP {response.status_code} for {domain}")
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                logger.warning(f"crt.sh network/timeout error for {domain} (attempt {attempt}/{self.max_retries}): {exc}")

        return []

    def parse_certificates_and_domains(
        self, domain: str, raw_entries: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """
        Normalizes crt.sh entries, parses validity dates, flags wildcards, and extracts deduplicated subdomains.
        """
        now = datetime.now(timezone.utc)
        parsed_certs: List[Dict[str, Any]] = []
        discovered_domains: Set[str] = {domain.lower()}

        # Always include base domain
        for entry in raw_entries:
            common_name = (entry.get("common_name") or "").strip().lower()
            name_value = (entry.get("name_value") or "").strip().lower()
            issuer_name = entry.get("issuer_name") or "Unknown Issuer"
            serial_number = str(entry.get("serial_number") or "")

            # Parse SANs (name_value often contains multiple lines)
            raw_sans = set()
            if name_value:
                for line in name_value.split("\n"):
                    val = line.strip().lower()
                    if val:
                        raw_sans.add(val)
            if common_name:
                raw_sans.add(common_name)

            # Dates
            not_before = self._parse_iso_date(entry.get("not_before"))
            not_after = self._parse_iso_date(entry.get("not_after"))
            entry_timestamp = self._parse_iso_date(entry.get("entry_timestamp"))

            is_expired = False
            if not_after and not_after < now:
                is_expired = True

            is_wildcard = any(san.startswith("*.") for san in raw_sans)

            # Collect clean subdomains matching target domain
            clean_sans_list = []
            for san in raw_sans:
                clean_san = san.lstrip("*.").strip()
                if clean_san and (clean_san == domain or clean_san.endswith(f".{domain}")):
                    clean_sans_list.append(clean_san)
                    discovered_domains.add(clean_san)

            parsed_certs.append({
                "common_name": common_name,
                "subject_alt_names": json.dumps(sorted(list(set(clean_sans_list)))),
                "issuer_name": issuer_name,
                "not_before": not_before,
                "not_after": not_after,
                "is_expired": is_expired,
                "is_wildcard": is_wildcard,
                "serial_number": serial_number[:128] if serial_number else None,
                "logged_at": entry_timestamp,
                "source": "CRT_SH",
                "raw_evidence": json.dumps({
                    "id": entry.get("id"),
                    "issuer_ca_id": entry.get("issuer_ca_id"),
                }),
            })

        return parsed_certs, discovered_domains

    @staticmethod
    def _parse_iso_date(val: Optional[str]) -> Optional[datetime]:
        if not val or not isinstance(val, str):
            return None
        formats = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d",
        ]
        val_clean = val.split(".")[0].rstrip("Z")
        for fmt in formats:
            try:
                dt = datetime.strptime(val_clean, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
