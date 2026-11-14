"""
PREVENT-X RDAP Intelligence Adapter
Queries public RDAP endpoints via rdap.org with mandatory PII redaction and registrar timeline extraction.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Dict, Any, Optional, List
import httpx
from backend.app.modules.attack_surface.interfaces import RDAPIntelligenceProvider

logger = logging.getLogger("preventx.attack_surface.rdap")


class RDAPAdapter(RDAPIntelligenceProvider):
    """Fetches domain registration data with strict privacy preservation."""

    BASE_URL = "https://rdap.org/domain/"

    def __init__(self, timeout_seconds: float = 10.0, max_retries: int = 2):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def fetch_domain_profile(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Executes RDAP query and returns sanitized registration metadata.
        """
        url = f"{self.BASE_URL}{domain}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "PREVENT-X-AttackSurfaceEngine/1.0 (+https://preventx.smb.in)",
        }

        for attempt in range(1, self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout_seconds, follow_redirects=True) as client:
                    resp = client.get(url, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        return self._sanitize_and_parse(data)
                    elif resp.status_code == 404:
                        logger.info(f"RDAP record not found for domain {domain}")
                        return None
                    else:
                        logger.warning(f"RDAP query for {domain} returned HTTP {resp.status_code}")
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.warning(f"RDAP connection error for {domain} (attempt {attempt}/{self.max_retries}): {e}")

        return None

    def _sanitize_and_parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts registration metadata while stripping all personal PII.
        """
        handle = raw.get("handle")
        port43 = raw.get("port43")
        status_codes = raw.get("status", [])

        # Extract nameservers
        nameservers: List[str] = []
        for ns in raw.get("nameservers", []):
            ldh_name = ns.get("ldhName")
            if ldh_name:
                nameservers.append(ldh_name.lower())

        # Extract dates from events
        reg_date: Optional[datetime] = None
        exp_date: Optional[datetime] = None
        last_changed_date: Optional[datetime] = None

        for event in raw.get("events", []):
            action = event.get("eventAction")
            date_str = event.get("eventDate")
            if not date_str:
                continue

            dt = self._parse_iso_date(date_str)
            if not dt:
                continue

            if action == "registration":
                reg_date = dt
            elif action == "expiration":
                exp_date = dt
            elif action in ("last changed", "last update"):
                last_changed_date = dt

        # Extract registrar name safely without logging individuals
        registrar_name = None
        for entity in raw.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if len(prop) > 3 and prop[0] == "fn":
                            registrar_name = str(prop[3])
                            break
                if not registrar_name:
                    registrar_name = entity.get("handle")

        return {
            "handle": handle,
            "registrar_name": registrar_name,
            "whois_server": port43,
            "registration_date": reg_date,
            "expiration_date": exp_date,
            "last_updated_date": last_changed_date,
            "nameservers": json.dumps(nameservers) if nameservers else None,
            "status_codes": json.dumps(status_codes) if status_codes else None,
            "asn": None,
            "raw_data": json.dumps({
                "ldhName": raw.get("ldhName"),
                "status": status_codes,
            }),
        }

    @staticmethod
    def _parse_iso_date(val: str) -> Optional[datetime]:
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ]
        clean = val.split(".")[0]
        for fmt in formats:
            try:
                dt = datetime.strptime(clean, fmt)
                if not dt.tzinfo:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None
