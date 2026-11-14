"""
PREVENT-X Evidence-Based CNAME Takeover Verification Engine
Enforces multi-stage, non-intrusive classification of dangling CNAME aliases:
- POTENTIAL_DANGLING_CNAME
- UNVERIFIED_RESOURCE
- VERIFIED_UNCLAIMED_RESOURCE
- CONFIRMED_TAKEOVER

STRICT RULES:
1. A DNS NXDOMAIN response alone NEVER establishes a confirmed takeover vulnerability.
2. Provider-specific response signatures are strictly required for VERIFIED_UNCLAIMED_RESOURCE.
3. CONFIRMED_TAKEOVER is NEVER assigned without strong independent human/dual corroboration.
4. NEVER attempt to claim, register, modify, or exploit external resources.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
import dns.resolver
import dns.exception

from backend.app.models.attack_surface import TakeoverVerificationStatus, EvidenceNature
from backend.app.modules.attack_surface.ssrf_defense import SSRFDefense, SSRFValidationError

logger = logging.getLogger("preventx.attack_surface.cname_verifier")

# Known cloud provider CNAME regexes and unallocated/unclaimed error signatures
KNOWN_PROVIDERS: Dict[str, Dict[str, Any]] = {
    "GitHub Pages": {
        "cname_patterns": [r".*\.github\.io$"],
        "signatures": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "status_codes": [404],
    },
    "Amazon Web Services (S3)": {
        "cname_patterns": [
            r".*\.s3\.amazonaws\.com$",
            r".*\.s3-website-[a-z0-9-]+\.amazonaws\.com$",
            r".*\.s3-[a-z0-9-]+\.amazonaws\.com$",
            r".*\.s3\.dualstack\.[a-z0-9-]+\.amazonaws\.com$",
        ],
        "signatures": [
            "<Code>NoSuchBucket</Code>",
            "The specified bucket does not exist",
        ],
        "status_codes": [404],
    },
    "Microsoft Azure App Service": {
        "cname_patterns": [
            r".*\.azurewebsites\.net$",
            r".*\.cloudapp\.net$",
            r".*\.trafficmanager\.net$",
            r".*\.azurefd\.net$",
        ],
        "signatures": [
            "404 Web Site not found",
            "The web app you have selected is temporarily unavailable",
        ],
        "status_codes": [404],
    },
    "Heroku": {
        "cname_patterns": [r".*\.herokuapp\.com$", r".*\.herokudns\.com$"],
        "signatures": [
            "Heroku | No such app",
            "No such app",
            "<title>No such app</title>",
        ],
        "status_codes": [404, 502],
    },
    "Shopify": {
        "cname_patterns": [r".*\.myshopify\.com$"],
        "signatures": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left to start selling",
        ],
        "status_codes": [404],
    },
    "Bitbucket Cloud": {
        "cname_patterns": [r".*\.bitbucket\.io$"],
        "signatures": [
            "Repository not found",
            "The page you are looking for doesn't exist",
        ],
        "status_codes": [404],
    },
    "Ghost": {
        "cname_patterns": [r".*\.ghost\.io$"],
        "signatures": [
            "The thing you were looking for is no longer here",
            "Site unavailable",
        ],
        "status_codes": [404],
    },
    "Fastly": {
        "cname_patterns": [r".*\.fastly\.net$"],
        "signatures": [
            "Fastly error: unknown domain",
        ],
        "status_codes": [404, 500],
    },
    "Surge": {
        "cname_patterns": [r".*\.surge\.sh$"],
        "signatures": [
            "project not found",
        ],
        "status_codes": [404],
    },
    "Zendesk": {
        "cname_patterns": [r".*\.zendesk\.com$"],
        "signatures": [
            "Help Center Closed",
        ],
        "status_codes": [404],
    },
}


@dataclass
class CNAMEVerificationResult:
    """Structured evidence assessment for a CNAME alias pointer."""
    subdomain: str
    cname_target: str
    provider: Optional[str]
    status: str  # TakeoverVerificationStatus enum
    evidence_nature: str  # EvidenceNature enum
    confidence: str  # HIGH, MEDIUM, LOW
    matched_signature: Optional[str] = None
    http_status_code: Optional[int] = None
    reason: str = ""
    evidence_payload: Dict[str, Any] = field(default_factory=dict)


class CNAMEVerifier:
    """Non-intrusive evidence-based CNAME takeover classifier."""

    def __init__(self, resolver_timeout: float = 3.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = resolver_timeout
        self.resolver.lifetime = resolver_timeout
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "8.8.4.4"]

    def identify_provider(self, cname_target: str) -> Optional[str]:
        """Matches a CNAME target against known cloud provider patterns."""
        clean = cname_target.strip().lower().rstrip(".")
        for provider, config in KNOWN_PROVIDERS.items():
            for pattern in config["cname_patterns"]:
                if re.match(pattern, clean):
                    return provider
        return None

    def verify_cname(
        self,
        subdomain: str,
        cname_target: str,
        allow_http_probe: bool = True,
        independent_analyst_verified: bool = False,
    ) -> CNAMEVerificationResult:
        """
        Executes evidence-based classification of a CNAME pointer.
        Never establishes CONFIRMED_TAKEOVER without strong independent corroboration.
        """
        clean_sub = subdomain.strip().lower().rstrip(".")
        clean_target = cname_target.strip().lower().rstrip(".")

        provider = self.identify_provider(clean_target)

        # 1. Unknown provider or generic CNAME alias
        if not provider:
            return CNAMEVerificationResult(
                subdomain=clean_sub,
                cname_target=clean_target,
                provider=None,
                status=TakeoverVerificationStatus.POTENTIAL_DANGLING_CNAME,
                evidence_nature=EvidenceNature.UNVERIFIED_FINDING,
                confidence="LOW",
                reason=f"CNAME alias '{clean_target}' does not match recognized cloud provider patterns.",
                evidence_payload={"subdomain": clean_sub, "cname_target": clean_target, "provider": None},
            )

        provider_config = KNOWN_PROVIDERS[provider]

        # 2. DNS Resolution of the CNAME Target
        dns_nxdomain = False
        dns_resolved_ips: List[str] = []
        try:
            answers = self.resolver.resolve(clean_target, "A")
            dns_resolved_ips = [str(r).strip() for r in answers]
        except dns.resolver.NXDOMAIN:
            dns_nxdomain = True
        except (dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException) as exc:
            logger.debug(f"DNS check on {clean_target} yielded error: {exc}")

        # 3. Safe read-only HTTP signature verification (if permitted)
        if allow_http_probe:
            http_result = self._probe_http_signature(clean_sub, provider, provider_config)
            if http_result:
                status_code, matched_sig, body_snippet = http_result
                evidence = {
                    "subdomain": clean_sub,
                    "cname_target": clean_target,
                    "provider": provider,
                    "matched_signature": matched_sig,
                    "http_status_code": status_code,
                    "body_snippet": body_snippet,
                    "dns_nxdomain": dns_nxdomain,
                }

                # Strong independent analyst corroboration required for CONFIRMED_TAKEOVER
                if independent_analyst_verified:
                    return CNAMEVerificationResult(
                        subdomain=clean_sub,
                        cname_target=clean_target,
                        provider=provider,
                        status=TakeoverVerificationStatus.CONFIRMED_TAKEOVER,
                        evidence_nature=EvidenceNature.VERIFIED_ISSUE,
                        confidence="HIGH",
                        matched_signature=matched_sig,
                        http_status_code=status_code,
                        reason=f"Confirmed unclaimed {provider} tenancy verified by provider signature and independent corroboration.",
                        evidence_payload=evidence,
                    )

                # Sufficient provider signature verified: VERIFIED_UNCLAIMED_RESOURCE
                return CNAMEVerificationResult(
                    subdomain=clean_sub,
                    cname_target=clean_target,
                    provider=provider,
                    status=TakeoverVerificationStatus.VERIFIED_UNCLAIMED_RESOURCE,
                    evidence_nature=EvidenceNature.VERIFIED_ISSUE,
                    confidence="HIGH",
                    matched_signature=matched_sig,
                    http_status_code=status_code,
                    reason=f"Verified unclaimed {provider} resource: HTTP response matched provider signature '{matched_sig}' with status {status_code}.",
                    evidence_payload=evidence,
                )

        # 4. If DNS returned NXDOMAIN, but NO provider signature was verified:
        # Prompt 1.2 Rule: "A DNS NXDOMAIN response alone must never establish a confirmed takeover vulnerability."
        if dns_nxdomain:
            return CNAMEVerificationResult(
                subdomain=clean_sub,
                cname_target=clean_target,
                provider=provider,
                status=TakeoverVerificationStatus.POTENTIAL_DANGLING_CNAME,
                evidence_nature=EvidenceNature.POTENTIAL_WEAKNESS,
                confidence="MEDIUM",
                reason=f"Target {clean_target} ({provider}) returned DNS NXDOMAIN, but provider-specific unclaimed signature was not confirmed; classified as potential dangling pointer.",
                evidence_payload={"subdomain": clean_sub, "cname_target": clean_target, "provider": provider, "dns_status": "NXDOMAIN"},
            )

        # 5. Inconclusive or active response
        return CNAMEVerificationResult(
            subdomain=clean_sub,
            cname_target=clean_target,
            provider=provider,
            status=TakeoverVerificationStatus.UNVERIFIED_RESOURCE,
            evidence_nature=EvidenceNature.UNVERIFIED_FINDING,
            confidence="LOW",
            reason=f"Target {clean_target} ({provider}) did not yield conclusive provider-specific unclaimed evidence.",
            evidence_payload={"subdomain": clean_sub, "cname_target": clean_target, "provider": provider, "resolved_ips": dns_resolved_ips},
        )

    def _probe_http_signature(
        self,
        subdomain: str,
        provider: str,
        config: Dict[str, Any],
    ) -> Optional[Tuple[int, str, str]]:
        """
        Sends a safe, read-only GET request to the target host to check for provider error signatures.
        Enforces strict timeouts, payload caps, and SSRF defenses.
        Never executes state-modifying requests or claims.
        """
        try:
            client = SSRFDefense.create_safe_client(
                allow_private=False,
                max_redirects=2,
                max_response_size=512 * 1024,  # 512 KB cap for signature checks
            )
            with client:
                # Probe HTTP
                url = f"http://{subdomain}/"
                resp = client.get(url, timeout=5.0)

                # Check status code and signatures
                if resp.status_code in config.get("status_codes", [404]):
                    text = resp.text
                    for sig in config["signatures"]:
                        if sig in text:
                            snippet = text[:200].replace("\n", " ").strip()
                            return resp.status_code, sig, snippet

        except (SSRFValidationError, Exception) as exc:
            logger.debug(f"Safe HTTP signature check on {subdomain} yielded non-fatal exception: {exc}")

        return None
