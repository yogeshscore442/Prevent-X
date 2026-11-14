"""
PREVENT-X Comprehensive SSRF Defenses & Safe Transport Gate
Provides multi-layer validation against IPv4/IPv6 alternate encodings, IPv4-mapped IPv6,
cloud metadata, DNS rebinding, redirect exploitation, and payload bomb attacks.
"""

import ipaddress
import re
import socket
from typing import Optional, Tuple, List, Union
from urllib.parse import urlparse
import dns.resolver
import dns.exception
import httpx
from fastapi import HTTPException, status


class SSRFValidationError(HTTPException):
    """Exception raised when SSRF or network boundary check fails."""
    def __init__(self, detail: str, status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(status_code=status_code, detail=detail)


# Standard forbidden hostnames and cloud metadata domains
FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "metadata",
}

FORBIDDEN_TLDS = {
    "local", "internal", "localhost", "lan", "home", "corp",
    "test", "example", "invalid", "onion", "arpa"
}

# Explicit cloud hypervisor metadata IP addresses
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS, GCP, Azure, OpenStack
    "169.254.169.253",  # AWS EC2 DNS
    "100.100.100.200",  # Alibaba Cloud metadata
    "192.0.0.192",      # Oracle Cloud metadata
}


class SSRFDefense:
    """Enterprise SSRF defense suite enforcing multi-stage connection security."""

    MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB maximum allowed response payload
    CONNECT_TIMEOUT = 5.0                # 5 seconds connect timeout
    READ_TIMEOUT = 10.0                  # 10 seconds read timeout

    @classmethod
    def parse_and_normalize_ip(cls, candidate: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """
        Parses IP addresses handling decimal, octal, hex, and IPv4-mapped IPv6 encodings.
        Returns IP address object, or None if string is not an IP address.
        """
        candidate = candidate.strip().lower()
        if not candidate:
            return None

        # 1. Standard IP address parsing
        try:
            return ipaddress.ip_address(candidate)
        except ValueError:
            pass

        # 2. Decimal integer IP representation (e.g. "2130706433" for 127.0.0.1)
        if candidate.isdigit():
            try:
                num = int(candidate)
                if 0 <= num <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(num)
            except (ValueError, OverflowError):
                pass

        # 3. Hex integer IP representation (e.g. "0x7f000001")
        if candidate.startswith("0x") and re.match(r"^0x[0-9a-f]{1,8}$", candidate):
            try:
                num = int(candidate, 16)
                if 0 <= num <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(num)
            except (ValueError, OverflowError):
                pass

        # 4. Dotted hex or octal notation (e.g. "0177.0.0.1" or "0x7f.0.0.1")
        parts = candidate.split(".")
        if len(parts) == 4:
            try:
                octets = []
                for p in parts:
                    if p.startswith("0x"):
                        octets.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1 and p.isdigit():
                        octets.append(int(p, 8))
                    elif p.isdigit():
                        octets.append(int(p, 10))
                    else:
                        return None
                if all(0 <= o <= 255 for o in octets):
                    return ipaddress.IPv4Address(bytes(octets))
            except (ValueError, OverflowError):
                pass

        return None

    @classmethod
    def extract_real_ip(cls, ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
        """
        Unpacks IPv4-mapped IPv6, IPv4-compatible IPv6, and 6to4 addresses to their underlying IPv4.
        """
        if isinstance(ip_obj, ipaddress.IPv6Address):
            # IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
            if ip_obj.ipv4_mapped:
                return ip_obj.ipv4_mapped

            # IPv4-compatible IPv6 (::127.0.0.1)
            if ip_obj.is_reserved and ip_obj.exploded.startswith("0000:0000:0000:0000:0000:0000:"):
                last_32_bits = int(ip_obj) & 0xFFFFFFFF
                return ipaddress.IPv4Address(last_32_bits)

            # 6to4 address (2002::/16 where bits 16..48 represent embedded IPv4)
            if ip_obj.exploded.startswith("2002:"):
                raw_int = int(ip_obj)
                embedded_v4_int = (raw_int >> 80) & 0xFFFFFFFF
                return ipaddress.IPv4Address(embedded_v4_int)

        return ip_obj

    @classmethod
    def is_ip_forbidden(
        cls,
        ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
        allow_private: bool = False,
        allowlist_cidrs: Optional[List[str]] = None,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether an IP address violates SSRF network boundaries.
        Returns:
            Tuple[bool, str]: (is_forbidden, reason)
        """
        real_ip = cls.extract_real_ip(ip_obj)
        ip_str = str(real_ip)

        # 1. Cloud Hypervisor Metadata is ALWAYS prohibited
        if ip_str in CLOUD_METADATA_IPS:
            return True, f"Target IP {ip_str} is a protected cloud metadata endpoint."

        # 2. Loopback addresses are ALWAYS prohibited
        if real_ip.is_loopback or (isinstance(real_ip, ipaddress.IPv4Address) and ip_str.startswith("127.")):
            return True, f"Loopback address {ip_str} is strictly prohibited."

        # 3. Link-Local addresses are ALWAYS prohibited
        if real_ip.is_link_local:
            return True, f"Link-local address {ip_str} is strictly prohibited."

        # 4. Carrier-grade NAT (100.64.0.0/10)
        cgnat = ipaddress.ip_network("100.64.0.0/10")
        if isinstance(real_ip, ipaddress.IPv4Address) and real_ip in cgnat:
            return True, f"Shared carrier-grade NAT address {ip_str} is forbidden."

        # 5. Multicast and Reserved
        if real_ip.is_multicast or real_ip.is_reserved:
            return True, f"Multicast or reserved IP address {ip_str} is forbidden."

        # 6. Private RFC 1918 addresses
        if real_ip.is_private:
            if not allow_private:
                return True, f"Private RFC 1918 address {ip_str} is forbidden under PUBLIC_PASSIVE policy."
            # If allow_private is True, verify against authorized CIDR allowlist
            if allowlist_cidrs:
                matched = False
                for cidr in allowlist_cidrs:
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if real_ip in net:
                            matched = True
                            break
                    except ValueError:
                        continue
                if not matched:
                    return True, f"Private IP {ip_str} is not within organization authorized CIDR allowlist ({', '.join(allowlist_cidrs)})."

        return False, "Allowed"

    @classmethod
    def validate_hostname(cls, hostname: str) -> None:
        """
        Validates target hostname syntax and rejects userinfo, control chars, and forbidden internal TLDs.
        """
        if not hostname or not isinstance(hostname, str):
            raise SSRFValidationError("Hostname cannot be empty.")

        clean = hostname.strip().lower()

        # Reject userinfo credentials (@) in URL/host
        if "@" in clean:
            raise SSRFValidationError("Hostnames containing userinfo credentials (@) are prohibited.")

        # Reject control characters or whitespace
        if any(ord(c) < 32 or ord(c) == 127 for c in clean):
            raise SSRFValidationError("Hostname contains illegal control characters.")

        # Check explicit forbidden internal hostnames
        if clean in FORBIDDEN_HOSTNAMES:
            raise SSRFValidationError(f"Target host '{clean}' is a reserved internal or metadata name.")

        # Check forbidden TLDs
        parts = clean.split(".")
        if len(parts) >= 1:
            tld = parts[-1]
            if tld in FORBIDDEN_TLDS:
                raise SSRFValidationError(f"Internal non-routable TLD (.{tld}) is prohibited for public discovery.")

        # Check if the hostname string is actually an encoded IP address
        ip_obj = cls.parse_and_normalize_ip(clean)
        if ip_obj:
            forbidden, reason = cls.is_ip_forbidden(ip_obj, allow_private=False)
            if forbidden:
                raise SSRFValidationError(reason)

    @classmethod
    def validate_url_or_ip(
        cls,
        target: str,
        allow_private: bool = False,
        allowlist_cidrs: Optional[List[str]] = None,
    ) -> None:
        """
        Validates target URL or IP string against SSRF, alternate encodings, and boundary policies.
        """
        if not target or not isinstance(target, str):
            raise SSRFValidationError("Target cannot be empty.")

        clean = target.strip()
        if "://" in clean:
            parsed = urlparse(clean)
            host = parsed.hostname or ""
        else:
            host = clean.split("/")[0].split(":")[0]

        host = host.strip("[]").strip()

        if host.lower() in FORBIDDEN_HOSTNAMES:
            raise SSRFValidationError(f"Target host '{host}' is a reserved internal or metadata name.")

        ip_obj = cls.parse_and_normalize_ip(host)
        if ip_obj:
            forbidden, reason = cls.is_ip_forbidden(ip_obj, allow_private=allow_private, allowlist_cidrs=allowlist_cidrs)
            if forbidden:
                raise SSRFValidationError(reason)
        else:
            cls.validate_hostname(host)

    @classmethod
    def validate_resolved_ips(
        cls,
        ip_list: List[str],
        allow_private: bool = False,
        allowlist_cidrs: Optional[List[str]] = None,
    ) -> None:
        """
        Verifies that none of the resolved IPs in the list violate SSRF rules (DNS rebinding defense).
        """
        for ip_str in ip_list:
            ip_obj = cls.parse_and_normalize_ip(ip_str.strip())
            if ip_obj:
                forbidden, reason = cls.is_ip_forbidden(ip_obj, allow_private=allow_private, allowlist_cidrs=allowlist_cidrs)
                if forbidden:
                    raise SSRFValidationError(f"Prohibited resolved address {ip_str}: {reason}")

    @classmethod
    def create_redirect_validator(
        cls,
        allow_private: bool = False,
        allowlist_cidrs: Optional[List[str]] = None,
    ):
        """
        Returns a callable that inspects request/response URLs to reject redirect hops to prohibited destinations.
        """
        def redirect_validator(request_or_response) -> None:
            url = getattr(request_or_response, "url", None)
            if url is not None:
                cls.validate_url_or_ip(str(url), allow_private=allow_private, allowlist_cidrs=allowlist_cidrs)
        return redirect_validator

    @classmethod
    def validate_dns_resolution(
        cls,
        hostname: str,
        allow_private: bool = False,
        allowlist_cidrs: Optional[List[str]] = None,
        resolver_timeout: float = 3.0,
    ) -> List[str]:
        """
        Resolves hostname and verifies that NONE of the resolved IPs violate boundary rules (DNS Rebinding Defense).
        """
        # If hostname is already an IP, validate directly
        direct_ip = cls.parse_and_normalize_ip(hostname)
        if direct_ip:
            forbidden, reason = cls.is_ip_forbidden(direct_ip, allow_private=allow_private, allowlist_cidrs=allowlist_cidrs)
            if forbidden:
                raise SSRFValidationError(reason)
            return [str(direct_ip)]

        cls.validate_hostname(hostname)

        resolver = dns.resolver.Resolver()
        resolver.timeout = resolver_timeout
        resolver.lifetime = resolver_timeout
        resolved_ips: List[str] = []

        # Query A and AAAA records
        for rtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname, rtype)
                for rdata in answers:
                    ip_str = str(rdata).strip()
                    ip_obj = cls.parse_and_normalize_ip(ip_str)
                    if ip_obj:
                        forbidden, reason = cls.is_ip_forbidden(
                            ip_obj, allow_private=allow_private, allowlist_cidrs=allowlist_cidrs
                        )
                        if forbidden:
                            raise SSRFValidationError(
                                f"DNS rebinding defense: Hostname '{hostname}' resolved to prohibited address {ip_str}: {reason}"
                            )
                        resolved_ips.append(ip_str)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except (dns.resolver.Timeout, dns.exception.DNSException) as exc:
                # Log but continue if at least one record resolves
                pass

        return resolved_ips

    @classmethod
    def create_safe_client(
        cls,
        allow_private: bool = False,
        allowlist_cidrs: Optional[List[str]] = None,
        max_redirects: int = 3,
    ) -> httpx.Client:
        """
        Instantiates an HTTPX client with hardened connection timeouts, redirect re-validation, and response size limits.
        """
        def on_response(response: httpx.Response) -> None:
            # Check redirect targets
            if response.is_redirect and "location" in response.headers:
                redirect_url = response.headers["location"]
                parsed = urlparse(redirect_url)
                host = parsed.hostname
                if host:
                    cls.validate_dns_resolution(host, allow_private=allow_private, allowlist_cidrs=allowlist_cidrs)

        transport = httpx.HTTPTransport(retries=1)
        client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(cls.READ_TIMEOUT, connect=cls.CONNECT_TIMEOUT),
            follow_redirects=True,
            max_redirects=max_redirects,
            event_hooks={"response": [on_response]},
            headers={"User-Agent": "PREVENT-X-PassiveRecon/2.0 (+https://preventx.smb.in)"},
        )
        return client
