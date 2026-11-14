"""
PREVENT-X Controlled Active Service Discovery Scanner
Executes safe TCP reachability checks, restricted port profile scanning,
safe protocol handshakes, TLS certificate metadata collection, and banner analysis.
Strictly non-destructive: no exploitation, fuzzing, brute force, or stealth/raw sockets.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json
import logging
import re
import socket
import ssl
import time
from typing import Optional, List, Dict, Any, Callable

from cryptography import x509

logger = logging.getLogger("preventx.scanner.active")

# Standard IANA port to service name mapping
STANDARD_PORT_NAMES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
}

HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000}
TLS_PORTS = {443, 8443, 993, 995, 465}
BANNER_PORTS = {21, 22, 25, 110, 143, 587}


@dataclass
class PortScanResult:
    port: int
    protocol: str = "tcp"
    state: str = "CLOSED"  # OPEN, CLOSED, FILTERED
    service_name: str = "unknown"
    confidence: str = "INFERRED_SERVICE"  # CONFIRMED_OBSERVATION or INFERRED_SERVICE
    banner: Optional[str] = None
    tls_metadata: Optional[Dict[str, Any]] = None
    http_metadata: Optional[Dict[str, Any]] = None
    raw_evidence: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ActiveScanner:
    """Controlled, non-destructive active network service discovery engine."""

    def __init__(
        self,
        max_concurrency: int = 5,
        connect_timeout: float = 2.0,
        rate_limit_delay_seconds: float = 0.05,
    ):
        self.max_concurrency = max(1, min(max_concurrency, 10))
        self.connect_timeout = max(0.5, min(connect_timeout, 5.0))
        self.rate_limit_delay_seconds = max(0.01, min(rate_limit_delay_seconds, 1.0))

    def scan_ports(
        self,
        target_ip: str,
        target_host: str,
        ports: List[int],
        cancellation_check: Optional[Callable[[], bool]] = None,
        progress_callback: Optional[Callable[[int, int, List[PortScanResult]], None]] = None,
    ) -> List[PortScanResult]:
        """
        Executes controlled port scanning across the authorized target and ports.
        Enforces concurrency limits, rate limiting delays, and periodic cancellation checks.
        """
        results: List[PortScanResult] = []
        total_ports = len(ports)
        scanned_count = 0

        # Process in concurrency batches to allow clean cancellation checkpoints
        batch_size = self.max_concurrency

        for i in range(0, total_ports, batch_size):
            if cancellation_check and cancellation_check():
                logger.info(f"Active scan cancelled by user/system. Terminating before port batch {i}.")
                break

            batch = ports[i : i + batch_size]
            batch_results: List[PortScanResult] = []

            with ThreadPoolExecutor(max_workers=len(batch)) as executor:
                futures = {
                    executor.submit(self._probe_single_port, target_ip, target_host, port): port
                    for port in batch
                }
                for future in as_completed(futures):
                    port_res = future.result()
                    batch_results.append(port_res)

            # Sort batch results by port
            batch_results.sort(key=lambda r: r.port)
            results.extend(batch_results)
            scanned_count += len(batch)

            if progress_callback:
                progress_callback(scanned_count, total_ports, results)

            # Gentle rate limiting between probe batches
            if i + batch_size < total_ports:
                time.sleep(self.rate_limit_delay_seconds)

        results.sort(key=lambda r: r.port)
        return results

    def _probe_single_port(self, target_ip: str, target_host: str, port: int) -> PortScanResult:
        """
        Probes a single TCP port with reachability check and safe protocol handshakes.
        """
        inferred_name = STANDARD_PORT_NAMES.get(port, "unknown")

        # 1. TCP Reachability Check
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.connect_timeout)
        is_open = False
        state = "CLOSED"

        try:
            s.connect((target_ip, port))
            is_open = True
            state = "OPEN"
        except socket.timeout:
            state = "FILTERED"
        except (ConnectionRefusedError, OSError):
            state = "CLOSED"
        finally:
            try:
                s.close()
            except Exception:
                pass

        if not is_open:
            return PortScanResult(
                port=port,
                state=state,
                service_name=inferred_name,
                confidence="INFERRED_SERVICE",
            )

        # 2. Port is OPEN - perform safe protocol analysis
        service_name = inferred_name
        confidence = "INFERRED_SERVICE"
        banner: Optional[str] = None
        tls_meta: Optional[Dict[str, Any]] = None
        http_meta: Optional[Dict[str, Any]] = None
        raw_evidence: Dict[str, Any] = {"tcp_connect": "SUCCESS"}

        # A. TLS Inspection for TLS-designated ports or port 443/8443
        if port in TLS_PORTS or port == 443:
            tls_meta = self._extract_tls_metadata(target_ip, target_host, port)
            if tls_meta:
                service_name = "https" if port in (443, 8443) else inferred_name
                confidence = "CONFIRMED_OBSERVATION"
                raw_evidence["tls_handshake"] = "SUCCESS"

            # Check for HTTPS endpoint metadata
            if port in (443, 8443):
                http_meta = self._probe_http(target_ip, target_host, port, is_tls=True)
                if http_meta and http_meta.get("status_code") is not None:
                    confidence = "CONFIRMED_OBSERVATION"
                    raw_evidence["http_probe"] = "SUCCESS"

        # B. HTTP Inspection for standard HTTP ports
        elif port in HTTP_PORTS or port == 80:
            http_meta = self._probe_http(target_ip, target_host, port, is_tls=False)
            if http_meta and http_meta.get("status_code") is not None:
                service_name = "http"
                confidence = "CONFIRMED_OBSERVATION"
                raw_evidence["http_probe"] = "SUCCESS"

        # C. Banner Grabbing for greeting-first protocols (SSH, FTP, SMTP, POP3, IMAP)
        elif port in BANNER_PORTS:
            banner = self._grab_banner(target_ip, port)
            if banner:
                confidence = "CONFIRMED_OBSERVATION"
                raw_evidence["banner_grab"] = "SUCCESS"
                if "ssh" in banner.lower():
                    service_name = "ssh"
                elif "ftp" in banner.lower():
                    service_name = "ftp"
                elif "smtp" in banner.lower() or "esmtp" in banner.lower():
                    service_name = "smtp"
                elif "pop" in banner.lower():
                    service_name = "pop3"
                elif "imap" in banner.lower():
                    service_name = "imap"

        # D. Generic Safe Handshake Probe for unknown/custom ports
        else:
            # First try quick banner read
            banner = self._grab_banner(target_ip, port, timeout=1.0)
            if banner:
                confidence = "CONFIRMED_OBSERVATION"
                raw_evidence["banner_grab"] = "SUCCESS"
                if "ssh" in banner.lower():
                    service_name = "ssh"
                elif "ftp" in banner.lower():
                    service_name = "ftp"
                elif "smtp" in banner.lower():
                    service_name = "smtp"
            else:
                # Try lightweight HTTP probe
                http_meta = self._probe_http(target_ip, target_host, port, is_tls=False, timeout=1.0)
                if http_meta and http_meta.get("status_code") is not None:
                    service_name = "http"
                    confidence = "CONFIRMED_OBSERVATION"
                    raw_evidence["http_probe"] = "SUCCESS"
                else:
                    # Try TLS
                    tls_meta = self._extract_tls_metadata(target_ip, target_host, port, timeout=1.0)
                    if tls_meta:
                        service_name = "ssl/tls"
                        confidence = "CONFIRMED_OBSERVATION"
                        raw_evidence["tls_handshake"] = "SUCCESS"

        return PortScanResult(
            port=port,
            state="OPEN",
            service_name=service_name,
            confidence=confidence,
            banner=banner,
            tls_metadata=tls_meta,
            http_metadata=http_meta,
            raw_evidence=raw_evidence,
        )

    def _extract_tls_metadata(
        self,
        target_ip: str,
        target_host: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Safely performs TLS handshake and extracts certificate metadata."""
        effective_timeout = timeout or self.connect_timeout
        raw_sock = None
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(effective_timeout)
            raw_sock.connect((target_ip, port))

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # Use target_host for SNI if it is a valid domain name
            sni_host = None
            if target_host and not target_host.replace(".", "").isdigit():
                sni_host = target_host

            with ctx.wrap_socket(raw_sock, server_hostname=sni_host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cipher_info = ssock.cipher()
                if not cert_der:
                    return None

                cert = x509.load_der_x509_certificate(cert_der)

                # Subject CN
                cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                subject_cn = cns[0].value if cns else None

                # SANs
                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(x) for x in san_ext.value.get_values_for_type(x509.DNSName)]
                except Exception:
                    pass

                # Issuer
                issuer_cns = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                issuer_orgs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                issuer_name = issuer_cns[0].value if issuer_cns else (issuer_orgs[0].value if issuer_orgs else None)

                now_utc = datetime.now(timezone.utc)
                valid_from = cert.not_valid_before_utc
                valid_to = cert.not_valid_after_utc
                days_remaining = (valid_to - now_utc).days

                return {
                    "subject_cn": subject_cn,
                    "san_list": sans,
                    "issuer": issuer_name,
                    "valid_from": valid_from.isoformat(),
                    "valid_to": valid_to.isoformat(),
                    "days_remaining": days_remaining,
                    "is_expired": days_remaining < 0,
                    "cipher_name": cipher_info[0] if cipher_info else None,
                    "tls_version": cipher_info[1] if cipher_info else None,
                }
        except Exception as e:
            logger.debug(f"TLS inspection failed for {target_ip}:{port}: {e}")
            return None
        finally:
            if raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def _probe_http(
        self,
        target_ip: str,
        target_host: str,
        port: int,
        is_tls: bool = False,
        timeout: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Safely probes HTTP endpoint using minimal non-destructive GET request."""
        effective_timeout = timeout or self.connect_timeout
        raw_sock = None
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(effective_timeout)
            raw_sock.connect((target_ip, port))

            sock = raw_sock
            if is_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sni_host = target_host if target_host and not target_host.replace(".", "").isdigit() else None
                sock = ctx.wrap_socket(raw_sock, server_hostname=sni_host)

            with sock:
                host_header = target_host or target_ip
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"User-Agent: PREVENT-X-Active-Scanner/1.0 (Authorized Audit)\r\n"
                    f"Accept: text/html,*/*\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(req.encode("utf-8"))

                data = b""
                while len(data) < 8192:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    data += chunk

                if not data:
                    return None

                response_text = data.decode("latin-1", errors="replace")
                lines = response_text.split("\r\n")
                status_line = lines[0] if lines else ""
                status_code = None
                if status_line.startswith("HTTP/"):
                    parts = status_line.split(" ", 2)
                    if len(parts) >= 2 and parts[1].isdigit():
                        status_code = int(parts[1])

                server_header = None
                location_header = None
                for line in lines[1:]:
                    if not line:
                        break
                    if ":" in line:
                        hname, hval = line.split(":", 1)
                        hname_lower = hname.strip().lower()
                        if hname_lower == "server":
                            server_header = hval.strip()
                        elif hname_lower == "location":
                            location_header = hval.strip()

                title = None
                title_match = re.search(r"<title[^>]*>(.*?)</title>", response_text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    title = " ".join(title_match.group(1).split())[:200]

                return {
                    "status_code": status_code,
                    "server_header": server_header,
                    "redirect_url": location_header,
                    "title": title,
                }
        except Exception as e:
            logger.debug(f"HTTP probe failed for {target_ip}:{port}: {e}")
            return None
        finally:
            if raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def _grab_banner(
        self,
        target_ip: str,
        port: int,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Safely reads server greeting banner for banner-speaking protocols."""
        effective_timeout = timeout or min(1.5, self.connect_timeout)
        try:
            with socket.create_connection((target_ip, port), timeout=effective_timeout) as s:
                s.settimeout(effective_timeout)
                data = s.recv(256)
                if data:
                    clean = "".join(c for c in data.decode("latin-1", errors="replace") if 32 <= ord(c) < 127).strip()
                    return clean[:256] if clean else None
        except Exception:
            pass
        return None

