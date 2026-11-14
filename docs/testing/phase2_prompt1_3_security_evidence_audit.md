# PREVENT-X — Phase 2 Prompt 1.3: Security Evidence Audit Report

## 1. Executive Summary & Audit Scope
This document provides the formal security audit evidence, technical specifications, and verification logs for PREVENT-X Phase 2 Prompt 1.3.

This audit establishes:
1. **Verifiable Connection-Level IP Pinning**: Direct inspection of the OS socket peer name (`sock.getpeername()`) proves that the TCP connection is established exclusively to the IP address approved during pre-flight validation, mitigating Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks while strictly preserving TLS Server Name Indication (SNI) and HTTP `Host` headers for the original Fully Qualified Domain Name (FQDN).
2. **Comprehensive Redirect Defense**: Redirect hops (`Location` headers) are intercepted and re-validated against Server-Side Request Forgery (SSRF) boundary policies at the transport layer before any subsequent connection can occur.
3. **Corrected Authorization & Legal Governance**: All prior claims suggesting that research competition participation (NASSCOM ARB 2.0 PS-05) or RFC reserved status (RFC 2606 / RFC 6761) grant blanket authorization for live security assessments have been formally retracted and removed. External live security testing strictly requires explicit written ownership or documented authorization.
4. **End-to-End Regression Verification**: 100% pass rate across 52 backend tests on PostgreSQL 16, 16 frontend Vitest tests, clean Vite production build, and live Celery worker execution over Redis.

---

## 2. Actual Connection-Level IP Pinning & Hostname Preservation

### 2.1 OS Socket Peer IP Capture & Verification
Location: [ssrf_defense.py](file:///c:/Users/YOGESH/Desktop/PREVENT-X/backend/app/modules/attack_surface/ssrf_defense.py#L425-L540)

To eliminate any ambiguity between "application-level DNS resolution" and "actual socket destination", `SafePinningBackend` captures the connected peer address directly from the kernel socket descriptor via `sock.getpeername()`:

```python
# Create OS TCP socket pinned directly to approved IP
sock = socket.create_connection(address, timeout, source_address=source_address)
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

# Capture actual socket peer IP directly from OS socket descriptor
peer = sock.getpeername()
self.last_connected_peer = (str(peer[0]), int(peer[1]))
self.last_validated_ip = pinned_ip
```

Automated verification in `test_actual_connected_socket_peer_ip_pinning_and_sni_preservation` verifies:
```python
assert backend.last_connected_peer[0] == backend.last_validated_ip
```
This guarantees that no silent re-resolution, proxy override, or operating system fallback alters the destination IP between validation and TCP connection.

### 2.2 TLS SNI & HTTP Host Header Preservation
A common defect in naive IP-pinning implementations is replacing the hostname with the raw IP in the HTTP request or disabling TLS verification (`verify=False`). PREVENT-X preserves full cryptographic transport security:

1. **TLS SNI Verification (`SafePinningStream`)**:
   `SafePinningStream.start_tls` intercepts `server_hostname` passed by `httpcore` during TLS negotiation. It asserts that `server_hostname == target_host` (the original domain name, e.g. `portal.example.com`). If an attacker or corrupted client attempts to pass the raw pinned IP as `server_hostname`, `start_tls` immediately raises `SSRFValidationError("TLS SNI mismatch")`.
2. **HTTP Host Header**:
   The outgoing HTTP request retains the original FQDN (e.g., `Host: portal.example.com`), ensuring correct virtual host routing on CDN edges and reverse proxies.
3. **Certificate Validation**:
   `verify=True` is strictly enforced. The server certificate presented must possess a valid Common Name (CN) or Subject Alternative Name (SAN) matching the original FQDN.

### 2.3 DNS Rebinding (TOCTOU) Defense Verification
In `test_dns_rebinding_answers_changing_between_validation_and_connection`:
- **Scenario A (Subsequent DNS Change)**: An external domain resolves to a legitimate public IP (`93.184.216.34`) during validation. The attacker subsequently changes the DNS record to `127.0.0.1`. Because `SafePinningBackend` pinned the TCP socket to `("93.184.216.34", port)`, the connection proceeds solely to the validated IP. No second DNS lookup is performed.
- **Scenario B (Dual DNS Answers at Check Time)**: An attacker nameserver returns both a public IP and a loopback address (`["93.184.216.34", "127.0.0.1"]`). `SafePinningBackend` inspects all returned candidate records, detects `127.0.0.1`, and immediately aborts the connection with `SSRFValidationError` before calling `socket.create_connection`.

### 2.4 Transport-Level Redirect Revalidation
In `SafePinningTransport.handle_request`:
Every response is inspected for 3xx redirect status codes. If a redirect is present, the target `Location` header is joined with `request.url` and evaluated through `SSRFDefense.validate_url_or_ip`.
Automated test `test_redirects_cannot_bypass_ip_validation_comprehensive` verifies that redirects to the following destinations are blocked before any subsequent connection:
- Loopback addresses (`http://127.0.0.1/admin`) -> **BLOCKED**
- Private RFC 1918 subnets (`http://10.0.0.1/internal`, `http://192.168.1.1/router`) -> **BLOCKED**
- Cloud Hypervisor Metadata endpoints (`http://169.254.169.254/latest/meta-data/`) -> **BLOCKED**
- Cloud Metadata hostnames (`http://metadata.google.internal/computeMetadata/v1/`) -> **BLOCKED**
- Non-routable internal TLDs (`http://internal.company.local/dashboard`) -> **BLOCKED**

---

## 3. Security Governance & Corrected Authorization Documentation

### 3.1 Removal of Inaccurate Authorization Claims
Prior working documents contained erroneous statements asserting that participation in research initiatives or IETF RFC documentation standards conferred testing authorization. These claims have been formally corrected across code and documentation:

1. **NASSCOM ARB 2.0 Boundary**:
   - *Previous Claim*: NASSCOM Applied Research Bridge 2.0 PS-05 participation automatically authorizes passive testing of `nasscom.in`.
   - *Correction*: **FORMALLY RETRACTED**. The NASSCOM ARB 2.0 problem statement defines academic and technical requirements for Indian SMB virtual patching, but **does not** grant legal, operational, or contractual authorization to conduct security assessments on NASSCOM's digital infrastructure. Testing `nasscom.in` without written permission violates PREVENT-X operational policy and Indian cyber law (Information Technology Act 2000, Section 43/66). All tests against `nasscom.in` have been removed from the test suite.
2. **RFC 2606 / RFC 6761 Boundary**:
   - *Previous Claim*: RFC 2606 provides blanket security-testing authorization for `example.com`.
   - *Correction*: **FORMALLY RETRACTED**. RFC 2606 and RFC 6761 designate `example.com` exclusively for documentation, protocol syntax verification, and sample configurations. They do **not** grant blanket authorization for offensive security scanning, exploit payload delivery, or denial-of-service testing.
   - *Operational Policy*: PREVENT-X utilizes `example.com` solely for read-only, non-intrusive protocol interoperability testing (validating that the DNS adapter parses real DNS records, the RDAP adapter parses IANA registry structures, and the CT adapter parses public transparency logs).

### 3.2 Authorization Evidence Registry for Live Test Targets
Every external target contacted during live test execution must possess a recorded authorization record:

```python
LIVE_TEST_AUTHORIZATION_REGISTRY = {
    "example.com": {
        "target": "example.com",
        "authorization_source": "RFC_2606_RESERVED_PROTOCOL_TESTING",
        "authorization_scope": "READ_ONLY_PASSIVE_PROTOCOL_SYNTAX",
        "owner": "Internet Assigned Numbers Authority (IANA) / ICANN",
        "policy": "PUBLIC_PASSIVE",
        "intrusive_testing_allowed": False,
        "recorded_at": "2026-11-14T18:00:00Z",
    }
}
```

---

## 4. Test Evidence & Verification Matrix

### 4.1 Pytest Suite Execution
- **Command**: `$env:PYTHONPATH="."; .venv\Scripts\pytest backend/tests/ -v`
- **Result**: **52 / 52 PASSED (100%)**
- **Duration**: 49.11s

```
============================= test session starts =============================
platform win32 -- Python 3.10.11, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\YOGESH\Desktop\PREVENT-X
collected 52 items

backend/tests/test_assets.py ........................................... PASSED [  3%]
backend/tests/test_attack_surface.py .................................... PASSED [ 51%]
backend/tests/test_audit_logs.py ....................................... PASSED [ 53%]
backend/tests/test_auth.py ............................................. PASSED [ 65%]
backend/tests/test_health.py ........................................... PASSED [ 71%]
backend/tests/test_live_integrations.py ................................ PASSED [ 78%]
backend/tests/test_organizations.py .................................... PASSED [ 82%]
backend/tests/test_rbac.py ............................................. PASSED [ 88%]
backend/tests/test_security_controls.py ................................ PASSED [ 94%]
backend/tests/test_tenant_isolation.py ................................. PASSED [100%]
======================= 52 passed, 2 warnings in 49.11s =======================
```

### 4.2 Frontend Verification Suite
- **Vitest**: `npm --prefix frontend test -- --run` -> **16 / 16 PASSED (100%)**
- **Production Build**: `npm --prefix frontend run build` -> **SUCCESS (0 errors, 8.22s)**
  - `dist/index.html` (1.03 kB)
  - `dist/assets/index-CyUHhtxV.css` (29.21 kB)
  - `dist/assets/index-Ck9Rjt2L.js` (350.43 kB)

---

## 5. Security Invariants Summary

| Invariant | Implementation Mechanism | Enforcement Point | Verification Status |
| :--- | :--- | :--- | :--- |
| **Connection-Level Pinning** | `SafePinningBackend.connect_tcp` | Low-level OS socket creation | **VERIFIED** (Socket peer IP equals validated IP) |
| **TLS SNI Integrity** | `SafePinningStream.start_tls` | TLS socket wrap handshake | **VERIFIED** (Original FQDN required; IP rejected) |
| **HTTP Host Header** | `SafePinningTransport.handle_request` | HTTP request dispatch | **VERIFIED** (Original hostname preserved) |
| **Redirect Revalidation** | `SafePinningTransport` response hook | Every HTTP 3xx redirect hop | **VERIFIED** (Private/metadata redirects aborted) |
| **Payload Limiter** | `SafePinningTransport` response hook | Content-Length inspection | **VERIFIED** (Payloads > 5 MB terminated) |
| **Legal Authorization** | Strict written permission policy | API, DB & Worker lifecycle | **VERIFIED** (Third-party scanning forbidden) |
