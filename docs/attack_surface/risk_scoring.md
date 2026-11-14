# PREVENT-X — Deterministic Exposure Risk Scoring Model

## 1. Mathematical Formulation & Normalization Guarantee

PREVENT-X implements an **Explainable, Deterministic Exposure Risk Score** strictly calibrated on a 0.0 to 100.0 scale.

Unlike arbitrary vulnerability scoring systems or non-deterministic heuristic models, the PREVENT-X exposure score is calculated using exact, normalized, reproducible mathematical rules. 

$$
\text{Total Exposure Score} = \sum_{i=1}^{6} W_i \times S_i \quad \text{where} \quad \sum_{i=1}^{6} W_i = 100.0
$$

Where:
- $W_i$: Maximum weight allotted to factor $i$. The weights sum mathematically to **exactly 100.0**.
- $S_i$: Normalized factor contribution calculated from empirical telemetry ($0.0 \le S_i \le 1.0$).
- Strictly bounded: $0.0 \le \text{Total Exposure Score} \le 100.0$ without artificial truncation or capping.

---

## 2. Factor Weights & Evaluation Framework

| Factor $i$ | Factor Name & Category | Max Weight ($W_i$) | Nature & Distinction | Evaluation Rules |
| :---: | :--- | :---: | :--- | :--- |
| **1** | **Perimeter Breadth & Sprawl**<br>`ATTACK_SURFACE_EXPOSURE` | **20.0** | **Exposure Indicator**<br>(Not proof of compromise) | - $\le 1$ domain: $0.0$<br>- $2-5$ subdomains: $5.0$<br>- $6-20$ subdomains: $12.0$<br>- $>20$ subdomains: $20.0$ |
| **2** | **Certificate Scope Posture**<br>`CERTIFICATE_TLS_POSTURE` | **15.0** | **Architectural Indicator**<br>(Not a vulnerability) | - Wildcard certificate (`*.`): $15.0$ (expands blast radius across hostnames)<br>- Scoped host certificates: $0.0$ |
| **3** | **Service Availability (TLS)**<br>`CERTIFICATE_TLS_POSTURE` | **20.0** | **Availability / Trust Breakdown**<br>(Not code exploitability) | - Expired active TLS certificate: $20.0$<br>- Expiring within 14 days: $10.0$<br>- Expiring within 30 days: $5.0$<br>- Valid certificate: $0.0$ |
| **4** | **Email Spoofing Defense**<br>`EMAIL_SECURITY_POSTURE` | **20.0** | **Brand Impersonation Defense**<br>(Distinct from app exposure) | - Missing both SPF and DMARC: $20.0$<br>- Missing DMARC only: $10.0$<br>- Missing SPF only: $10.0$<br>- Both configured: $0.0$ |
| **5** | **Resource Takeover Indicators**<br>`RESOURCE_TAKEOVER_INDICATOR` | **15.0** | **Cloud Tenancy Hygiene**<br>(Differentiates verified vs unverified) | - Verified unclaimed external resource (NXDOMAIN): $15.0$<br>- Unverified potential dangling CNAME: $7.5$<br>- No dangling pointers: $0.0$ |
| **6** | **Network Topology Exposure**<br>`DNS_CONFIGURATION_WEAKNESS` | **10.0** | **Information Leakage**<br>(Internal network numbering) | - RFC 1918 private IP exposed in public DNS: $10.0$<br>- Distributed footprint ($>10$ public IPs): $5.0$<br>- Standard footprint: $0.0$ |
| **SUM** | **Total Factor Capacity** | **100.0** | **Normalized Scale** | **Strictly bounded 0.0 to 100.0** |

---

## 3. Core Architectural Distinctions

### Exposure Indicators vs. Confirmed Vulnerabilities
A wide attack surface (e.g., 25 subdomains) increases maintenance overhead and discovery surface, but does **not** indicate that any service is exploited or vulnerable. All factors explicitly set `is_vulnerability: false` to ensure executive reports never conflate perimeter visibility with vulnerability presence.

### Wildcard Certificates as Architectural Posture
Wildcard certificates (`*.company.com`) are standard operational conveniences. However, if any single subdomain server is compromised, the attacker obtains private keys valid for all other sibling services. This is treated as a blast-radius risk factor (15.0 pts), not a code defect.

### Availability Disruptions vs. Exploitability
An expired certificate disrupts TLS handshakes and prevents legitimate users from accessing business applications. While critical for business continuity, it is classified under service availability, not remote code execution or authentication bypass.

### Email Security Posture vs. Application Exposure
Email authentication (SPF, DKIM, DMARC) protects domain reputation and prevents phishing impersonation. It is decoupled from web application vulnerabilities and evaluated under `EMAIL_SECURITY_POSTURE`.

### Dangling CNAME Verification Stages
PREVENT-X never claims external resources or performs invasive actions. It categorizes CNAME indicators into:
- `POTENTIAL_DANGLING_CNAME`: DNS alias to known cloud services without status check.
- `UNVERIFIED_RESOURCE`: CNAME alias detected; verification pending.
- `VERIFIED_UNCLAIMED_RESOURCE`: Target resolves to NXDOMAIN or unallocated host (15.0 pts).
- `CONFIRMED_TAKEOVER`: Requires human analyst validation; never automatically claimed.

---

## 4. Exposure Level Classification

| Score Range | Risk Level | Operational Meaning |
| :---: | :---: | :--- |
| **$75.0 - 100.0$** | **CRITICAL** | Severe exposure posture with verified unclaimed cloud resources, expired TLS certificates, or absent email authentication. Immediate remediation advised. |
| **$50.0 - 74.9$** | **HIGH** | Notable attack surface exposure requiring prompt remediation of email authentication or dangling cloud pointers. |
| **$20.0 - 49.9$** | **MEDIUM** | Moderate external footprint with routine subdomains and active certificate maintenance. |
| **$0.0 - 19.9$** | **LOW** | Minimal exposure perimeter with hardened email security and clean DNS records. |

---

## 5. Structured Factor Evidence & Confidence Reporting

Every evaluation generates a structured JSON telemetry payload recorded in `discovery_jobs.risk_score_details`. Each factor dictionary includes:
- `name`: Human-readable title
- `factor_key`: Unique factor identifier
- `category`: One of the 5 standardized finding categories
- `score`: Actual awarded score
- `max_weight`: Weight allotment
- `impact`: Severity classification (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `confidence`: Confidence level ($0.0$ to $1.0$) based on data freshness and verification
- `evidence_quality`: Qualitative rating (`HIGH`, `MEDIUM`, `LOW`)
- `is_vulnerability`: Boolean flag explicitly marked `False`
- `description`: Plain-English explanation of observed facts and operational context.
