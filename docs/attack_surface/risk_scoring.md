# PREVENT-X — Deterministic Exposure Risk Scoring Model

## 1. Mathematical Formulation

PREVENT-X implements an **Explainable, Deterministic Exposure Risk Score** calibrated on a 0.0 to 100.0 scale.

Unlike opaque machine learning models or arbitrary severity numbers, the PREVENT-X exposure score is calculated using explicit, reproducible mathematical rules. It does **not** estimate CVE vulnerability severity (which belongs to Phase 3 Vulnerability Mapping), but rather measures the empirical external attack exposure surface of the SMB.

$$
\text{Total Exposure Score} = \min\left(100.0, \sum_{i=1}^{6} W_i \times S_i\right)
$$

Where:
- $W_i$: Maximum weight allotted to factor $i$.
- $S_i$: Normalized factor score calculated from observed telemetry ($0.0 \le S_i \le 1.0$).

---

## 2. Risk Factors and Weight Breakdown

| Factor $i$ | Factor Name | Max Weight ($W_i$) | Evaluation Criteria |
| :---: | :--- | :---: | :--- |
| **1** | **Subdomain Sprawl** | **25.0** | - $\le 1$ domain: $0.0$<br>- $2-5$ subdomains: $5.0$<br>- $6-20$ subdomains: $15.0$<br>- $>20$ subdomains: $25.0$ |
| **2** | **Wildcard TLS Certificates** | **15.0** | - Wildcard present: $15.0$ (blast radius expansion across all hostnames)<br>- No wildcard: $0.0$ |
| **3** | **Certificate Validity** | **20.0** | - Expired certificate observed: $20.0$<br>- Expiring within 30 days: $10.0$<br>- Valid certificate: $0.0$ |
| **4** | **Email Security Posture** | **20.0** | - Missing both SPF and DMARC: $20.0$<br>- Missing DMARC only: $10.0$<br>- Missing SPF only: $10.0$<br>- Both configured: $0.0$ |
| **5** | **Dangling CNAME Takeover** | **15.0** | - Dangling cloud CNAME detected: $15.0$<br>- No dangling pointers: $0.0$ |
| **6** | **Infrastructure & IP Leakage** | **10.0** | - Internal RFC 1918 / loopback leaked in public DNS: $10.0$<br>- $>5$ distinct public IPs: $5.0$<br>- Standard footprint: $0.0$ |

---

## 3. Exposure Level Classification

| Score Range | Risk Level | Operational Meaning |
| :---: | :---: | :--- |
| **$75.0 - 100.0$** | **CRITICAL** | Severe exposure posture with active takeover candidates, expired certificates, or widespread email spoofing risks. Immediate remediation required. |
| **$50.0 - 74.9$** | **HIGH** | Notable attack surface exposures requiring remediation of email authentication or dangling cloud pointers. |
| **$20.0 - 49.9$** | **MEDIUM** | Moderate external footprint with routine subdomains and standard certificate lifecycles. |
| **$0.0 - 19.9$** | **LOW** | Minimal exposure perimeter with hardened email security and clean DNS records. |

---

## 4. Auditability & Explanations

Every calculation produces a structured JSON breakdown stored in `discovery_jobs.risk_score_details`.
Each factor record includes:
- `name`: Human-readable title
- `factor_key`: Unique identifier
- `score`: Actual score awarded
- `max_weight`: Weight capacity
- `impact`: Severity level (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `description`: Plain-English explanation of why the score was assigned.
