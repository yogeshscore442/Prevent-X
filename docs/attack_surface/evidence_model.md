# PREVENT-X — Attack Surface Evidence & Findings Model

## 1. Evidence Model Philosophy

The **Evidence Model** in PREVENT-X bridges raw external telemetry with actionable, explainable security intelligence.

Findings are never synthetic alerts or fabricated vulnerabilities. Every `ExposureFinding` stored in the database is derived directly from empirical, reproducible signals collected during passive reconnaissance.

---

## 2. Standardized Finding Categories

In accordance with Prompt 1.1 requirements, PREVENT-X organizes findings into 5 clear, objective categories:

| Category | Description | Primary Sources | Typical Severity |
| :--- | :--- | :--- | :--- |
| `ATTACK_SURFACE_EXPOSURE` | Observed perimeter breadth, discovered domains/subdomains, public IP mappings, and uncatalogued asset relationships. | CT Logs, DNS (`A`, `AAAA`) | `INFO` / `LOW` / `MEDIUM` |
| `EMAIL_SECURITY_POSTURE` | Anti-spoofing and brand impersonation posture (SPF, DMARC policies). Evaluated separately from web application flaws. | DNS (`TXT`) | `MEDIUM` / `HIGH` |
| `CERTIFICATE_TLS_POSTURE` | Expired TLS certificates, imminent validity expirations, or wildcard certificates expanding blast radius. | CT Logs, X.509 telemetry | `INFO` / `HIGH` / `CRITICAL` |
| `DNS_CONFIGURATION_WEAKNESS` | RFC 1918 private IP leakage in public records, missing reverse DNS, or DNS zone delegation issues. | DNS Resolvers | `LOW` / `HIGH` |
| `RESOURCE_TAKEOVER_INDICATOR` | CNAME pointers to third-party cloud tenancies (AWS S3, Azure, GitHub Pages, Heroku, etc.) with verified unclaimed or unverified status. | DNS (`CNAME`) | `MEDIUM` / `HIGH` |

---

## 3. Evidence Nature Taxonomy

To ensure operational accuracy and eliminate confusion between observed facts and verified flaws, every finding is tagged with an explicit `evidence_nature`:

1. `OBSERVED_FACT`: An empirical infrastructure attribute observed during reconnaissance (e.g. public IP address, registered nameserver, wildcard certificate). It is an architectural fact, not a defect.
2. `POTENTIAL_WEAKNESS`: A configuration setting that weakens defense-in-depth but does not guarantee exploitative impact (e.g., missing DMARC enforcement policy, wildcard TLS certificate).
3. `VERIFIED_ISSUE`: A verified technical deficiency directly confirmed through deterministic evidence (e.g., expired TLS certificate causing browser disruption, RFC 1918 internal IP leak in public DNS).
4. `UNVERIFIED_FINDING`: A heuristic observation requiring further validation (e.g., CNAME pointer pointing to an external cloud provider that is not yet verified as unclaimed).

---

## 4. Dangling CNAME & Resource Takeover Classification

PREVENT-X adopts a strictly non-intrusive approach to cloud resource takeover indicators. It **never** attempts to claim, register, or exploit external resources.

Takeover indicators advance through clear verification states:

| State | Definition | Operational Handling |
| :--- | :--- | :--- |
| `POTENTIAL_DANGLING_CNAME` | Domain possesses a CNAME pointing to a known cloud hosting pattern. | Flagged as unverified finding. |
| `UNVERIFIED_RESOURCE` | The resource alias is observed, but target host resolution is indeterminate or resolving. | Assigned 7.5 risk points (`MEDIUM` quality). |
| `VERIFIED_UNCLAIMED_RESOURCE` | Non-intrusive DNS resolution check confirms the target domain yields `NXDOMAIN` (unallocated cloud tenant). | Assigned 15.0 risk points (`HIGH` quality, verified). |
| `CONFIRMED_TAKEOVER` | Confirmed through manual verification; never automatically triggered. | Requires human SOC analyst review. |

---

## 5. Structured Finding Record Schema

Each record in `exposure_findings` includes:
- `target`: Exposed FQDN or IP address.
- `finding_category`: Standardized finding category enum.
- `evidence_nature`: `OBSERVED_FACT`, `POTENTIAL_WEAKNESS`, `VERIFIED_ISSUE`, or `UNVERIFIED_FINDING`.
- `verification_status`: `POTENTIAL_DANGLING_CNAME`, `UNVERIFIED_RESOURCE`, `VERIFIED_UNCLAIMED_RESOURCE`, or `CONFIRMED_TAKEOVER`.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `confidence`: `HIGH`, `MEDIUM`, `LOW`.
- `title`: Human-readable summary title.
- `description`: Plain-English explanation of observed facts and operational context.
- `evidence`: JSON-encoded technical telemetry payload (raw records, certificates, timestamps).
- `discovery_source`: `CERTIFICATE_TRANSPARENCY`, `DNS_RESOLVER`, `RDAP`, `PASSIVE_RECON`.
- `first_observed_at` & `last_observed_at`: Timestamps in UTC.
- `current_status`: `ACTIVE`.
