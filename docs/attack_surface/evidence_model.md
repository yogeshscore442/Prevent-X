# PREVENT-X — Attack Surface Evidence & Findings Model

## 1. Evidence Model Philosophy

The **Evidence Model** in PREVENT-X bridges raw external telemetry with actionable security intelligence.

Findings are never synthetic alerts. Every `ExposureFinding` stored in the database is derived directly from empirical, reproducible signals collected during passive reconnaissance.

---

## 2. Finding Categories

| Category | Description | Primary Sources | Default Severity |
| :--- | :--- | :--- | :--- |
| `PUBLIC_DOMAIN` | Verification that the primary apex domain is exposed and routable on the public web. | DNS, RDAP | `INFO` |
| `DISCOVERED_SUBDOMAIN` | Active external subdomains verified via Certificate Transparency logs. | `crt.sh` | `LOW` |
| `PUBLIC_IP` | Public IPv4/IPv6 endpoints mapped to domain records. | DNS (`A`, `AAAA`) | `INFO` |
| `DNS_CONFIGURATION` | Missing email defenses (SPF, DMARC), internal IP leakages, or dangling CNAME pointers. | DNS (`TXT`, `CNAME`) | `HIGH` |
| `CERTIFICATE_EXPOSURE`| Expired TLS certificates, imminent expiration, or wildcard certificate scope. | Certificate Transparency | `MEDIUM` / `CRITICAL` |
| `UNKNOWN_ASSET_RELATIONSHIP` | Subdomains actively discovered that are not cataloged in the tenant's managed asset inventory. | Cross-reference | `MEDIUM` |

---

## 3. Finding Structure & Evidence JSON

Each finding stored in `exposure_findings` includes:
- `target`: The specific domain, subdomain, or IP address exposed.
- `finding_category`: Standardized taxonomy enum.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
- `confidence`: `HIGH`, `MEDIUM`, `LOW`.
- `title`: Short human-readable summary.
- `description`: Detailed explanation of the exposure and threat implications.
- `evidence`: JSON-encoded payload containing raw technical telemetry (e.g. DNS response text, certificate timestamps, registrar metadata).
- `discovery_source`: `CERTIFICATE_TRANSPARENCY`, `DNS_RESOLVER`, `RDAP`, `PASSIVE_RECON`.
- `first_observed_at` & `last_observed_at`: Precise observation timelines.
- `current_status`: `ACTIVE`.

### Example Evidence Payloads

#### Missing SPF Record (High Severity)
```json
{
  "domain": "smbclient.in",
  "checked_records": ["TXT"],
  "dns_status": "NO_SPF_FOUND"
}
```

#### Dangling CNAME Candidate (High Severity)
```json
{
  "cname_target": "custom-portal.s3.amazonaws.com",
  "domain": "files.smbclient.in"
}
```

#### Expired TLS Certificate (Critical Severity)
```json
{
  "common_name": "legacy-api.smbclient.in",
  "issuer": "Let's Encrypt Authority X3",
  "not_after": "2025-11-01T00:00:00Z"
}
```
