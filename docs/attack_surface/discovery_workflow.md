# PREVENT-X — Attack Surface Discovery Workflow

## 1. Complete Step-by-Step Discovery Lifecycle

The attack surface discovery pipeline moves through a deterministic state machine managed by `DiscoveryManager`.

```mermaid
flowchart TD
    A[Client Submits Job] --> B[Scope & SSRF Validation]
    B -->|Validation Failed| C[Reject HTTP 400 / 403 / 404]
    B -->|Validation Passed| D[Persist Job: QUEUED]
    D --> E[Celery Dispatches Task via Redis]
    E --> F[Stage 1: VALIDATION (10%)]
    F --> G[Stage 2: CERTIFICATE_TRANSPARENCY (30%)]
    G --> H[Stage 3: DNS_ENUMERATION (60%)]
    H --> I[Stage 4: RDAP_ANALYSIS (80%)]
    I --> J[Stage 5: RISK_EVALUATION (95%)]
    J --> K[Persist Findings & Telemetry]
    K --> L[State: COMPLETED / PARTIALLY_COMPLETED (100%)]
```

---

## 2. Detailed Execution Stages

### Stage 1: Validation (10% Progress)
- **Objective**: Ensure that runtime boundaries have not been tampered with and target remains authorized.
- **Actions**:
  1. Verifies asset belongs to active tenant organization.
  2. Verifies `is_in_scope == True`.
  3. Verifies `authorization_confirmed == True`.
  4. Checks if user flagged job for cancellation.

### Stage 2: Certificate Transparency Logs (30% Progress)
- **Objective**: Uncover external subdomains and wildcards without sending direct network packets to the customer's hosts.
- **Provider**: `CertificateTransparencyAdapter` querying `crt.sh`.
- **Telemetry Collected**:
  - `common_name` and multi-line Subject Alternative Names (`SANs`).
  - Issuer CA name and serial number.
  - Validity range (`not_before`, `not_after`).
  - Wildcard detection (`*.domain`).
  - Deduplicated list of discovered subdomains matching the target scope.
- **Resilience**: If `crt.sh` experiences HTTP 502/504 or network timeout, the stage records a warning in `stage_errors` and proceeds to DNS rather than failing the job.

### Stage 3: DNS Enumeration (60% Progress)
- **Objective**: Resolve records and inspect core email security and cloud delegation pointers.
- **Provider**: `DNSIntelligenceAdapter` using `dnspython`.
- **Telemetry Collected**:
  - `A` and `AAAA` records: extracted and categorized into public routable vs private/RFC 1918 addresses.
  - `CNAME` records: analyzed for dangling third-party cloud hosting patterns (e.g., `s3.amazonaws.com`, `azurewebsites.net`, `github.io`, `herokuapp.com`).
  - `MX` and `NS` records: identifies mail routing and authoritative nameservers.
  - `TXT` records: parses SPF (`v=spf1 ...`) on domain apex.
  - DMARC record: queries `_dmarc.<domain>` for `v=DMARC1 ...`.
- **Target Breadth**: Queries target domain apex plus up to 15 top discovered subdomains.

### Stage 4: RDAP Analysis (80% Progress)
- **Objective**: Retrieve authoritative registrar information and domain registration timelines while guaranteeing privacy.
- **Provider**: `RDAPAdapter` querying `rdap.org`.
- **Privacy Preservation**:
  - Personal contact details (registrant names, individual emails, telephone numbers, postal addresses) are strictly redacted.
  - Only institutional data is preserved: registrar name, whois server, registration date, expiration date, and nameservers.
- **Resilience**: If RDAP returns 404 or times out, the stage records a non-fatal warning and continues.

### Stage 5: Risk Evaluation & Findings Generation (95% Progress)
- **Objective**: Evaluate mathematical exposure risk and generate actionable evidence records.
- **Engines**: `DeterministicRiskEngine` + `EvidenceManager`.
- **Actions**:
  1. Computes explainable 0–100 Exposure Risk Score across 6 distinct weighted factors.
  2. Compares discovered subdomains against registered managed assets to flag uncataloged shadow IT assets (`UNKNOWN_ASSET_RELATIONSHIP`).
  3. Synthesizes formal `ExposureFinding` records with JSON evidence payloads.
  4. Commits all records to PostgreSQL within a database transaction.
  5. Transitions status to `COMPLETED` (or `PARTIALLY_COMPLETED` if external warnings occurred).

---

## 3. Job Cancellation & Interruption Handling

- At each stage boundary, `DiscoveryManager._check_cancellation` checks whether the user cancelled the job via `POST /api/v1/attack-surface/jobs/{id}/cancel`.
- If cancelled, the worker cleanly aborts execution without modifying downstream entities, marking status as `CANCELLED`.
