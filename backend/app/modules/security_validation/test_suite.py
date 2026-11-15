"""
PREVENT-X Automated Security Validation & Regression Test Suite (MOD-10)
Defines structured, controlled, non-destructive test probes across attack vectors,
WAF bypass variations, encoding regressions, and legitimate benign traffic.
"""

from typing import Any, Dict, List, Optional
from backend.app.models.security_validation import ValidationTestCategory


class ValidationTestCase:
    def __init__(
        self,
        test_id: str,
        category: str,
        name: str,
        description: str,
        endpoint: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        expected_status: int = 403,
        expected_decision: str = "BLOCKED",
        confidence: int = 95,
    ):
        self.test_id = test_id
        self.category = category
        self.name = name
        self.description = description
        self.endpoint = endpoint
        self.method = method
        self.headers = headers or {}
        self.query_params = query_params or {}
        self.body = body
        self.expected_status = expected_status
        self.expected_decision = expected_decision
        self.confidence = confidence


# Structured Catalog of Non-Destructive Validation Test Probes
STANDARD_SECURITY_VALIDATION_SUITE: List[ValidationTestCase] = [
    # -------------------------------------------------------------------------
    # 1. SQL Injection Protection (CWE-89)
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="VAL-SQLI-01",
        category=ValidationTestCategory.SQLI.value,
        name="SQL Injection: Raw UNION SELECT",
        description="Verifies gateway blocks unauthorized SQL UNION SELECT statement.",
        endpoint="/products",
        query_params={"q": "1 UNION SELECT 1,2--"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-SQLI-02",
        category=ValidationTestCategory.SQLI.value,
        name="SQL Injection: Tautology Expression",
        description="Verifies gateway intercepts boolean-based tautology (' OR '1'='1).",
        endpoint="/products",
        query_params={"id": "1' OR '1'='1"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-SQLI-03",
        category=ValidationTestCategory.SQLI.value,
        name="SQL Injection: Time-Based Blind Delay",
        description="Verifies gateway terminates time-based blind SQL injection triggers (WAITFOR DELAY / sleep).",
        endpoint="/products",
        query_params={"id": "1; WAITFOR DELAY '0:0:5'--"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),

    # -------------------------------------------------------------------------
    # 2. Cross-Site Scripting Protection (CWE-79)
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="VAL-XSS-01",
        category=ValidationTestCategory.XSS.value,
        name="XSS: Unsanitized HTML Script Tag",
        description="Verifies rejection of raw client-side JavaScript script tags.",
        endpoint="/search",
        query_params={"query": "<script>alert(1)</script>"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-XSS-02",
        category=ValidationTestCategory.XSS.value,
        name="XSS: DOM Event Handler Injection",
        description="Verifies rejection of inline element event handlers (onerror=).",
        endpoint="/search",
        query_params={"query": '<img src=x onerror=alert("XSS")>'},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-XSS-03",
        category=ValidationTestCategory.XSS.value,
        name="XSS: JavaScript URI Scheme",
        description="Verifies blocking of executable javascript: pseudoprotocol.",
        endpoint="/search",
        query_params={"redirect": "javascript:document.cookie"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),

    # -------------------------------------------------------------------------
    # 3. Path Traversal Protection (CWE-22)
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="VAL-PATH-01",
        category=ValidationTestCategory.PATH_TRAVERSAL.value,
        name="Path Traversal: Relative Directory Escalation",
        description="Verifies gateway blocks relative directory escalation sequences (../../etc/passwd).",
        endpoint="/download",
        query_params={"file": "../../etc/passwd"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-PATH-02",
        category=ValidationTestCategory.PATH_TRAVERSAL.value,
        name="Path Traversal: Windows System Path Reference",
        description="Verifies blocking of Windows system32 executive path traversal.",
        endpoint="/download",
        query_params={"file": r"..\..\windows\system32\cmd.exe"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-PATH-03",
        category=ValidationTestCategory.PATH_TRAVERSAL.value,
        name="Path Traversal: Critical Shadow File Access",
        description="Verifies immediate interception of absolute critical OS credentials file references.",
        endpoint="/download",
        query_params={"file": "/etc/shadow"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),

    # -------------------------------------------------------------------------
    # 4. OS Command Injection (CWE-78)
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="VAL-CMDI-01",
        category=ValidationTestCategory.CMDI.value,
        name="Command Injection: Semicolon Binary Execution",
        description="Verifies blocking of command separator chaining with host system commands (;whoami).",
        endpoint="/report",
        query_params={"filter": "date;whoami"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="VAL-CMDI-02",
        category=ValidationTestCategory.CMDI.value,
        name="Command Injection: Pipe Operator Chaining",
        description="Verifies blocking of pipe chaining attempting shell escalation (|cat /etc/passwd).",
        endpoint="/report",
        query_params={"cmd": "cat /etc/passwd | grep root"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),

    # -------------------------------------------------------------------------
    # 5. WAF Regression & Encoding Variations
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="REG-ENC-01",
        category=ValidationTestCategory.REGRESSION_ENCODING.value,
        name="Regression: URL-Encoded XSS Script Tag",
        description="Verifies WAF normalizes and catches standard percent-encoded script tags (%3Cscript%3E).",
        endpoint="/search",
        query_params={"query": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="REG-ENC-02",
        category=ValidationTestCategory.REGRESSION_ENCODING.value,
        name="Regression: Mixed-Case SQL Injection",
        description="Verifies case-insensitive matching intercepts mixed-case SQL keywords (uNiOn sElEcT).",
        endpoint="/products",
        query_params={"q": "1 uNiOn sElEcT 1,2--"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="REG-ENC-03",
        category=ValidationTestCategory.REGRESSION_ENCODING.value,
        name="Regression: Double-Encoded Path Traversal",
        description="Verifies protection against double-encoded path traversal sequences (%252e%252e%252f).",
        endpoint="/download",
        query_params={"file": "%252e%252e%252fetc%252fpasswd"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="REG-ENC-04",
        category=ValidationTestCategory.REGRESSION_ENCODING.value,
        name="Regression: Automated Reconnaissance Scanner",
        description="Verifies User-Agent block for automated security scanning frameworks.",
        endpoint="/api/v1/system",
        headers={"User-Agent": "sqlmap/1.5#stable"},
        expected_status=403,
        expected_decision="BLOCKED",
    ),
    ValidationTestCase(
        test_id="REG-ENC-05",
        category=ValidationTestCategory.REGRESSION_ENCODING.value,
        name="Regression: Bounded Input Size & ReDoS Safety",
        description="Tests gateway response to oversized repetitive payloads ensuring safe timeout bounding without CPU starvation.",
        endpoint="/search",
        query_params={"query": "A" * 2048 + "union select"},
        expected_status=403,
        expected_decision="BLOCKED",
        confidence=90,
    ),

    # -------------------------------------------------------------------------
    # 6. Legitimate Traffic Acceptance (Zero False-Positive Verification)
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="VAL-LEGIT-01",
        category=ValidationTestCategory.LEGITIMATE_TRAFFIC.value,
        name="Legitimate: Standard Product Browsing",
        description="Ensures legitimate application traffic passes through without false alarms.",
        endpoint="/products",
        query_params={"category": "electronics", "page": "1"},
        expected_status=200,
        expected_decision="ALLOWED",
    ),
    ValidationTestCase(
        test_id="VAL-LEGIT-02",
        category=ValidationTestCategory.LEGITIMATE_TRAFFIC.value,
        name="Legitimate: Benign Query Containing 'select' in Prose",
        description="Ensures benign queries containing English word 'select' are not falsely blocked.",
        endpoint="/articles",
        query_params={"query": "select_options_for_dropdown_menu"},
        expected_status=200,
        expected_decision="ALLOWED",
    ),
    ValidationTestCase(
        test_id="VAL-LEGIT-03",
        category=ValidationTestCategory.LEGITIMATE_TRAFFIC.value,
        name="Legitimate: Safe Document Download Request",
        description="Ensures valid document names without path escalation pass to upstream.",
        endpoint="/download",
        query_params={"file": "financial_report_2026_q3.pdf"},
        expected_status=200,
        expected_decision="ALLOWED",
    ),
    ValidationTestCase(
        test_id="VAL-LEGIT-04",
        category=ValidationTestCategory.LEGITIMATE_TRAFFIC.value,
        name="Legitimate: Safe User Email Search",
        description="Ensures searching by legitimate email address is allowed through cleanly.",
        endpoint="/users",
        query_params={"search": "finance.lead@smbcorp.in"},
        expected_status=200,
        expected_decision="ALLOWED",
    ),

    # -------------------------------------------------------------------------
    # 7. Upstream Connectivity & Reverse Proxy Reachability
    # -------------------------------------------------------------------------
    ValidationTestCase(
        test_id="VAL-UPSTREAM-01",
        category=ValidationTestCategory.UPSTREAM_CONNECTIVITY.value,
        name="Upstream: Gateway Health and Reverse Proxy Routing",
        description="Verifies proxy correctly routes traffic to backend upstream application cluster.",
        endpoint="/",
        expected_status=200,
        expected_decision="ALLOWED",
    ),
]

