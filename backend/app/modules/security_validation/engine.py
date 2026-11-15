"""
PREVENT-X Automated Security Validation Engine (MOD-10)
Executes controlled, non-destructive test suites against reverse proxy gateways,
evaluates WAF regression coverage, and records forensic evidence.
"""

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy.orm import Session

from backend.app.database.base import utc_now
from backend.app.models.security_validation import (
    TestResultStatus,
    ValidationJob,
    ValidationJobStatus,
    ValidationTestResult,
)
from backend.app.modules.security_validation.test_suite import (
    STANDARD_SECURITY_VALIDATION_SUITE,
    ValidationTestCase,
)

logger = logging.getLogger("preventx.security_validation.engine")


class SecurityValidationEngine:
    """
    Automated security validation runner executing non-destructive test requests.
    """

    SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "token", "secret"}

    @classmethod
    def redact_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Redacts credentials, cookies, and tokens from request metadata.
        """
        sanitized = {}
        for k, v in headers.items():
            if k.lower() in cls.SENSITIVE_HEADERS:
                sanitized[k] = "[REDACTED_CREDENTIAL]"
            else:
                sanitized[k] = v
        return sanitized

    @classmethod
    def execute_single_test(
        cls,
        client: httpx.Client,
        base_url: str,
        test_case: ValidationTestCase,
    ) -> Tuple[int, str, float, str, Optional[str]]:
        """
        Sends an isolated HTTP test request and captures response metrics.
        Returns (status_code, decision, latency_ms, evidence_snippet, error_message).
        """
        url = f"{base_url.rstrip('/')}{test_case.endpoint}"
        start_time = time.perf_counter()
        headers = dict(test_case.headers)
        error_msg = None

        # If query parameters contain already percent-encoded values, format directly into URL
        params = test_case.query_params
        if params:
            has_pre_encoded = any("%" in str(v) for v in params.values())
            if has_pre_encoded:
                query_str = "&".join(f"{k}={v}" for k, v in params.items())
                delimiter = "&" if "?" in url else "?"
                url = f"{url}{delimiter}{query_str}"
                params = None

        try:
            resp = client.request(
                method=test_case.method,
                url=url,
                params=params,
                headers=headers,
                content=test_case.body.encode("utf-8") if test_case.body else None,
                timeout=5.0,
            )
            latency = (time.perf_counter() - start_time) * 1000.0
            status_code = resp.status_code
            evidence = resp.text[:500] if resp.text else f"Status: {resp.status_code}"

            decision = "BLOCKED" if status_code in (403, 405) else "ALLOWED"
            return status_code, decision, round(latency, 2), evidence, None

        except httpx.ConnectError as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return 0, "ERROR", round(latency, 2), "", f"Connection refused to {base_url}: {e}"
        except httpx.TimeoutException:
            latency = (time.perf_counter() - start_time) * 1000.0
            return 504, "ERROR", round(latency, 2), "", "Request timed out after 5.0 seconds"
        except Exception as e:
            latency = (time.perf_counter() - start_time) * 1000.0
            return 500, "ERROR", round(latency, 2), "", f"Execution error: {str(e)}"

    @classmethod
    def run_validation_job(
        cls,
        db: Session,
        job: ValidationJob,
        test_cases: Optional[List[ValidationTestCase]] = None,
    ) -> ValidationJob:
        """
        Executes complete validation test suite against target gateway proxy.
        """
        suite = test_cases or STANDARD_SECURITY_VALIDATION_SUITE
        logger.info(
            "Starting Security Validation Job %s (%s tests) against %s",
            job.id,
            len(suite),
            job.target_url,
        )

        job.status = ValidationJobStatus.RUNNING.value
        job.started_at = utc_now()
        job.total_tests = len(suite)
        db.commit()

        passed_count = 0
        failed_count = 0
        blocked_count = 0
        allowed_count = 0
        false_positives = 0
        bypasses = 0

        # Execute tests with HTTP client
        with httpx.Client(timeout=10.0) as client:
            for tc in suite:
                status_code, actual_dec, latency_ms, evidence, error_msg = cls.execute_single_test(
                    client=client,
                    base_url=job.target_url,
                    test_case=tc,
                )

                # Determine test outcome
                is_passed = (status_code == tc.expected_status) and (error_msg is None)
                res_status = TestResultStatus.PASSED.value if is_passed else (
                    TestResultStatus.ERROR.value if error_msg else TestResultStatus.FAILED.value
                )

                if is_passed:
                    passed_count += 1
                else:
                    failed_count += 1

                if actual_dec == "BLOCKED":
                    blocked_count += 1
                elif actual_dec == "ALLOWED":
                    allowed_count += 1

                # Track bypasses and false positives
                if tc.expected_decision == "BLOCKED" and actual_dec == "ALLOWED":
                    bypasses += 1
                    logger.warning("WAF BYPASS DETECTED: %s (%s)", tc.test_id, tc.name)
                elif tc.expected_decision == "ALLOWED" and actual_dec == "BLOCKED":
                    false_positives += 1
                    logger.warning("FALSE POSITIVE DETECTED: %s (%s)", tc.test_id, tc.name)

                # Build redacted request payload description
                req_summary = []
                if tc.query_params:
                    req_summary.append(f"Query: {tc.query_params}")
                if tc.body:
                    req_summary.append(f"Body: {tc.body[:200]}")
                payload_str = " | ".join(req_summary) if req_summary else None

                # Record individual test result
                result_record = ValidationTestResult(
                    id=uuid.uuid4(),
                    job_id=job.id,
                    organization_id=job.organization_id,
                    test_id=tc.test_id,
                    test_category=tc.category,
                    test_name=tc.name,
                    description=tc.description,
                    target_endpoint=tc.endpoint,
                    http_method=tc.method,
                    request_headers_redacted=json.dumps(cls.redact_headers(tc.headers)),
                    request_payload_redacted=payload_str,
                    expected_status_code=tc.expected_status,
                    actual_status_code=status_code,
                    expected_decision=tc.expected_decision,
                    actual_decision=actual_dec,
                    result=res_status,
                    latency_ms=latency_ms,
                    evidence_snippet=evidence,
                    confidence=tc.confidence,
                    error_message=error_msg,
                )
                db.add(result_record)

        # Update Job summary metrics
        job.passed_tests = passed_count
        job.failed_tests = failed_count
        job.blocked_attacks = blocked_count
        job.allowed_legitimate = allowed_count
        job.false_positives_detected = false_positives
        job.bypasses_detected = bypasses
        job.pass_rate_percentage = round((passed_count / len(suite) * 100.0) if suite else 0.0, 2)
        job.completed_at = utc_now()

        # Job passes ONLY if all tests passed and 0 bypasses/false positives detected
        if failed_count == 0 and bypasses == 0 and false_positives == 0:
            job.status = ValidationJobStatus.PASSED.value
        else:
            job.status = ValidationJobStatus.FAILED.value

        summary = {
            "total": len(suite),
            "passed": passed_count,
            "failed": failed_count,
            "bypasses": bypasses,
            "false_positives": false_positives,
            "pass_rate": job.pass_rate_percentage,
            "target_url": job.target_url,
            "timestamp": job.completed_at.isoformat(),
        }
        job.summary_report = json.dumps(summary)

        db.commit()
        db.refresh(job)
        return job

