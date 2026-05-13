import asyncio
import time
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

ERROR_PATTERNS = [
    "sql syntax", "mysql_fetch", "ora-", "postgresql",
    "sqlite_", "syntax error", "unclosed quotation",
    "you have an error in your sql", "warning: mysql",
    "division by zero", "supplied argument is not a valid mysql"
]

ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1", "';--", "\";--"]

BOOLEAN_PAIRS = [
    ("' OR '1'='1' --", "' OR '1'='2' --"),
    ("1 OR 1=1", "1 OR 1=2"),
]

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",   # MSSQL
    "'; SELECT SLEEP(5)--",          # MySQL
    "'; SELECT pg_sleep(5)--",       # PostgreSQL
]

TIME_THRESHOLD = 4.5  # seconds


def inject_into_params(params: Dict, payload: str) -> Dict:
    """Inject payload into every param value."""
    return {k: str(v) + payload for k, v in params.items()}


def inject_into_body(body: Dict, payload: str) -> Dict:
    """Inject payload into every string field in body."""
    injected = {}
    for k, v in body.items():
        injected[k] = str(v) + payload if isinstance(v, (str, int)) else v
    return injected


async def run(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    findings = []

    baseline = await get_baseline(method, url, headers=headers, body=body)
    if not baseline:
        return findings

    baseline_text = baseline.text.lower()
    baseline_length = len(baseline.text)

    test_params = {"id": "1", "user": "test", "search": "hello", "q": "test", "query": "test", "name": "test", "input": "test"}
    test_body = body if body else {"id": "1", "username": "test"}

    # -------------------------------------------------------
    # Test 1: Error-based SQLi
    # -------------------------------------------------------
    for payload in ERROR_PAYLOADS:
        injected_params = inject_into_params(test_params, payload)
        resp = await send_request(method, url, headers=headers,
                                  body=inject_into_body(test_body, payload),
                                  params=injected_params)
        if not resp:
            continue

        resp_text = resp.text.lower()
        matched = [p for p in ERROR_PATTERNS if p in resp_text]

        if matched and matched not in [p for p in ERROR_PATTERNS if p in baseline_text]:
            findings.append(build_finding(
                scanner="sqli",
                severity="critical",
                title="Error-Based SQL Injection Detected",
                description=(
                    f"The payload `{payload}` triggered a database error message "
                    f"in the response, indicating unsanitized input is passed "
                    f"directly to a SQL query."
                ),
                evidence={
                    "payload": payload,
                    "matched_patterns": matched,
                    "response_snippet": resp.text[:400]
                },
                endpoint=url
            ))
            break

    # -------------------------------------------------------
    # Test 2: Boolean-based SQLi
    # -------------------------------------------------------
    for true_payload, false_payload in BOOLEAN_PAIRS:
        true_params = inject_into_params(test_params, true_payload)
        false_params = inject_into_params(test_params, false_payload)

        true_resp = await send_request(method, url, headers=headers,
                                       params=true_params,
                                       body=inject_into_body(test_body, true_payload))
        false_resp = await send_request(method, url, headers=headers,
                                        params=false_params,
                                        body=inject_into_body(test_body, false_payload))

        if not true_resp or not false_resp:
            continue

        true_len = len(true_resp.text)
        false_len = len(false_resp.text)

        # Significant difference in response = boolean condition evaluated
        if abs(true_len - false_len) > 50:
            findings.append(build_finding(
                scanner="sqli",
                severity="high",
                title="Boolean-Based SQL Injection Detected",
                description=(
                    f"True condition payload returned {true_len} bytes, "
                    f"false condition returned {false_len} bytes. "
                    "This difference suggests the SQL boolean condition "
                    "is being evaluated by the database."
                ),
                evidence={
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "true_response_length": true_len,
                    "false_response_length": false_len
                },
                endpoint=url
            ))
            break

    # -------------------------------------------------------
    # Test 3: Time-based SQLi
    # -------------------------------------------------------
    for payload in TIME_PAYLOADS:
        injected_params = inject_into_params(test_params, payload)
        start = time.monotonic()
        resp = await send_request(method, url, headers=headers,
                                  params=injected_params,
                                  body=inject_into_body(test_body, payload),
                                  timeout=15)
        elapsed = time.monotonic() - start

        if resp and elapsed >= TIME_THRESHOLD:
            findings.append(build_finding(
                scanner="sqli",
                severity="critical",
                title="Time-Based SQL Injection Detected",
                description=(
                    f"The payload `{payload}` caused the server to delay "
                    f"its response by {elapsed:.2f} seconds, strongly indicating "
                    "the payload was executed by the database engine."
                ),
                evidence={
                    "payload": payload,
                    "response_time_seconds": round(elapsed, 2)
                },
                endpoint=url
            ))
            break

    if not findings:
        findings.append(build_finding(
            scanner="sqli",
            severity="info",
            title="No SQL Injection Detected",
            description="No error, boolean, or time-based SQLi indicators found.",
            endpoint=url
        ))

    return findings
