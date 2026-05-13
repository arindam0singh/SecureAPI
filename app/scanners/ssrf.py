import asyncio
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://169.254.169.254",                          # AWS metadata
    "http://169.254.169.254/latest/meta-data/",        # AWS metadata full
    "http://metadata.google.internal",                  # GCP metadata
    "http://192.168.0.1",
    "http://10.0.0.1",
    "http://[::1]",                                     # IPv6 localhost
    "http://127.0.0.1:6379",                           # Redis
    "http://127.0.0.1:5432",                           # PostgreSQL
    "http://127.0.0.1:27017",                          # MongoDB
    "file:///etc/passwd",                               # Local file read
]

SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "dest",
    "destination", "redirect", "next", "callback",
    "return", "returnUrl", "redirect_uri", "image_url",
    "fetch", "load", "proxy", "path"
]

SSRF_INDICATORS = [
    "root:x:", "localhost", "EC2", "metadata", "ami-id",
    "instance-id", "internal", "169.254"
]


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

    # -------------------------------------------------------
    # Test 1: Inject SSRF payloads into URL query params
    # -------------------------------------------------------
    for param_name in SSRF_PARAM_NAMES:
        for payload in SSRF_PAYLOADS:
            resp = await send_request(
                method, url,
                headers=headers,
                params={param_name: payload},
                body=body,
                timeout=8
            )

            if not resp:
                continue

            resp_text = resp.text
            matched = [ind for ind in SSRF_INDICATORS if ind.lower() in resp_text.lower()]

            if matched:
                findings.append(build_finding(
                    scanner="ssrf",
                    severity="critical",
                    title="SSRF Vulnerability Detected via Query Parameter",
                    description=(
                        f"Injecting `{payload}` into the `{param_name}` parameter "
                        "caused the server to make an internal request and return "
                        "internal/metadata content in the response."
                    ),
                    evidence={
                        "param": param_name,
                        "payload": payload,
                        "matched_indicators": matched,
                        "response_snippet": resp_text[:400]
                    },
                    endpoint=url
                ))
                return findings  # stop on first confirmed SSRF

    # -------------------------------------------------------
    # Test 2: Inject into request body fields
    # -------------------------------------------------------
    for param_name in SSRF_PARAM_NAMES:
        for payload in SSRF_PAYLOADS[:5]:  # fewer payloads for body test
            injected_body = {**(body or {}), param_name: payload}
            resp = await send_request(
                method, url,
                headers=headers,
                body=injected_body,
                timeout=8
            )

            if not resp:
                continue

            resp_text = resp.text
            matched = [ind for ind in SSRF_INDICATORS if ind.lower() in resp_text.lower()]

            if matched:
                findings.append(build_finding(
                    scanner="ssrf",
                    severity="critical",
                    title="SSRF Vulnerability Detected via Request Body",
                    description=(
                        f"Injecting `{payload}` into the `{param_name}` body field "
                        "caused the server to make an internal request."
                    ),
                    evidence={
                        "field": param_name,
                        "payload": payload,
                        "matched_indicators": matched,
                        "response_snippet": resp_text[:400]
                    },
                    endpoint=url
                ))
                return findings

    # -------------------------------------------------------
    # Test 3: Check for open redirect that could lead to SSRF
    # -------------------------------------------------------
    for param_name in ["redirect", "next", "returnUrl", "redirect_uri"]:
        resp = await send_request(
            method, url,
            headers=headers,
            params={param_name: "http://127.0.0.1"},
            follow_redirects=False
        )

        if resp and resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.headers.get("location", "")
            if "127.0.0.1" in location or "localhost" in location:
                findings.append(build_finding(
                    scanner="ssrf",
                    severity="high",
                    title="Open Redirect to Internal Address Detected",
                    description=(
                        f"The `{param_name}` parameter redirected to an internal "
                        "address. This can be chained into a full SSRF attack."
                    ),
                    evidence={
                        "param": param_name,
                        "redirect_location": location,
                        "status_code": resp.status_code
                    },
                    endpoint=url
                ))

    if not findings:
        findings.append(build_finding(
            scanner="ssrf",
            severity="info",
            title="No SSRF Detected",
            description="No SSRF indicators found across tested parameters and payloads.",
            endpoint=url
        ))

    return findings
