from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "http://localhost",
    "https://subdomain.evil.com",
]


async def run(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    findings = []

    # -------------------------------------------------------
    # Test 1: Wildcard CORS
    # -------------------------------------------------------
    baseline = await get_baseline(method, url, headers=headers, body=body)
    if not baseline:
        return findings

    acao = baseline.headers.get("access-control-allow-origin", "")
    acac = baseline.headers.get("access-control-allow-credentials", "")

    if acao == "*":
        findings.append(build_finding(
            scanner="cors",
            severity="medium",
            title="Wildcard CORS Policy Detected",
            description=(
                "The API returns `Access-Control-Allow-Origin: *`, allowing "
                "any website to make cross-origin requests. While credentials "
                "cannot be sent with wildcard, it may still expose public data "
                "to malicious sites."
            ),
            evidence={"Access-Control-Allow-Origin": acao},
            endpoint=url
        ))

    # -------------------------------------------------------
    # Test 2: Wildcard + credentials (critical misconfiguration)
    # -------------------------------------------------------
    if acao == "*" and acac.lower() == "true":
        findings.append(build_finding(
            scanner="cors",
            severity="critical",
            title="CORS Wildcard With Credentials Allowed",
            description=(
                "The API allows wildcard origin AND credentials. This is a "
                "browser-rejected but dangerous misconfiguration indicating "
                "the developer intended to allow all origins with credentials."
            ),
            evidence={
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac
            },
            endpoint=url
        ))

    # -------------------------------------------------------
    # Test 3: Arbitrary origin reflection
    # -------------------------------------------------------
    for origin in TEST_ORIGINS:
        test_headers = {**(headers or {}), "Origin": origin}
        resp = await send_request(method, url, headers=test_headers, body=body)

        if not resp:
            continue

        reflected_origin = resp.headers.get("access-control-allow-origin", "")
        allows_credentials = resp.headers.get(
            "access-control-allow-credentials", "").lower() == "true"

        if reflected_origin == origin:
            severity = "critical" if allows_credentials else "high"
            findings.append(build_finding(
                scanner="cors",
                severity=severity,
                title="Arbitrary Origin Reflected in CORS Header",
                description=(
                    f"The server reflected the attacker-controlled origin `{origin}` "
                    f"back in the `Access-Control-Allow-Origin` header"
                    f"{' and also allows credentials' if allows_credentials else ''}. "
                    "This allows malicious websites to make authenticated "
                    "cross-origin requests on behalf of logged-in users."
                ),
                evidence={
                    "sent_origin": origin,
                    "reflected_origin": reflected_origin,
                    "credentials_allowed": allows_credentials
                },
                endpoint=url
            ))
            break  # one confirmed is enough

    # -------------------------------------------------------
    # Test 4: Preflight OPTIONS check
    # -------------------------------------------------------
    preflight_headers = {
        **(headers or {}),
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization, Content-Type"
    }

    preflight = await send_request("OPTIONS", url, headers=preflight_headers)
    if preflight:
        allowed_methods = preflight.headers.get("access-control-allow-methods", "")
        allowed_headers = preflight.headers.get("access-control-allow-headers", "")
        preflight_origin = preflight.headers.get("access-control-allow-origin", "")

        if preflight_origin == "https://evil.com":
            findings.append(build_finding(
                scanner="cors",
                severity="high",
                title="Preflight Request Allows Arbitrary Origin",
                description=(
                    "The OPTIONS preflight response approved a request from "
                    "`https://evil.com`. This confirms the CORS misconfiguration "
                    "extends to complex cross-origin requests."
                ),
                evidence={
                    "allowed_origin": preflight_origin,
                    "allowed_methods": allowed_methods,
                    "allowed_headers": allowed_headers
                },
                endpoint=url
            ))

    if not findings:
        findings.append(build_finding(
            scanner="cors",
            severity="info",
            title="No CORS Misconfiguration Detected",
            description="CORS headers appear to be properly configured.",
            endpoint=url
        ))

    return findings
