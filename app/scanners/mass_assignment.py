from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

PRIVILEGE_FIELDS = [
    {"isAdmin": True},
    {"is_admin": True},
    {"role": "admin"},
    {"admin": True},
    {"superuser": True},
    {"privilege": "admin"},
    {"permissions": ["admin", "write", "delete"]},
    {"account_type": "premium"},
    {"verified": True},
    {"balance": 999999},
    {"credit": 999999},
]


async def run(
    url: str,
    method: str = "POST",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    findings = []

    baseline = await get_baseline(method, url, headers=headers, body=body)
    if not baseline:
        return findings

    baseline_text = baseline.text.lower()
    baseline_status = baseline.status_code

    triggered = []

    for extra_fields in PRIVILEGE_FIELDS:
        injected_body = {**(body or {}), **extra_fields}
        resp = await send_request(method, url, headers=headers, body=injected_body)

        if not resp:
            continue

        resp_text = resp.text.lower()

        # Look for privilege keywords reflected in response
        reflected = [
            k for k in extra_fields
            if str(k).lower() in resp_text or str(extra_fields[k]).lower() in resp_text
        ]

        # Or response changed significantly
        length_diff = abs(len(resp.text) - len(baseline.text))

        if reflected or (resp.status_code == 200 and length_diff > 100):
            triggered.append({
                "injected_fields": extra_fields,
                "status_code": resp.status_code,
                "reflected_fields": reflected,
                "response_length_diff": length_diff
            })

    if triggered:
        findings.append(build_finding(
            scanner="mass_assignment",
            severity="high",
            title="Mass Assignment Vulnerability Detected",
            description=(
                "The API appears to accept and potentially process extra fields "
                "such as 'isAdmin', 'role', or 'balance' that were injected into "
                "the request body. This may allow privilege escalation or "
                "unauthorized data manipulation."
            ),
            evidence={"triggered_payloads": triggered},
            endpoint=url
        ))
    else:
        findings.append(build_finding(
            scanner="mass_assignment",
            severity="info",
            title="No Mass Assignment Detected",
            description="Injected privilege fields did not appear to affect responses.",
            endpoint=url
        ))

    return findings
