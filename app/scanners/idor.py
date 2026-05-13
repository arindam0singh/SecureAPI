import asyncio
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding
import re

ID_RANGE = range(1, 11)  # test IDs 1 through 10


def replace_id_in_url(url: str, new_id: int) -> Optional[str]:
    """
    Replace numeric ID segments in the URL path.
    e.g. /users/5/profile -> /users/3/profile
    """
    pattern = r'(/\w+/)(\d+)(/?)'
    match = re.search(pattern, url)
    if match:
        return re.sub(pattern, f"{match.group(1)}{new_id}{match.group(3)}", url, count=1)
    return None


async def run(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    findings = []

    baseline = await get_baseline(method, url, headers=headers, body=body)
    if not baseline:
        findings.append(build_finding(
            scanner="idor",
            severity="info",
            title="Endpoint Unreachable",
            description="Could not reach endpoint for IDOR testing.",
            endpoint=url
        ))
        return findings

    baseline_status = baseline.status_code
    baseline_length = len(baseline.text)
    accessible_ids = []

    # -------------------------------------------------------
    # Test 1: Iterate IDs in URL path
    # -------------------------------------------------------
    for test_id in ID_RANGE:
        modified_url = replace_id_in_url(url, test_id)
        if not modified_url or modified_url == url:
            continue

        resp = await send_request(method, modified_url, headers=headers, body=body)
        if not resp:
            continue

        if resp.status_code in [200, 201]:
            accessible_ids.append({
                "id": test_id,
                "url": modified_url,
                "status_code": resp.status_code,
                "response_length": len(resp.text)
            })

    if len(accessible_ids) > 1:
        findings.append(build_finding(
            scanner="idor",
            severity="high",
            title="Potential IDOR / BOLA Vulnerability Detected",
            description=(
                f"Multiple object IDs ({[r['id'] for r in accessible_ids]}) "
                "returned successful responses when accessed sequentially. "
                "If these belong to different users, this indicates broken "
                "object-level authorization (BOLA/IDOR)."
            ),
            evidence={"accessible_resources": accessible_ids},
            endpoint=url
        ))

    # -------------------------------------------------------
    # Test 2: ID in query params
    # -------------------------------------------------------
    param_accessible = []
    for test_id in ID_RANGE:
        resp = await send_request(method, url, headers=headers,
                                  params={"id": test_id}, body=body)
        if resp and resp.status_code in [200, 201]:
            param_accessible.append(test_id)

    if len(param_accessible) > 1:
        findings.append(build_finding(
            scanner="idor",
            severity="high",
            title="IDOR via Query Parameter",
            description=(
                f"Accessing `?id=` with values {param_accessible} all returned "
                "successful responses. This may indicate missing authorization checks."
            ),
            evidence={"accessible_ids": param_accessible},
            endpoint=url
        ))

    if not findings:
        findings.append(build_finding(
            scanner="idor",
            severity="info",
            title="No IDOR Detected",
            description="No obvious IDOR patterns found during sequential ID testing.",
            endpoint=url
        ))

    return findings
