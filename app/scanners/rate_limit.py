import asyncio
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

FLOOD_COUNT = 50        # number of requests to send
CONCURRENCY = 10        # how many at once
BLOCK_STATUS = [429, 503, 403]  # status codes that indicate blocking


async def run(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    """
    Rate limit scanner:
    1. Gets a baseline response
    2. Floods the endpoint with concurrent requests
    3. Checks if any response indicates blocking
    4. Checks for rate limit headers
    """
    findings = []

    # Step 1 — baseline
    baseline = await get_baseline(method, url, headers=headers, body=body)
    if baseline is None:
        findings.append(build_finding(
            scanner="rate_limit",
            severity="info",
            title="Endpoint Unreachable",
            description="Could not reach the endpoint during rate limit testing.",
            endpoint=url
        ))
        return findings

    baseline_status = baseline.status_code

    # Step 2 — flood concurrently in batches
    statuses = []
    blocked_responses = []

    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def single_request():
        async with semaphore:
            resp = await send_request(method, url, headers=headers, body=body)
            if resp is not None:
                statuses.append(resp.status_code)
                if resp.status_code in BLOCK_STATUS:
                    blocked_responses.append(resp.status_code)

    tasks = [single_request() for _ in range(FLOOD_COUNT)]
    await asyncio.gather(*tasks)

    # Step 3 — analyze results
    if not statuses:
        findings.append(build_finding(
            scanner="rate_limit",
            severity="info",
            title="No Responses Received During Flood",
            description="All requests during flood testing timed out or failed.",
            endpoint=url
        ))
        return findings

    block_rate = len(blocked_responses) / len(statuses) * 100

    if not blocked_responses:
        findings.append(build_finding(
            scanner="rate_limit",
            severity="high",
            title="No Rate Limiting Detected",
            description=(
                f"Sent {FLOOD_COUNT} rapid requests and received no blocking response. "
                f"All {len(statuses)} responses returned status {baseline_status}. "
                "This endpoint appears to have no rate limiting, making it vulnerable "
                "to brute force and denial-of-service attacks."
            ),
            evidence={
                "requests_sent": FLOOD_COUNT,
                "responses_received": len(statuses),
                "status_codes": list(set(statuses))
            },
            endpoint=url
        ))
    else:
        findings.append(build_finding(
            scanner="rate_limit",
            severity="info",
            title="Rate Limiting Detected",
            description=(
                f"Rate limiting is active. {len(blocked_responses)}/{len(statuses)} "
                f"requests were blocked ({block_rate:.1f}% block rate)."
            ),
            evidence={
                "blocked_count": len(blocked_responses),
                "total_requests": len(statuses),
                "block_rate_percent": round(block_rate, 1)
            },
            endpoint=url
        ))

    # Step 4 — check for rate limit headers in baseline
    rl_headers = ["x-ratelimit-limit", "x-ratelimit-remaining",
                  "retry-after", "ratelimit-limit", "ratelimit-remaining"]

    found_rl_headers = {
        k: v for k, v in baseline.headers.items()
        if k.lower() in rl_headers
    }

    if not found_rl_headers and not blocked_responses:
        findings.append(build_finding(
            scanner="rate_limit",
            severity="medium",
            title="No Rate Limit Headers Found",
            description=(
                "No standard rate limiting headers were found in the response. "
                "Even if server-side limiting exists, clients have no visibility "
                "into their quota (X-RateLimit-Limit, Retry-After, etc.)."
            ),
            evidence={"headers_checked": rl_headers},
            endpoint=url
        ))

    return findings
