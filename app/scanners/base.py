import httpx
import asyncio
from typing import Optional, Dict, Any

# Default headers to mimic a real browser/client
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SecureAPI-Scanner/1.0)",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json"
}

TIMEOUT = 10  # seconds per request
MAX_RETRIES = 3


async def send_request(
    method: str,
    url: str,
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None,
    params: Optional[Dict] = None,
    timeout: int = TIMEOUT,
    follow_redirects: bool = True
) -> Optional[httpx.Response]:
    """
    Core async HTTP request sender with retry logic and timeout handling.
    Returns the response or None if all retries fail.
    """
    merged_headers = {**DEFAULT_HEADERS, **(headers or {})}

    for attempt in range(MAX_RETRIES):
        try:
            async with httpx.AsyncClient(
                follow_redirects=follow_redirects,
                timeout=timeout,
                verify=False  # allow self-signed certs on test APIs
            ) as client:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=merged_headers,
                    json=body if body else None,
                    params=params
                )
                return response

        except httpx.TimeoutException:
            if attempt == MAX_RETRIES - 1:
                return None
            await asyncio.sleep(1)

        except httpx.RequestError:
            if attempt == MAX_RETRIES - 1:
                return None
            await asyncio.sleep(1)


async def get_baseline(
    method: str,
    url: str,
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> Optional[httpx.Response]:
    """
    Sends a clean baseline request so scanners can compare
    normal vs. crafted responses.
    """
    return await send_request(method, url, headers=headers, body=body)


def build_finding(
    scanner: str,
    severity: str,
    title: str,
    description: str,
    evidence: Any = None,
    endpoint: str = None
) -> Dict:
    """
    Standardized finding format returned by every scanner.
    severity: critical / high / medium / low / info
    """
    return {
        "scanner": scanner,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "endpoint": endpoint
    }
