import httpx
import re
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
from bs4 import BeautifulSoup

# Common API path patterns to look for
API_PATTERNS = [
    r'/api/[^\s\'"<>]+',
    r'/v\d+/[^\s\'"<>]+',
    r'/rest/[^\s\'"<>]+',
    r'/graphql[^\s\'"<>]*',
    r'/swagger[^\s\'"<>]*',
    r'/openapi[^\s\'"<>]*',
    r'/docs[^\s\'"<>]*',
    r'\.json[^\s\'"<>]*',
    r'/auth/[^\s\'"<>]+',
    r'/oauth[^\s\'"<>]*',
    r'/user[s]?/[^\s\'"<>]+',
    r'/account[s]?/[^\s\'"<>]+',
    r'/admin[^\s\'"<>]*',
    r'/dashboard[^\s\'"<>]*',
    r'/login[^\s\'"<>]*',
    r'/register[^\s\'"<>]*',
    r'/search[^\s\'"<>]*',
    r'/upload[^\s\'"<>]*',
    r'/download[^\s\'"<>]*',
    r'/payment[s]?/[^\s\'"<>]+',
    r'/order[s]?/[^\s\'"<>]+',
    r'/product[s]?/[^\s\'"<>]+',
    r'/checkout[^\s\'"<>]*',
    r'/webhook[s]?[^\s\'"<>]*',
    r'/health[^\s\'"<>]*',
    r'/status[^\s\'"<>]*',
    r'/metrics[^\s\'"<>]*',
]

# Known spec file locations to check
SPEC_PATHS = [
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json',
    '/openapi.yaml',
    '/api-docs',
    '/api-docs.json',
    '/api/docs',
    '/v1/swagger.json',
    '/v2/swagger.json',
    '/v3/swagger.json',
    '/api/swagger.json',
    '/api/openapi.json',
    '/docs/swagger.json',
    '/api/v1/swagger.json',
    '/api/v2/swagger.json',
    '/api/v3/swagger.json',
]

# JS file patterns that often contain API endpoints
JS_API_PATTERNS = [
    r'["\'](/api/[^"\'<>\s]+)["\']',
    r'["\'](/v\d+/[^"\'<>\s]+)["\']',
    r'["\'](/rest/[^"\'<>\s]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']+)["\']',
    r'\.post\(["\']([^"\']+)["\']',
    r'\.put\(["\']([^"\']+)["\']',
    r'\.delete\(["\']([^"\']+)["\']',
    r'baseURL[:\s]+["\']([^"\']+)["\']',
    r'BASE_URL[:\s=]+["\']([^"\']+)["\']',
    r'API_URL[:\s=]+["\']([^"\']+)["\']',
]


async def discover(url: str) -> Dict:
    """
    Main discovery function.
    Takes a website URL and returns all discovered API endpoints.
    """
    results = {
        "base_url": url,
        "endpoints": [],
        "spec_files": [],
        "js_files_scanned": [],
        "errors": []
    }

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(
        timeout=15,
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; SecureAPI-Scanner/1.0)"}
    ) as client:

        # ── Step 1: Check for spec files ──
        for spec_path in SPEC_PATHS:
            spec_url = base + spec_path
            try:
                resp = await client.get(spec_url)
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    if "json" in content_type or "yaml" in content_type or resp.text.strip().startswith("{"):
                        results["spec_files"].append({
                            "url": spec_url,
                            "type": "OpenAPI/Swagger spec",
                            "note": "Can be used directly in Swagger URL tab"
                        })
            except Exception:
                pass

        # ── Step 2: Fetch and parse the main page ──
        try:
            resp = await client.get(url)
            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')

            # Extract endpoints from HTML
            html_endpoints = extract_from_text(html, base)
            for ep in html_endpoints:
                add_endpoint(results["endpoints"], ep, "HTML page")

            # Find all script tags with src
            script_tags = soup.find_all('script', src=True)
            js_urls = []
            for tag in script_tags:
                src = tag.get('src', '')
                if src:
                    full_url = urljoin(url, src)
                    if parsed.netloc in full_url:
                        js_urls.append(full_url)

            # Also find inline scripts
            inline_scripts = soup.find_all('script', src=False)
            for tag in inline_scripts:
                if tag.string:
                    js_endpoints = extract_from_js(tag.string, base)
                    for ep in js_endpoints:
                        add_endpoint(results["endpoints"], ep, "Inline script")

            # Extract from anchor tags and form actions
            for a in soup.find_all('a', href=True):
                href = a['href']
                if any(re.search(p, href) for p in API_PATTERNS):
                    full = urljoin(base, href)
                    add_endpoint(results["endpoints"], full, "HTML link")

            for form in soup.find_all('form', action=True):
                action = form.get('action', '')
                if action and not action.startswith('#'):
                    full = urljoin(base, action)
                    add_endpoint(results["endpoints"], full, "Form action")

        except Exception as e:
            results["errors"].append(f"Failed to fetch main page: {str(e)}")

        # ── Step 3: Fetch and scan JS files ──
        for js_url in js_urls[:10]:  # limit to 10 JS files
            try:
                js_resp = await client.get(js_url)
                if js_resp.status_code == 200:
                    results["js_files_scanned"].append(js_url)
                    js_endpoints = extract_from_js(js_resp.text, base)
                    for ep in js_endpoints:
                        add_endpoint(results["endpoints"], ep, f"JS: {js_url.split('/')[-1]}")
            except Exception:
                pass

    # Sort and deduplicate
    results["endpoints"] = sorted(
        results["endpoints"],
        key=lambda x: x["url"]
    )

    return results


def extract_from_text(text: str, base: str) -> List[str]:
    """Extract API endpoint URLs from raw text using regex patterns."""
    found = set()
    for pattern in API_PATTERNS:
        matches = re.findall(pattern, text)
        for match in matches:
            clean = match.strip('\'"').split('?')[0].rstrip('/')
            if clean and len(clean) > 2:
                full = base + clean if clean.startswith('/') else clean
                if '.' not in clean.split('/')[-1] or clean.endswith('.json'):
                    found.add(full)
    return list(found)


def extract_from_js(js_text: str, base: str) -> List[str]:
    """Extract API endpoint URLs from JavaScript source."""
    found = set()
    for pattern in JS_API_PATTERNS:
        matches = re.findall(pattern, js_text)
        for match in matches:
            clean = match.strip().rstrip('/')
            if clean and len(clean) > 2 and not clean.startswith('http'):
                full = base + clean if clean.startswith('/') else clean
                found.add(full)
            elif clean.startswith('http') and len(clean) > 10:
                found.add(clean)
    return list(found)


def add_endpoint(endpoint_list: List, url: str, source: str):
    """Add endpoint to list if not already present."""
    existing_urls = {e["url"] for e in endpoint_list}
    if url not in existing_urls and url.startswith('http'):
        parsed = urlparse(url)
        path = parsed.path
        endpoint_list.append({
            "url": url,
            "path": path,
            "source": source,
            "method": guess_method(path)
        })


def guess_method(path: str) -> str:
    """Guess likely HTTP method based on path patterns."""
    path_lower = path.lower()
    if any(k in path_lower for k in ['create', 'add', 'new', 'register', 'login', 'upload', 'submit']):
        return "POST"
    if any(k in path_lower for k in ['update', 'edit', 'modify']):
        return "PUT"
    if any(k in path_lower for k in ['delete', 'remove']):
        return "DELETE"
    return "GET"
