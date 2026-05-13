import re
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key": r"(?i)(api_key|apikey|api-key)['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{16,}",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_.+/=]*",
    "JWT Token": r"eyJ[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_.+/=]*",
    "Password in Response": r"(?i)(\"password\"|\"passwd\"|\"pwd\")\s*:\s*\"[^\"]+\"",
    "Email Address": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Private Key": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "Internal IP": r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
    "Stack Trace": r"(?i)(traceback|stack trace|at [a-z]+\.[a-z]+\()",
    "Database Error": r"(?i)(mysql_fetch|ora-\d+|sqlite_|pg_query|sql syntax)"
}

SEVERITY_MAP = {
    "AWS Access Key": "critical",
    "AWS Secret Key": "critical",
    "Private Key": "critical",
    "Stripe Secret Key": "critical",
    "GitHub Token": "critical",
    "Bearer Token": "high",
    "JWT Token": "high",
    "Password in Response": "critical",
    "Generic API Key": "high",
    "Google API Key": "high",
    "Credit Card": "critical",
    "SSN": "critical",
    "Email Address": "medium",
    "Internal IP": "medium",
    "Stack Trace": "medium",
    "Database Error": "high"
}


async def run(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    findings = []

    resp = await send_request(method, url, headers=headers, body=body)
    if not resp:
        return findings

    response_text = resp.text

    matched_patterns = {}
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, response_text)
        if matches:
            # Truncate to avoid leaking full secrets in our own report
            matched_patterns[name] = [m[:40] + "..." if len(m) > 40 else m for m in matches[:3]]

    if matched_patterns:
        for pattern_name, matches in matched_patterns.items():
            findings.append(build_finding(
                scanner="sensitive_data",
                severity=SEVERITY_MAP.get(pattern_name, "medium"),
                title=f"Sensitive Data Exposed: {pattern_name}",
                description=(
                    f"The API response contains what appears to be a {pattern_name}. "
                    "Exposing sensitive data in API responses can lead to credential "
                    "theft, account takeover, or compliance violations (GDPR, PCI-DSS)."
                ),
                evidence={"pattern": pattern_name, "matches": matches},
                endpoint=url
            ))
    else:
        findings.append(build_finding(
            scanner="sensitive_data",
            severity="info",
            title="No Sensitive Data Detected",
            description="No common sensitive data patterns found in the response.",
            endpoint=url
        ))

    # Check response headers for sensitive info
    sensitive_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    exposed_headers = {k: v for k, v in resp.headers.items() if k.lower() in sensitive_headers}

    if exposed_headers:
        findings.append(build_finding(
            scanner="sensitive_data",
            severity="low",
            title="Server Technology Disclosed in Headers",
            description=(
                "Response headers reveal server technology details which can help "
                "attackers fingerprint the stack and target known vulnerabilities."
            ),
            evidence={"exposed_headers": exposed_headers},
            endpoint=url
        ))

    return findings
