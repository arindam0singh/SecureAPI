from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Any
from datetime import datetime


# --- Scan request models ---

class SingleEndpointScanRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[dict] = {}
    body: Optional[dict] = {}
    scanners: Optional[List[str]] = [
        "rate_limit", "auth", "sqli", "idor",
        "mass_assignment", "sensitive_data",
        "ssrf", "cmd_injection", "cors"
    ]

class SwaggerScanRequest(BaseModel):
    spec_url: Optional[str] = None   # URL to fetch the swagger JSON/YAML
    scanners: Optional[List[str]] = [
        "rate_limit", "auth", "sqli", "idor",
        "mass_assignment", "sensitive_data",
        "ssrf", "cmd_injection", "cors"
    ]


# --- Response models ---

class FindingModel(BaseModel):
    scanner: str
    severity: str        # critical / high / medium / low / info
    title: str
    description: str
    evidence: Optional[Any] = None
    endpoint: Optional[str] = None

class ScanResultResponse(BaseModel):
    id: int
    target_url: str
    scan_type: str
    status: str
    findings: List[Any]
    summary: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True
