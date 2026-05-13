from app.scanners import discovery
import asyncio
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import yaml
import json

from app.database import get_db, init_db
from app.models import ScanResult
from app.schemas import (
    SingleEndpointScanRequest,
    SwaggerScanRequest,
)
from app.parser import fetch_spec, parse_endpoints

from app.scanners import (
    rate_limit, auth, sqli, idor,
    mass_assignment, sensitive_data,
    ssrf, cmd_injection, cors
)

app = FastAPI(
    title="SecureAPI Scanner",
    description="Automated API vulnerability scanner",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    await init_db()


SCANNER_MAP = {
    "rate_limit": rate_limit.run,
    "auth": auth.run,
    "sqli": sqli.run,
    "idor": idor.run,
    "mass_assignment": mass_assignment.run,
    "sensitive_data": sensitive_data.run,
    "ssrf": ssrf.run,
    "cmd_injection": cmd_injection.run,
    "cors": cors.run,
}


async def run_scanners(url, method, headers, body, selected_scanners):
    tasks = []
    scanner_names = []
    for name in selected_scanners:
        fn = SCANNER_MAP.get(name)
        if fn:
            tasks.append(fn(url=url, method=method, headers=headers, body=body))
            scanner_names.append(name)

    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings = []
    for name, result in zip(scanner_names, results):
        if isinstance(result, Exception):
            all_findings.append({
                "scanner": name,
                "severity": "info",
                "title": f"Scanner Error: {name}",
                "description": str(result),
                "evidence": None,
                "endpoint": url
            })
        else:
            all_findings.extend(result)
    return all_findings


def build_summary(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    total = sum(v for k, v in counts.items() if k != "info")
    return (
        f"Scan complete. Found {total} actionable issue(s): "
        f"{counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low."
    )


def scan_to_dict(scan):
    """Convert a ScanResult SQLAlchemy object to a plain dict."""
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "findings": scan.findings or [],
        "summary": scan.summary,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }


@app.get("/")
async def root():
    return {"name": "SecureAPI Scanner", "version": "1.0.0", "docs": "/docs"}


@app.get("/scanners")
async def list_scanners():
    return {
        "scanners": [
            {"id": "rate_limit",      "name": "Rate Limiting",                "severity": "high"},
            {"id": "auth",            "name": "Broken Auth / JWT Attacks",    "severity": "critical"},
            {"id": "sqli",            "name": "SQL Injection",                "severity": "critical"},
            {"id": "idor",            "name": "IDOR / BOLA",                  "severity": "high"},
            {"id": "mass_assignment", "name": "Mass Assignment",              "severity": "high"},
            {"id": "sensitive_data",  "name": "Sensitive Data Exposure",      "severity": "critical"},
            {"id": "ssrf",            "name": "SSRF Detection",               "severity": "critical"},
            {"id": "cmd_injection",   "name": "Command Injection",            "severity": "critical"},
            {"id": "cors",            "name": "CORS Misconfiguration",        "severity": "medium"},
        ]
    }


@app.post("/scan/single")
async def scan_single_endpoint(
    request: SingleEndpointScanRequest,
    db: AsyncSession = Depends(get_db)
):
    scan = ScanResult(
        target_url=request.url,
        scan_type="single",
        status="running"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        findings = await run_scanners(
            url=request.url,
            method=request.method,
            headers=request.headers or {},
            body=request.body or {},
            selected_scanners=request.scanners
        )
        scan.findings = findings
        scan.summary = build_summary(findings)
        scan.status = "done"
        scan.completed_at = datetime.utcnow()
    except Exception as e:
        scan.status = "failed"
        scan.summary = str(e)

    await db.commit()
    await db.refresh(scan)
    return scan_to_dict(scan)


@app.post("/scan/swagger")
async def scan_swagger_spec(
    request: SwaggerScanRequest,
    db: AsyncSession = Depends(get_db)
):
    spec = await fetch_spec(request.spec_url)
    if not spec:
        raise HTTPException(status_code=400, detail="Could not fetch or parse the spec.")

    endpoints = parse_endpoints(spec)
    if not endpoints:
        raise HTTPException(status_code=400, detail="No endpoints found in spec.")

    results = []
    for ep in endpoints:
        scan = ScanResult(
            target_url=ep["url"],
            scan_type="swagger",
            status="running"
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        try:
            findings = await run_scanners(
                url=ep["url"],
                method=ep["method"],
                headers={},
                body=ep.get("body", {}),
                selected_scanners=request.scanners
            )
            scan.findings = findings
            scan.summary = build_summary(findings)
            scan.status = "done"
            scan.completed_at = datetime.utcnow()
        except Exception as e:
            scan.status = "failed"
            scan.summary = str(e)

        await db.commit()
        await db.refresh(scan)
        results.append(scan_to_dict(scan))

    return results


@app.post("/scan/swagger/upload")
async def scan_swagger_upload(
    file: UploadFile = File(...),
    scanners: str = "",
    db: AsyncSession = Depends(get_db)
):
    content = await file.read()
    try:
        if file.filename.endswith((".yaml", ".yml")):
            spec = yaml.safe_load(content)
        else:
            spec = json.loads(content)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid spec file format.")

    endpoints = parse_endpoints(spec)
    if not endpoints:
        raise HTTPException(status_code=400, detail="No endpoints found in spec.")

    results = []
    for ep in endpoints:
        scan = ScanResult(
            target_url=ep["url"],
            scan_type="swagger",
            status="running"
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        try:
            findings = await run_scanners(
                url=ep["url"],
                method=ep["method"],
                headers={},
                body=ep.get("body", {}),
                selected_scanners=scanners.split(",") if scanners else list(SCANNER_MAP.keys())
            )
            scan.findings = findings
            scan.summary = build_summary(findings)
            scan.status = "done"
            scan.completed_at = datetime.utcnow()
        except Exception as e:
            scan.status = "failed"
            scan.summary = str(e)

        await db.commit()
        await db.refresh(scan)
        results.append(scan_to_dict(scan))

    return results


@app.get("/scans")
async def get_all_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanResult).order_by(ScanResult.created_at.desc())
    )
    scans = result.scalars().all()
    return [scan_to_dict(s) for s in scans]


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan_to_dict(scan)

@app.post("/discover")
async def discover_endpoints(request: dict):
    """Discover API endpoints from a website URL."""
    url = request.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required.")
    if not url.startswith("http"):
        url = "https://" + url
    try:
        results = await discovery.discover(url)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanResult).where(ScanResult.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    await db.delete(scan)
    await db.commit()
    return {"message": f"Scan {scan_id} deleted."}
