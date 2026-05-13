from sqlalchemy import Column, Integer, String, DateTime, JSON, Text
from sqlalchemy.sql import func
from app.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)   # "single" or "swagger"
    status = Column(String, default="pending")   # pending / running / done / failed
    findings = Column(JSON, default=[])          # list of vulnerability findings
    summary = Column(Text, nullable=True)        # human-readable summary
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
