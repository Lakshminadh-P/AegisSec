"""
Scan Schemas (Pydantic)
"""
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class ScanCreate(BaseModel):
    scan_type: str  # SAST, SCA, DAST, SECRET, CONTAINER, IAC
    scanner: str  # Tool name
    target: Optional[str] = "."


class ScanResponse(BaseModel):
    id: int
    scan_type: str
    scanner: str
    target: Optional[str] = None
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    open_count: int = 0
    in_progress_count: int = 0
    fixed_count: int = 0
    false_positive_count: int = 0
    total_scans: int = 0
    last_scan_time: Optional[datetime] = None
    security_score: float = 100.0
    scan_pass: bool = True
