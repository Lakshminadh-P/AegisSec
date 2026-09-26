"""
Dashboard Routes

Provides aggregated security metrics for the dashboard.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.schemas.scan import DashboardStats
from app.security.auth import get_current_user
from app.services.risk_scoring import calculate_security_score
from sqlalchemy import desc

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Get aggregated security statistics for the dashboard."""
    vulns = db.query(Vulnerability).all()
    
    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    status_counts = {"OPEN": 0, "IN_PROGRESS": 0, "FIXED": 0, "FALSE_POSITIVE": 0}
    
    for v in vulns:
        if v.severity in severity_counts:
            severity_counts[v.severity] += 1
        if v.status in status_counts:
            status_counts[v.status] += 1
    
    # Get last scan
    last_scan = db.query(Scan).order_by(desc(Scan.started_at)).first()
    
    # Check if last scan passed (no critical findings)
    scan_pass = True
    if last_scan and last_scan.critical_count > 0:
        scan_pass = False
    
    security_score = calculate_security_score(vulns)
    
    return DashboardStats(
        total_vulnerabilities=len(vulns),
        critical_count=severity_counts["CRITICAL"],
        high_count=severity_counts["HIGH"],
        medium_count=severity_counts["MEDIUM"],
        low_count=severity_counts["LOW"],
        open_count=status_counts["OPEN"],
        in_progress_count=status_counts["IN_PROGRESS"],
        fixed_count=status_counts["FIXED"],
        false_positive_count=status_counts["FALSE_POSITIVE"],
        total_scans=db.query(Scan).count(),
        last_scan_time=last_scan.started_at if last_scan else None,
        security_score=security_score,
        scan_pass=scan_pass,
    )
