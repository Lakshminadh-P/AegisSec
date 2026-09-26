"""
Scan Service

Orchestrates security scans and manages scan lifecycle.
"""
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.models.scan import Scan, SecurityEvent


def create_scan(db: Session, scan_type: str, scanner: str, target: str = ".") -> Scan:
    """Create a new scan record."""
    scan = Scan(
        scan_type=scan_type,
        scanner=scanner,
        target=target,
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def update_scan_status(
    db: Session, scan_id: int, status: str,
    findings_count: int = 0, critical: int = 0, high: int = 0,
    medium: int = 0, low: int = 0, error_message: str = None
) -> Optional[Scan]:
    """Update scan status and counts."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    
    scan.status = status
    scan.findings_count = findings_count
    scan.critical_count = critical
    scan.high_count = high
    scan.medium_count = medium
    scan.low_count = low
    scan.error_message = error_message
    
    if status in ("COMPLETED", "FAILED"):
        scan.completed_at = datetime.now(timezone.utc)
    
    db.commit()
    db.refresh(scan)
    return scan


def get_scans(db: Session, skip: int = 0, limit: int = 50) -> List[Scan]:
    """Get all scans, newest first."""
    return db.query(Scan).order_by(desc(Scan.started_at)).offset(skip).limit(limit).all()


def get_scan(db: Session, scan_id: int) -> Optional[Scan]:
    """Get a single scan by ID."""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def log_security_event(
    db: Session, event_type: str, description: str,
    severity: str = "INFO", user_id: int = None
):
    """Log a security event for audit purposes."""
    event = SecurityEvent(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
    )
    db.add(event)
    db.commit()


def get_security_events(db: Session, limit: int = 50) -> List[SecurityEvent]:
    """Get recent security events."""
    return db.query(SecurityEvent).order_by(
        desc(SecurityEvent.timestamp)
    ).limit(limit).all()
