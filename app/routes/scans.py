"""
Security Scan Routes

Endpoints for running and managing security scans.
"""
import asyncio
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.scan import ScanCreate, ScanResponse
from app.security.auth import get_current_user, require_role
from app.services.scan_service import create_scan, get_scans, get_scan, update_scan_status, log_security_event
from app.scanners import get_available_scanners, run_scanner

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """List all security scans."""
    return get_scans(db, skip, limit)


@router.get("/tools")
def list_tools():
    """List available security scanning tools."""
    return get_available_scanners()


@router.post("/run", response_model=ScanResponse)
def start_scan(
    scan_req: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user=Depends(require_role(["ADMIN", "SECURITY_ANALYST"])),
):
    """Start a security scan.
    
    The scan runs in the background so the API responds immediately.
    """
    # Create scan record
    scan = create_scan(db, scan_req.scan_type, scan_req.scanner, scan_req.target or ".")
    
    # Run the scan in the background
    background_tasks.add_task(run_scanner, scan.id, scan_req.scanner, scan_req.target or ".")
    
    log_security_event(
        db, "SCAN_STARTED",
        f"Scan started: {scan_req.scanner} ({scan_req.scan_type}) by {user.username}",
        "INFO", user.id
    )
    
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
def read_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get details of a specific scan."""
    scan = get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
