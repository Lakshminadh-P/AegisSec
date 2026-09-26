"""
Vulnerability Management Routes

CRUD operations for security vulnerabilities.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.vulnerability import (
    VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityResponse
)
from app.security.auth import get_current_user, require_role
from app.services.vulnerability_service import (
    create_vulnerability, get_vulnerabilities, get_vulnerability,
    update_vulnerability, delete_vulnerability
)
from app.services.scan_service import log_security_event

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


@router.get("/", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """List vulnerabilities with optional filters."""
    return get_vulnerabilities(db, severity, status, source, search, skip, limit)


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def read_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get a single vulnerability by ID."""
    vuln = get_vulnerability(db, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.post("/", response_model=VulnerabilityResponse, status_code=201)
def add_vulnerability(
    vuln: VulnerabilityCreate,
    db: Session = Depends(get_db),
    user=Depends(require_role(["ADMIN", "SECURITY_ANALYST"])),
):
    """Create a new vulnerability (Admin/Analyst only)."""
    return create_vulnerability(db, vuln)


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
def modify_vulnerability(
    vuln_id: int,
    update: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_role(["ADMIN", "SECURITY_ANALYST"])),
):
    """Update a vulnerability (Admin/Analyst only)."""
    vuln = update_vulnerability(db, vuln_id, update)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    log_security_event(
        db, "VULN_UPDATED",
        f"Vulnerability #{vuln_id} updated by {user.username}",
        "INFO", user.id
    )
    return vuln


@router.put("/{vuln_id}/status")
def change_status(
    vuln_id: int,
    new_status: str = Query(...),
    db: Session = Depends(get_db),
    user=Depends(require_role(["ADMIN", "SECURITY_ANALYST"])),
):
    """Change vulnerability status."""
    valid_statuses = ["OPEN", "IN_PROGRESS", "FIXED", "FALSE_POSITIVE"]
    if new_status.upper() not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )
    
    update = VulnerabilityUpdate(status=new_status.upper())
    vuln = update_vulnerability(db, vuln_id, update)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    log_security_event(
        db, "VULN_STATUS_CHANGED",
        f"Vulnerability #{vuln_id} status changed to {new_status} by {user.username}",
        "INFO", user.id
    )
    return {"message": f"Status updated to {new_status}", "id": vuln_id}


@router.delete("/{vuln_id}")
def remove_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_role(["ADMIN"])),
):
    """Delete a vulnerability (Admin only)."""
    if not delete_vulnerability(db, vuln_id):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"message": "Vulnerability deleted", "id": vuln_id}
