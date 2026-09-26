"""
Security Events Routes

Provides access to the security audit log.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.security.auth import get_current_user
from app.services.scan_service import get_security_events

router = APIRouter(prefix="/api/events", tags=["Security Events"])


@router.get("/")
def list_events(
    limit: int = 50,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get recent security events."""
    events = get_security_events(db, limit)
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "description": e.description,
            "severity": e.severity,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in events
    ]
