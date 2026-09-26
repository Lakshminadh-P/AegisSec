"""
Scan, ScanResult, and SecurityEvent Models

Scan: Tracks each security scan execution
ScanResult: Links scans to their vulnerability findings
SecurityEvent: Audit log of security-relevant actions
"""
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.sql import func
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(20), nullable=False)  # SAST, SCA, DAST, SECRET, CONTAINER, IAC
    scanner = Column(String(50), nullable=False)  # Tool name (e.g., semgrep, bandit)
    target = Column(String(500), nullable=True)  # What was scanned
    status = Column(String(20), default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False)  # LOGIN, SCAN_STARTED, VULN_FIXED, etc.
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="INFO")  # INFO, WARNING, CRITICAL
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
