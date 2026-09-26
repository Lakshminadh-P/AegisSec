"""
Security Report Routes

Generates security reports in JSON and HTML formats.
"""
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan
from app.security.auth import get_current_user
from app.services.risk_scoring import calculate_security_score
from sqlalchemy import desc

router = APIRouter(prefix="/api/reports", tags=["Reports"])


def _build_report(db: Session) -> dict:
    """Build the security report data."""
    vulns = db.query(Vulnerability).all()
    scans = db.query(Scan).order_by(desc(Scan.started_at)).limit(10).all()
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        if v.severity in severity_counts:
            severity_counts[v.severity] += 1
    
    vuln_list = []
    for v in vulns:
        vuln_list.append({
            "id": v.id,
            "title": v.title,
            "severity": v.severity,
            "source": v.source,
            "component": v.component,
            "status": v.status,
            "risk_score": v.risk_score,
            "cve": v.cve,
        })
    
    scan_list = []
    for s in scans:
        scan_list.append({
            "id": s.id,
            "scanner": s.scanner,
            "scan_type": s.status,
            "status": s.status,
            "findings_count": s.findings_count,
        })
    
    security_score = calculate_security_score(vulns)
    pipeline_pass = severity_counts["CRITICAL"] == 0
    
    return {
        "report_title": "AegisSec Security Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "security_score": security_score,
        "pipeline_status": "PASS" if pipeline_pass else "FAIL",
        "total_findings": len(vulns),
        "severity_breakdown": severity_counts,
        "vulnerabilities": vuln_list,
        "recent_scans": scan_list,
    }


@router.get("/json")
def get_json_report(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Generate security report in JSON format."""
    report = _build_report(db)
    return JSONResponse(content=report)


@router.get("/html")
def get_html_report(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Generate security report in HTML format."""
    report = _build_report(db)
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AegisSec Security Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1a1a2e; color: #e0e0e0; }}
            h1 {{ color: #00d4ff; }}
            h2 {{ color: #7f8fa6; margin-top: 30px; }}
            .score {{ font-size: 48px; font-weight: bold; color: {'#00d4ff' if report['security_score'] >= 70 else '#ff6b6b'}; }}
            .status {{ padding: 8px 16px; border-radius: 4px; font-weight: bold; display: inline-block; }}
            .pass {{ background: #00b894; color: white; }}
            .fail {{ background: #ff6b6b; color: white; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #2d3436; }}
            th {{ background: #2d3436; color: #00d4ff; }}
            .critical {{ color: #ff6b6b; }}
            .high {{ color: #fdcb6e; }}
            .medium {{ color: #ffa502; }}
            .low {{ color: #00b894; }}
            .meta {{ color: #7f8fa6; font-size: 14px; }}
        </style>
    </head>
    <body>
        <h1>🛡️ AegisSec Security Report</h1>
        <p class="meta">Generated: {report['generated_at']}</p>
        
        <h2>Security Score</h2>
        <div class="score">{report['security_score']}/100</div>
        
        <h2>Pipeline Status</h2>
        <span class="status {'pass' if report['pipeline_status'] == 'PASS' else 'fail'}">
            {report['pipeline_status']}
        </span>
        
        <h2>Severity Breakdown</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td class="critical">Critical</td><td>{report['severity_breakdown']['CRITICAL']}</td></tr>
            <tr><td class="high">High</td><td>{report['severity_breakdown']['HIGH']}</td></tr>
            <tr><td class="medium">Medium</td><td>{report['severity_breakdown']['MEDIUM']}</td></tr>
            <tr><td class="low">Low</td><td>{report['severity_breakdown']['LOW']}</td></tr>
        </table>
        
        <h2>Vulnerabilities ({report['total_findings']})</h2>
        <table>
            <tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Status</th><th>Risk</th></tr>
    """
    
    for v in report['vulnerabilities']:
        sev_class = v['severity'].lower()
        html += f"""<tr>
            <td>{v['id']}</td>
            <td>{v['title']}</td>
            <td class="{sev_class}">{v['severity']}</td>
            <td>{v['source']}</td>
            <td>{v['status']}</td>
            <td>{v['risk_score']}</td>
        </tr>\n"""
    
    html += """
        </table>
        <p class="meta" style="margin-top: 40px;">AegisSec — Automated DevSecOps Security Platform</p>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)
