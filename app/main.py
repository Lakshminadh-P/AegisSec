"""
AegisSec — Automated DevSecOps Security & Vulnerability Management Platform

Main application entry point.

This is a portfolio project demonstrating:
- Python/FastAPI backend development
- Cybersecurity vulnerability management
- Integration with security scanning tools
- DevSecOps pipeline concepts

Author: [Your Name]
Project: Educational DevSecOps Portfolio Project
"""
import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import get_settings
from app.database import init_db
from app.utils.sample_data import load_sample_data

# Import route modules
from app.routes import auth, dashboard, vulnerabilities, scans, reports, events

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup: Initialize database and load sample data
    print("\n" + "="*60)
    print("  🛡️  AegisSec — DevSecOps Security Platform")
    print("  Starting up...")
    print("="*60)
    
    init_db()
    load_sample_data()
    
    print(f"\n  Dashboard: http://localhost:{settings.port}")
    print(f"  API Docs:  http://localhost:{settings.port}/docs")
    print("="*60 + "\n")
    
    yield
    
    # Shutdown
    print("\n🛡️ AegisSec shutting down...")


# Create FastAPI application
app = FastAPI(
    title="AegisSec",
    description="Automated DevSecOps Security & Vulnerability Management Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware — allows frontend to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(vulnerabilities.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(events.router)

# Serve frontend static files
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


# --- Frontend page routes ---

@app.get("/")
def root():
    """Redirect to login page."""
    return RedirectResponse(url="/login")


@app.get("/login")
def login_page():
    """Serve login page."""
    return FileResponse(os.path.join(frontend_dir, "login.html"))


@app.get("/dashboard")
def dashboard_page():
    """Serve dashboard page."""
    return FileResponse(os.path.join(frontend_dir, "dashboard.html"))


@app.get("/vulnerabilities")
def vulnerabilities_page():
    """Serve vulnerabilities page."""
    return FileResponse(os.path.join(frontend_dir, "vulnerabilities.html"))


@app.get("/scans")
def scans_page():
    """Serve scans page."""
    return FileResponse(os.path.join(frontend_dir, "scans.html"))


@app.get("/reports")
def reports_page():
    """Serve reports page."""
    return FileResponse(os.path.join(frontend_dir, "reports.html"))


@app.get("/events")
def events_page():
    """Serve security events page."""
    return FileResponse(os.path.join(frontend_dir, "events.html"))


@app.get("/settings")
def settings_page():
    """Serve settings page."""
    return FileResponse(os.path.join(frontend_dir, "settings.html"))


# Health check endpoint
@app.get("/health")
def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy", "app": "AegisSec", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=True)
