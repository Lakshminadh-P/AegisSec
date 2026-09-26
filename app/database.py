"""
AegisSec Database Configuration

Uses SQLAlchemy ORM with SQLite for local development.
SQLite is chosen for simplicity — no external database server needed.
In production, this could be swapped for PostgreSQL.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import get_settings

settings = get_settings()

# SQLite requires check_same_thread=False for FastAPI's async nature
connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency injection for database sessions.
    
    Yields a database session and ensures it's closed after use.
    This pattern prevents database connection leaks.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all database tables.
    
    Called on application startup to ensure tables exist.
    In production, you'd use Alembic migrations instead.
    """
    Base.metadata.create_all(bind=engine)
