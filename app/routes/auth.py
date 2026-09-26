"""
Authentication Routes

Handles user registration, login, and user management.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, UserResponse, Token
from app.security.auth import (
    hash_password, verify_password, create_access_token, get_current_user
)
from app.services.scan_service import log_security_event

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user account."""
    # Check if username already exists
    existing = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Validate role
    valid_roles = ["ADMIN", "SECURITY_ANALYST", "DEVELOPER"]
    if user.role.upper() not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Must be one of: {valid_roles}"
        )
    
    # Create user with hashed password
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hash_password(user.password),
        role=user.role.upper(),
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Log security event
    log_security_event(db, "USER_REGISTERED", f"New user: {user.username}", "INFO")
    
    return db_user


@router.post("/login", response_model=Token)
def login(user_login: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    user = db.query(User).filter(User.username == user_login.username).first()
    if not user or not verify_password(user_login.password, user.hashed_password):
        log_security_event(
            db, "LOGIN_FAILED",
            f"Failed login attempt for: {user_login.username}",
            "WARNING"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create JWT with username and role in payload
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    
    log_security_event(db, "LOGIN_SUCCESS", f"User logged in: {user.username}", "INFO", user.id)
    
    return Token(access_token=access_token)


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user's profile."""
    return current_user
