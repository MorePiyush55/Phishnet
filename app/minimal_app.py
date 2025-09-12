"""Minimal FastAPI app for Phase 1: Backbone testing."""

import logging
from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db, init_db
from app.config.settings import get_settings
from app.config.logging import setup_logging
from app.models.complete_schema import User
from app.core.security import verify_password, create_access_token, verify_token

# Initialize settings and logging
settings = get_settings()
setup_logging()

logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    database: str
    users_count: int

class StatusResponse(BaseModel):
    message: str
    phase: str
    components: dict

class UserInfo(BaseModel):
    email: str
    role: str
    name: str
    created_at: datetime

# Create FastAPI app
app = FastAPI(
    title="PhishNet API",
    description="Phishing Email Detection and Response Platform - Phase 1",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Get current user from JWT token."""
    try:
        payload = verify_token(token)
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials"
            )
        
        user = db.query(User).filter(User.email == user_email).first()
        if user is None or user.disabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or disabled"
            )
        return user
    except Exception as e:
        logger.warning(f"Authentication failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info("Phase 1: Backbone - Config, Logging, DB Engine initialized")

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "PhishNet API - Phase 1: Backbone",
        "version": settings.APP_VERSION,
        "status": "running",
        "phase": "1-backbone",
        "docs": "/api/docs",
        "health": "/api/v1/health"
    }

# Authentication endpoints
@app.post("/api/v1/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and return JWT token."""
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or user.disabled or not verify_password(form_data.password, user.password_hash):
        logger.warning(f"Failed login attempt for: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    access_token = create_access_token(data={"sub": user.email})
    logger.info(f"Successful login for user: {user.email}")
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """Public health check endpoint."""
    try:
        # Test database connection and get user count
        users_count = db.query(User).count()
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "disconnected"
        users_count = 0
    
    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        timestamp=datetime.utcnow().isoformat() + "Z",
        version=settings.APP_VERSION,
        database=db_status,
        users_count=users_count
    )

@app.get("/api/v1/status", response_model=StatusResponse)
async def get_status(current_user: User = Depends(get_current_user)):
    """Protected status endpoint requiring authentication."""
    logger.info(f"Status requested by user: {current_user.email}")
    
    return StatusResponse(
        message="PhishNet Phase 1: Backbone is operational",
        phase="1-backbone",
        components={
            "database": "✅ Connected",
            "authentication": "✅ Working", 
            "logging": "✅ Active",
            "users": "✅ Created",
            "next_phase": "2-emails-domain"
        }
    )

@app.get("/api/v1/me", response_model=UserInfo)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information (requires authentication)."""
    return UserInfo(
        email=current_user.email,
        role=current_user.role,
        name=current_user.name or "Unknown",
        created_at=current_user.created_at
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.minimal_app:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )
