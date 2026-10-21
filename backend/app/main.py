import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.database.connection import engine
from app.database.base import Base
import app.models  # Ensures all ORM models are registered with Base metadata
from app.routes import (
    auth_router,
    users_router,
    sessions_router,
    behavior_router,
    security_router,
    admin_router,
    demo_router,
    devices_router,
    notifications_router,
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cognisec")

# Create database tables automatically upon startup and sync schema columns
Base.metadata.create_all(bind=engine)
try:
    from app.database.schema_sync import sync_device_and_notification_schemas, sync_session_schema, sync_application_grants_schema
    sync_device_and_notification_schemas()
    sync_session_schema()
    sync_application_grants_schema()
except Exception as e:
    logger.warning(f"Schema sync deferred: {e}")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Agentic Cognitive Zero Trust Identity Protection System — Multi-Application Behavioral Security Engine",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS for multi-portal web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(users_router, prefix=settings.API_V1_STR)
app.include_router(sessions_router, prefix=settings.API_V1_STR)
app.include_router(behavior_router, prefix=settings.API_V1_STR)
app.include_router(security_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)
app.include_router(demo_router, prefix=settings.API_V1_STR)
app.include_router(devices_router, prefix=settings.API_V1_STR)
app.include_router(notifications_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "system": settings.PROJECT_NAME,
        "status": "ONLINE",
        "zero_trust_engine": "ACTIVE",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy", "engine": "Cognisec-ZeroTrust-v1.0"}
