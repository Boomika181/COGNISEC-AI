import os
from typing import List, Union
from pydantic_settings import BaseSettings

# Absolute path to backend directory .env file
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
env_path = os.path.join(backend_dir, ".env")


class Settings(BaseSettings):
    PROJECT_NAME: str = "COGNISEC-AI"
    ENVIRONMENT: str = "development"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = "cognisec_super_secret_jwt_key_2026_agentic_zero_trust_defense"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    DATABASE_URL: str = "sqlite:///./cognisec.db"

    # Risk Engine Policies & Thresholds
    RISK_THRESHOLD_LOW: float = 0.30
    RISK_THRESHOLD_MEDIUM: float = 0.65
    RISK_THRESHOLD_HIGH: float = 0.85

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "null",
        "*",
    ]

    class Config:
        case_sensitive = True
        env_file = (env_path, ".env", "backend/.env")
        extra = "allow"


settings = Settings()
