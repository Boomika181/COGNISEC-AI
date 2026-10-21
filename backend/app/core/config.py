import os
import json
from typing import List, Union, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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

    # SMTP / Email Delivery Configuration
    SMTP_HOST: Optional[str] = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: str = "cognisecai.security@gmail.com"
    SMTP_FROM_NAME: str = "COGNISEC-AI Security"
    SMTP_TLS: bool = True
    SMTP_TIMEOUT_SECONDS: int = 15
    SMTP_ENABLED: bool = False
    VERIFIED_COGNISIC_MAILBOXES: List[str] = []
    VERIFIED_RECIPIENT_MAILBOXES: List[str] = []
    APP_BASE_URL: str = "http://127.0.0.1:5500"
    EXHIBITION_MODE: bool = False

    # Bootstrap Secret for Controlled Development/Admin Provisioning
    BOOTSTRAP_ADMIN_KEY: Optional[str] = "cognisec_dev_bootstrap_secret_2026"

    # Observation Window Configuration (Default 30s as required by policy)
    OBSERVATION_WINDOW_SECONDS: int = 30

    # Risk Engine Policies & Thresholds
    RISK_THRESHOLD_LOW: float = 0.30
    RISK_THRESHOLD_MEDIUM: float = 0.65
    RISK_THRESHOLD_HIGH: float = 0.85

    # Machine Learning & Behavioral Intelligence Configuration
    ML_IF_N_ESTIMATORS: int = 100
    ML_IF_RANDOM_STATE: int = 42
    ML_IF_CONTAMINATION: float = 0.05
    ML_IF_MIN_SAMPLES: int = 25
    ML_RETRAIN_INTERVAL: int = 10

    # Feature-specific minimum standard deviation (sigma) floors
    FEATURE_MIN_SIGMA: dict = {
        "typing_speed_wpm": 5.0,
        "avg_flight_time_ms": 15.0,
        "avg_dwell_time_ms": 10.0,
        "mouse_velocity_avg": 50.0,
        "mouse_acceleration_avg": 50.0,
        "mouse_curvature_entropy": 0.05,
        "click_frequency": 0.25,
        "scroll_speed_avg": 50.0,
        "idle_duration_sec": 1.0,
        "navigation_entropy": 0.05,
    }

    # Telemetry feature sanity validation bounds
    FEATURE_BOUNDS: dict = {
        "typing_speed_wpm": {"min": 0.0, "max": 350.0},
        "avg_flight_time_ms": {"min": 0.0, "max": 5000.0},
        "avg_dwell_time_ms": {"min": 0.0, "max": 3000.0},
        "mouse_velocity_avg": {"min": 0.0, "max": 10000.0},
        "mouse_acceleration_avg": {"min": 0.0, "max": 25000.0},
        "mouse_curvature_entropy": {"min": 0.0, "max": 5.0},
        "click_frequency": {"min": 0.0, "max": 100.0},
        "scroll_speed_avg": {"min": 0.0, "max": 20000.0},
        "idle_duration_sec": {"min": 0.0, "max": 86400.0},
        "navigation_entropy": {"min": 0.0, "max": 5.0},
    }

    # CORS: Explicit origins only (NO wildcard '*' with credentials)
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed = json.loads(v)
                    # Filter out wildcard and null if present
                    return [origin.strip() for origin in parsed if origin not in ("*", "null")]
                except Exception:
                    pass
            # Comma-separated string
            return [i.strip() for i in v.split(",") if i.strip() not in ("*", "null")]
        elif isinstance(v, list):
            return [origin.strip() for origin in v if origin not in ("*", "null")]
        return v

    @field_validator("VERIFIED_COGNISIC_MAILBOXES", "VERIFIED_RECIPIENT_MAILBOXES", mode="before")
    @classmethod
    def assemble_verified_mailboxes(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    parsed = json.loads(v)
                    return [m.strip().lower() for m in parsed if m and m.strip()]
                except Exception:
                    pass
            return [i.strip().lower() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return [str(m).strip().lower() for m in v if m and str(m).strip()]
        return v or []

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=(env_path, ".env", "backend/.env"),
        extra="allow"
    )


settings = Settings()
