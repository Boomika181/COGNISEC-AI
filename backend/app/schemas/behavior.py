import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class BehaviorEventCreate(BaseModel):
    session_id: str
    application: str  # "college", "ecommerce", "healthcare", "platform"
    
    # Statistical behavioral features (Privacy-safe: NO raw keystrokes or passwords)
    typing_speed_wpm: Optional[float] = 0.0
    avg_flight_time_ms: Optional[float] = 0.0
    avg_dwell_time_ms: Optional[float] = 0.0
    mouse_velocity_avg: Optional[float] = 0.0
    mouse_acceleration_avg: Optional[float] = 0.0
    mouse_curvature_entropy: Optional[float] = 0.0
    click_frequency: Optional[float] = 0.0
    scroll_speed_avg: Optional[float] = 0.0
    idle_duration_sec: Optional[float] = 0.0
    navigation_entropy: Optional[float] = 0.0
    
    # Contextual metadata
    context_signals: Optional[Dict[str, Any]] = None

    # Anti-Replay / Anti-Tamper Security Controls
    timestamp: Optional[float] = None  # Unix epoch seconds of telemetry capture
    sequence_number: Optional[int] = None  # Monotonically increasing stream sequence
    telemetry_nonce: Optional[str] = None  # Unique cryptographically random packet identifier


class BehaviorLogResponse(BaseModel):
    id: int
    user_id: int
    session_id: str
    application: str
    timestamp: datetime.datetime
    typing_speed_wpm: float
    avg_flight_time_ms: float
    avg_dwell_time_ms: float
    mouse_velocity_avg: float
    mouse_acceleration_avg: float
    mouse_curvature_entropy: float
    click_frequency: float
    scroll_speed_avg: float
    idle_duration_sec: float
    navigation_entropy: float
    raw_feature_json: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class BehaviorProfileResponse(BaseModel):
    id: int
    user_id: int
    sample_count: int
    profile_version: int
    last_updated: datetime.datetime
    baseline_features: Optional[Dict[str, Any]] = None
    baseline_status: str = "COLD_START"  # "COLD_START", "LEARNING", "ESTABLISHED"
    maturity_confidence: float = 0.0  # 0.0 to 1.0
    is_mature: bool = False  # True if sample_count >= 5

    # Machine Learning Isolation Forest Information
    ml_status: str = "ML_COLD_START"  # "ML_COLD_START", "ML_LEARNING", "ML_READY"
    model_sample_count: int = 0
    is_anomaly: bool = False
    anomaly_score: float = 0.0

    # Behavioral Telemetry & Identity Profile Dashboard Attributes
    total_observations: int = 0
    last_observation_timestamp: Optional[datetime.datetime] = None
    enrollment_status: str = "NOT_ENROLLED"  # "NOT_ENROLLED", "ENROLLMENT_IN_PROGRESS", "ENROLLED"
    latest_decision: Optional[str] = None
    latest_risk_score: Optional[float] = None
    latest_risk_level: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

