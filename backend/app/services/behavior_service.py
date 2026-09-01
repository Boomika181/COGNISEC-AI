import json
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from app.models.behavior import BehaviorLog
from app.schemas.behavior import BehaviorEventCreate


class BehaviorService:
    @staticmethod
    def record_behavior_event(
        db: Session,
        user_id: int,
        event_data: BehaviorEventCreate
    ) -> BehaviorLog:
        """
        Stores structured behavioral telemetry.
        Never collects passwords or raw keystroke contents.
        """
        raw_json = json.dumps(event_data.context_signals or {})

        log = BehaviorLog(
            user_id=user_id,
            session_id=event_data.session_id,
            application=event_data.application.lower(),
            timestamp=datetime.now(timezone.utc),
            typing_speed_wpm=float(event_data.typing_speed_wpm or 0.0),
            avg_flight_time_ms=float(event_data.avg_flight_time_ms or 0.0),
            avg_dwell_time_ms=float(event_data.avg_dwell_time_ms or 0.0),
            mouse_velocity_avg=float(event_data.mouse_velocity_avg or 0.0),
            mouse_acceleration_avg=float(event_data.mouse_acceleration_avg or 0.0),
            mouse_curvature_entropy=float(event_data.mouse_curvature_entropy or 0.0),
            click_frequency=float(event_data.click_frequency or 0.0),
            scroll_speed_avg=float(event_data.scroll_speed_avg or 0.0),
            idle_duration_sec=float(event_data.idle_duration_sec or 0.0),
            navigation_entropy=float(event_data.navigation_entropy or 0.0),
            raw_feature_json=raw_json
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log

    @staticmethod
    def get_user_logs(db: Session, user_id: int, limit: int = 50) -> List[BehaviorLog]:
        return db.query(BehaviorLog).filter(
            BehaviorLog.user_id == user_id
        ).order_by(BehaviorLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_session_logs(db: Session, session_id: str) -> List[BehaviorLog]:
        return db.query(BehaviorLog).filter(
            BehaviorLog.session_id == session_id
        ).order_by(BehaviorLog.timestamp.asc()).all()
