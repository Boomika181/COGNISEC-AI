import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.models.behavior import BehaviorLog, BehavioralTrainingEvent
from app.schemas.behavior import BehaviorEventCreate


class BehaviorService:
    @staticmethod
    def derive_event_id(
        event_data: BehaviorEventCreate,
        fallback_log_id: Optional[int] = None
    ) -> Optional[str]:
        """
        Derives a deterministic, stable event identity from client telemetry metadata
        (telemetry_nonce, explicit context_signals.event_id, or sequence_number) so
        retries and crash recovery share the exact same idempotency key.
        Falls back to behavior_log:{fallback_log_id} when no client key is present.
        """
        nonce = getattr(event_data, "telemetry_nonce", None)
        if isinstance(nonce, str) and nonce.strip():
            return f"nonce:{event_data.session_id}:{nonce.strip()}"

        ctx = getattr(event_data, "context_signals", None)
        if isinstance(ctx, dict):
            explicit_id = ctx.get("event_id")
            if isinstance(explicit_id, str) and explicit_id.strip():
                return explicit_id.strip()

        seq = getattr(event_data, "sequence_number", None)
        if seq is not None:
            return f"seq:{event_data.session_id}:{int(seq)}"

        if fallback_log_id is not None:
            return f"behavior_log:{fallback_log_id}"
        return None

    @staticmethod
    def record_behavior_event(
        db: Session,
        user_id: int,
        event_data: BehaviorEventCreate
    ) -> BehaviorLog:
        """
        Stores structured behavioral telemetry in initial PENDING state and registers
        a corresponding durable BehavioralTrainingEvent in the same transaction.
        If a retry arrives for an existing deterministic event_id, returns the existing
        BehaviorLog row without creating duplicates.
        Never collects passwords or raw keystroke contents.
        """
        stable_event_id = BehaviorService.derive_event_id(event_data)
        if stable_event_id is not None:
            existing_evt = (
                db.query(BehavioralTrainingEvent)
                .filter(BehavioralTrainingEvent.event_id == stable_event_id)
                .first()
            )
            if existing_evt is not None and existing_evt.behavior_log_id is not None:
                existing_log = (
                    db.query(BehaviorLog)
                    .filter(
                        BehaviorLog.id == existing_evt.behavior_log_id,
                        BehaviorLog.user_id == user_id
                    )
                    .first()
                )
                if existing_log is not None:
                    return existing_log

        now_utc = datetime.now(timezone.utc)
        initial_payload = dict(event_data.context_signals or {})
        initial_payload["is_trusted"] = False
        initial_payload["eligibility_status"] = "PENDING"
        initial_payload["lifecycle_state"] = "PENDING"
        initial_payload["ml_registered"] = False
        initial_payload["worker_hydrated"] = False
        if getattr(event_data, "telemetry_nonce", None):
            initial_payload["telemetry_nonce"] = event_data.telemetry_nonce

        raw_vec_list = [
            float(event_data.typing_speed_wpm or 0.0),
            float(event_data.avg_flight_time_ms or 0.0),
            float(event_data.avg_dwell_time_ms or 0.0),
            float(event_data.mouse_velocity_avg or 0.0),
            float(event_data.mouse_acceleration_avg or 0.0),
            float(event_data.mouse_curvature_entropy or 0.0),
            float(event_data.click_frequency or 0.0),
            float(event_data.scroll_speed_avg or 0.0),
            float(event_data.idle_duration_sec or 0.0),
            float(event_data.navigation_entropy or 0.0),
        ]

        log = BehaviorLog(
            user_id=user_id,
            session_id=event_data.session_id,
            application=event_data.application.lower(),
            timestamp=now_utc,
            typing_speed_wpm=raw_vec_list[0],
            avg_flight_time_ms=raw_vec_list[1],
            avg_dwell_time_ms=raw_vec_list[2],
            mouse_velocity_avg=raw_vec_list[3],
            mouse_acceleration_avg=raw_vec_list[4],
            mouse_curvature_entropy=raw_vec_list[5],
            click_frequency=raw_vec_list[6],
            scroll_speed_avg=raw_vec_list[7],
            idle_duration_sec=raw_vec_list[8],
            navigation_entropy=raw_vec_list[9],
            raw_feature_json=json.dumps(initial_payload)
        )
        db.add(log)
        db.flush()

        canonical_event_id = stable_event_id or f"behavior_log:{log.id}"
        initial_payload["event_id"] = canonical_event_id
        log.raw_feature_json = json.dumps(initial_payload)

        existing_evt = (
            db.query(BehavioralTrainingEvent)
            .filter(BehavioralTrainingEvent.event_id == canonical_event_id)
            .first()
        )
        if existing_evt is None:
            training_evt = BehavioralTrainingEvent(
                event_id=canonical_event_id,
                user_id=user_id,
                session_id=event_data.session_id,
                behavior_log_id=log.id,
                lifecycle_state="PENDING",
                eligibility_status="PENDING",
                is_trusted=0,
                raw_vector_json=json.dumps(raw_vec_list),
                created_at=now_utc,
                updated_at=now_utc,
            )
            db.add(training_evt)
        else:
            if existing_evt.behavior_log_id is None:
                existing_evt.behavior_log_id = log.id

        try:
            db.commit()
            db.refresh(log)
            return log
        except IntegrityError as exc:
            db.rollback()
            err_msg = str(exc).lower()
            # Verify that the integrity error is specifically due to duplicate event_id
            is_dup_event = (
                "uq_behavioral_training_events_event_id" in err_msg
                or "behavioral_training_events.event_id" in err_msg
                or ("unique" in err_msg and "event_id" in err_msg)
                or ("unique" in err_msg and canonical_event_id.lower() in err_msg)
            )
            if not is_dup_event:
                existing_evt_check = (
                    db.query(BehavioralTrainingEvent)
                    .filter(BehavioralTrainingEvent.event_id == canonical_event_id)
                    .first()
                )
                if existing_evt_check is not None:
                    is_dup_event = True

            if not is_dup_event:
                # Unrelated database integrity error (e.g. foreign key, not-null, etc.)
                # MUST propagate correctly per Phase D requirement!
                raise

            # Duplicate event ID detected: retrieve the already-created winning event
            existing_evt = (
                db.query(BehavioralTrainingEvent)
                .filter(BehavioralTrainingEvent.event_id == canonical_event_id)
                .first()
            )
            if existing_evt is not None and existing_evt.behavior_log_id is not None:
                winning_log = (
                    db.query(BehaviorLog)
                    .filter(BehaviorLog.id == existing_evt.behavior_log_id)
                    .first()
                )
                if winning_log is not None:
                    return winning_log

            winning_log = (
                db.query(BehaviorLog)
                .filter(
                    BehaviorLog.user_id == user_id,
                    BehaviorLog.session_id == event_data.session_id
                )
                .order_by(BehaviorLog.id.desc())
                .first()
            )
            if winning_log is not None:
                return winning_log

            raise

    @staticmethod
    def mark_event_rejected(
        db: Session,
        log: Optional[BehaviorLog],
        event_id: str,
        persisted_payload: Dict[str, Any],
        rejection_reason: Optional[str] = None
    ) -> None:
        """
        Atomically transitions an ineligible or rejected telemetry event to the terminal
        REJECTED state in both BehavioralTrainingEvent and BehaviorLog.
        """
        now_utc = datetime.now(timezone.utc)
        persisted_payload["event_id"] = event_id
        persisted_payload["is_trusted"] = False
        persisted_payload["ml_registered"] = False
        persisted_payload["worker_hydrated"] = False
        persisted_payload["eligibility_status"] = "INELIGIBLE"
        persisted_payload["lifecycle_state"] = "REJECTED"
        if rejection_reason:
            persisted_payload["rejection_reason"] = str(rejection_reason)[:200]

        try:
            if log is not None:
                log.raw_feature_json = json.dumps(persisted_payload)

            evt = (
                db.query(BehavioralTrainingEvent)
                .filter(BehavioralTrainingEvent.event_id == event_id)
                .first()
            )
            if evt is not None:
                evt.lifecycle_state = "REJECTED"
                evt.eligibility_status = "REJECTED"
                evt.is_trusted = 0
                evt.rejection_reason = (str(rejection_reason)[:255] if rejection_reason else "Ineligible for ML training")
                evt.updated_at = now_utc
            elif log is not None:
                raw_vec_list = [
                    float(log.typing_speed_wpm),
                    float(log.avg_flight_time_ms),
                    float(log.avg_dwell_time_ms),
                    float(log.mouse_velocity_avg),
                    float(log.mouse_acceleration_avg),
                    float(log.mouse_curvature_entropy),
                    float(log.click_frequency),
                    float(log.scroll_speed_avg),
                    float(log.idle_duration_sec),
                    float(log.navigation_entropy),
                ]
                db.add(BehavioralTrainingEvent(
                    event_id=event_id,
                    user_id=log.user_id,
                    session_id=log.session_id,
                    behavior_log_id=log.id,
                    lifecycle_state="REJECTED",
                    eligibility_status="REJECTED",
                    is_trusted=0,
                    raw_vector_json=json.dumps(raw_vec_list),
                    rejection_reason=(str(rejection_reason)[:255] if rejection_reason else "Ineligible for ML training"),
                    created_at=now_utc,
                    updated_at=now_utc,
                ))
            db.commit()
        except Exception:
            db.rollback()

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
