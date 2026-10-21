import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.routes.deps import get_current_user
from app.services.notification_service import NotificationService
from app.schemas.notification import (
    NotificationListResponse,
    DeviceNotificationResponse,
    NotificationActionRequest,
    NotificationActionResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=NotificationListResponse)
def get_user_notifications(
    unread_only: bool = False,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves security notifications for the authenticated user.
    Enforces user isolation: User A cannot see User B's notifications.
    """
    notifications, unread_count = NotificationService.get_user_notifications(
        db, current_user.id, unread_only=unread_only, limit=limit
    )

    items = [DeviceNotificationResponse.model_validate(n) for n in notifications]
    return NotificationListResponse(
        notifications=items,
        total=len(items),
        total_count=len(items),
        unread_count=unread_count
    )


@router.post("/{notification_id}/read")
def mark_notification_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Marks a specific notification as read.
    Enforces user ownership.
    """
    success = NotificationService.mark_read(db, notification_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found or access forbidden."
        )
    return {"status": "success", "notification_id": notification_id, "is_read": True}


@router.post("/mark-all-read")
def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Marks all notifications for the authenticated user as read.
    """
    count = NotificationService.mark_all_read(db, current_user.id)
    return {"status": "success", "marked_read_count": count}


@router.post("/{notification_id}/respond", response_model=NotificationActionResponse)
def respond_to_notification(
    notification_id: str,
    request: NotificationActionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enables account owner to confirm ("yes") or deny ("no") a new device login alert.
    - 'yes': confirms device as TRUSTED.
    - 'no': revokes device, terminates affected sessions, and logs security event.
    Strictly enforces that User A cannot confirm/deny User B's alerts.
    """
    try:
        updated_notif, device = NotificationService.respond_to_notification(
            db,
            notification_id=notification_id,
            user_id=current_user.id,
            decision=request.decision
        )
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(pe)
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )

    if not updated_notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification not found."
        )

    action_msg = (
        "Device confirmed and marked as TRUSTED."
        if request.decision.lower() == "yes"
        else "Suspicious device revoked and associated sessions terminated immediately."
    )

    return NotificationActionResponse(
        status="success",
        message=action_msg,
        notification_status=updated_notif.status,
        device_trust_state=device.trust_state if device else "UNKNOWN"
    )
