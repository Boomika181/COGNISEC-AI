import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.routes.deps import get_current_user
from app.services.device_service import DeviceService
from app.schemas.device import DeviceResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["Devices"])


class UpdateNicknameRequest(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=100)


@router.get("", response_model=List[DeviceResponse])
def get_user_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns persistent inventory of devices registered to the authenticated user.
    Enforces that regular users can only view their own devices.
    """
    devices = DeviceService.get_user_devices(db, current_user.id)
    return devices


@router.get("/{device_id}", response_model=DeviceResponse)
def get_device_detail(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves detailed metadata for a specific device.
    Verifies user ownership or ADMIN authorization.
    """
    device = DeviceService.get_device_by_id(db, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found."
        )

    if device.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You do not have permission to view this device."
        )

    return device


@router.post("/{device_id}/revoke")
def revoke_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revokes trust for a device and terminates all its active sessions immediately.
    Strictly verifies ownership or ADMIN role.
    """
    device = DeviceService.get_device_by_id(db, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found."
        )

    if device.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You cannot revoke another user's device."
        )

    success = DeviceService.revoke_device(db, device_id, reason="User initiated revocation")
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to revoke device."
        )

    return {
        "status": "success",
        "message": f"Device {device.nickname or device.device_id} has been revoked and all associated sessions terminated.",
        "device_id": device_id,
        "trust_state": "REVOKED"
    }


@router.put("/{device_id}/nickname")
def update_nickname(
    device_id: str,
    request: UpdateNicknameRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Allows user to give their device an identifiable nickname (e.g., 'Boomika Work MacBook').
    """
    device = DeviceService.get_device_by_id(db, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found."
        )

    if device.user_id != current_user.id and current_user.role.upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: You cannot rename another user's device."
        )

    updated = DeviceService.update_device_nickname(db, device_id, request.nickname)
    return {
        "status": "success",
        "message": "Device nickname updated.",
        "device_id": device_id,
        "nickname": updated.nickname if updated else request.nickname
    }
