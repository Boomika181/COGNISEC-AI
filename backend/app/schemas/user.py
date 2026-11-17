import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    name: str
    email: EmailStr
    role: str = "USER"
    account_status: str = "ACTIVE"
    failed_login_attempts: int = 0


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    created_at: datetime.datetime
    email_verified: Optional[bool] = None
    security_enrollment_completed: bool = True
    email_verification_required: Optional[bool] = None
    masked_email: Optional[str] = None
    delivery_status: Optional[str] = None
    dev_otp: Optional[str] = None

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    name: Optional[str] = None
    account_status: Optional[str] = None
    role: Optional[str] = None
