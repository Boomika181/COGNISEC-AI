from typing import Optional
from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    application: Optional[str] = "platform"
    device_fingerprint: Optional[str] = "unknown"
    browser: Optional[str] = None
    os: Optional[str] = None


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[str] = "USER"  # "USER" or "ADMIN"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: int
    name: str
    email: str
    session_id: Optional[str] = None


class TokenData(BaseModel):
    user_id: Optional[int] = None
    role: Optional[str] = None
