from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


class OrderItemSchema(BaseModel):
    name: str
    qty: int = 1
    price: float
    icon: Optional[str] = "🛍️"


class PaymentOtpRequest(BaseModel):
    session_id: str
    order_id: str
    amount: float
    currency: Optional[str] = "INR"
    items: Optional[List[OrderItemSchema]] = None
    item_summary: Optional[str] = None
    shipping_address: Optional[str] = None
    payment_method: Optional[str] = "UPI_1TAP"


class PaymentOtpResponse(BaseModel):
    success: bool = True
    challenge_id: str
    order_id: str
    masked_email: str
    expires_in_seconds: int = 300
    resend_cooldown_seconds: int = 15
    message: str
    amount: float
    currency: str = "INR"
    is_demo_otp: Optional[bool] = False
    otp: Optional[str] = None


class PaymentOtpVerifyRequest(BaseModel):
    session_id: str
    order_id: str
    challenge_id: str
    otp_code: str


class PaymentOtpVerifyResponse(BaseModel):
    success: bool
    order_id: str
    payment_status: str  # "PAID"
    payment_reference: str  # e.g. "SIM-PAY-XXXX"
    message: str
    amount: float
    currency: str = "INR"
    paid_at: str


class ShoppingOrderResponse(BaseModel):
    order_id: str
    date: str
    items: List[Dict[str, Any]]
    item_count: int
    amount: float
    payment_method: str
    payment_status: str
    payment_reference: Optional[str] = None
    shipping_to: Optional[str] = None

