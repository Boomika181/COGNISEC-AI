import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.user import User
from app.routes.deps import get_current_user
from app.services.session_service import SessionService
from app.services.step_up_service import StepUpService
from app.services.shopping_service import ShoppingService
from app.schemas.shopping import (
    PaymentOtpRequest,
    PaymentOtpResponse,
    PaymentOtpVerifyRequest,
    PaymentOtpVerifyResponse,
    ShoppingOrderResponse
)

logger = logging.getLogger("cognisec.shopping")
router = APIRouter(prefix="/shopping", tags=["Shopping Checkout & Payment Verification"])


@router.post("/payment-otp/request", response_model=PaymentOtpResponse)
def request_payment_otp(
    request: PaymentOtpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Initiates payment authorization OTP for Shopping checkout.
    Dispatches a single-use 6-digit code via Gmail SMTP to user's registered address (boomikaram35@gmail.com).
    Binds challenge to order ID, amount, session, and user.
    """
    if not request.session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Session ID is required."
        )

    session = SessionService.get_session(db, request.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to the authenticated user."
        )

    if session.status in ("TERMINATED", "REVOKED") or session.current_risk_level == "CRITICAL":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session is terminated or restricted by security policy."
        )

    if session.status in ("PENDING_OBSERVATION", "PENDING_OTP"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Baseline behavioral observation or initial login verification is incomplete."
        )

    if request.amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Order amount must be greater than zero."
        )

    item_summary = request.item_summary
    if not item_summary and request.items:
        first = request.items[0]
        cnt = len(request.items)
        item_summary = f"{first.name}" + (f" + {cnt - 1} more items" if cnt > 1 else "")
    elif not item_summary:
        item_summary = f"Shopping Order {request.order_id}"

    # Persist or update pending order
    order = ShoppingService.create_or_update_pending_order(
        db=db,
        user_id=current_user.id,
        session_id=session.id,
        order_id=request.order_id,
        amount=request.amount,
        item_summary=item_summary,
        items=request.items,
        shipping_address=request.shipping_address,
        payment_method=request.payment_method
    )

    challenge_data = StepUpService.create_payment_otp_challenge(
        session_id=session.id,
        user_id=current_user.id,
        order_id=request.order_id,
        amount=request.amount,
        item_summary=item_summary,
        db=db
    )

    # Link challenge_id to order
    order.challenge_id = challenge_data["challenge_id"]
    db.commit()

    return PaymentOtpResponse(**challenge_data)


@router.post("/payment-otp/verify", response_model=PaymentOtpVerifyResponse)
def verify_payment_otp(
    request: PaymentOtpVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Atomically verifies the single-use payment OTP code.
    Upon success: marks simulated order as PAID, sets unique demo payment reference, and logs security event.
    Upon failure: rejects payment, keeps order PENDING, decrements remaining attempts.
    """
    session = SessionService.get_session(db, request.session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found."
        )

    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to the authenticated user."
        )

    success, message, payment_ref = StepUpService.verify_payment_otp(
        session_id=request.session_id,
        user_id=current_user.id,
        order_id=request.order_id,
        challenge_id=request.challenge_id,
        otp_code=request.otp_code,
        db=db
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    order = ShoppingService.get_order_by_id(db, current_user.id, request.order_id)
    amount = order.amount if order else 0.0
    paid_iso = order.paid_at.isoformat() if (order and order.paid_at) else datetime.now(timezone.utc).isoformat()

    return PaymentOtpVerifyResponse(
        success=True,
        order_id=request.order_id,
        payment_status="PAID",
        payment_reference=payment_ref or f"SIM-PAY-{request.order_id}",
        message=message,
        amount=amount,
        currency="INR",
        paid_at=paid_iso
    )


@router.post("/payment-otp/resend", response_model=PaymentOtpResponse)
def resend_payment_otp(
    request: PaymentOtpRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resends payment verification OTP subject to cooldown (15s).
    Invalidates prior challenge and issues fresh code.
    """
    session = SessionService.get_session(db, request.session_id)
    if not session or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid session."
        )

    challenge_data = StepUpService.resend_payment_otp_challenge(
        session_id=request.session_id,
        user_id=current_user.id,
        order_id=request.order_id,
        db=db
    )
    return PaymentOtpResponse(**challenge_data)


@router.get("/orders")
def get_shopping_orders(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns order history for the authenticated customer."""
    return ShoppingService.get_user_orders(db, current_user.id)


@router.get("/orders/{order_id}")
def get_shopping_order_status(
    order_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetches real-time status of a specific order."""
    order = ShoppingService.get_order_by_id(db, current_user.id, order_id)
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Order '{order_id}' not found."
        )
    return {
        "order_id": order.order_id,
        "amount": order.amount,
        "payment_status": order.payment_status,
        "payment_reference": order.payment_reference,
        "item_summary": order.item_summary,
        "created_at": order.created_at.isoformat(),
        "paid_at": order.paid_at.isoformat() if order.paid_at else None
    }

