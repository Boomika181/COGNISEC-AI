from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


def utc_now():
    return datetime.now(timezone.utc)


class ShoppingOrder(Base):
    __tablename__ = "shopping_orders"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    order_id = Column(String(50), unique=True, index=True, nullable=False)  # e.g. "NYR-849201"
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="INR", nullable=False)
    item_summary = Column(String(255), nullable=False)
    items_json = Column(Text, nullable=True)  # JSON-encoded array of items
    shipping_address = Column(String(255), nullable=True)
    payment_method = Column(String(50), default="UPI_1TAP", nullable=False)
    payment_status = Column(String(30), default="PENDING", nullable=False)  # "PENDING", "PAID", "FAILED"
    payment_reference = Column(String(64), nullable=True)  # e.g. "SIM-PAY-9482A"
    challenge_id = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    paid_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", backref="shopping_orders", foreign_keys=[user_id])

