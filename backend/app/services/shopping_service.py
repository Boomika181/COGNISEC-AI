import json
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.shopping_order import ShoppingOrder
from app.schemas.shopping import OrderItemSchema

logger = logging.getLogger("cognisec.shopping")


class ShoppingService:
    @staticmethod
    def get_user_orders(db: Session, user_id: int) -> List[Dict[str, Any]]:
        """Returns all simulated orders for the user, newest first."""
        orders = (
            db.query(ShoppingOrder)
            .filter(ShoppingOrder.user_id == user_id)
            .order_id(ShoppingOrder.created_at.desc()) if hasattr(ShoppingOrder, "order_id") and False else
            db.query(ShoppingOrder)
            .filter(ShoppingOrder.user_id == user_id)
            .order_by(ShoppingOrder.created_at.desc())
            .all()
        )
        results = []
        for o in orders:
            items = []
            if o.items_json:
                try:
                    items = json.loads(o.items_json)
                except Exception:
                    items = [{"name": o.item_summary, "qty": 1, "price": o.amount}]
            else:
                items = [{"name": o.item_summary, "qty": 1, "price": o.amount}]

            item_count = sum(item.get("qty", 1) for item in items)
            results.append({
                "order_id": o.order_id,
                "date": o.created_at.strftime("%d %b %Y"),
                "items": items,
                "item_count": item_count,
                "amount": o.amount,
                "payment_method": o.payment_method,
                "payment_status": o.payment_status,
                "payment_reference": o.payment_reference,
                "shipping_to": o.shipping_address,
                "created_at": o.created_at.isoformat(),
                "paid_at": o.paid_at.isoformat() if o.paid_at else None,
            })
        return results

    @staticmethod
    def get_order_by_id(db: Session, user_id: int, order_id: str) -> Optional[ShoppingOrder]:
        """Retrieves an order by order_id ensuring user ownership."""
        return (
            db.query(ShoppingOrder)
            .filter(ShoppingOrder.user_id == user_id, ShoppingOrder.order_id == order_id)
            .first()
        )

    @staticmethod
    def create_or_update_pending_order(
        db: Session,
        user_id: int,
        session_id: str,
        order_id: str,
        amount: float,
        item_summary: str,
        items: Optional[List[OrderItemSchema]] = None,
        shipping_address: Optional[str] = None,
        payment_method: Optional[str] = "UPI_1TAP",
        challenge_id: Optional[str] = None
    ) -> ShoppingOrder:
        """
        Creates or updates a simulated shopping order in PENDING status.
        Ensures order amounts and item consistency.
        """
        existing = (
            db.query(ShoppingOrder)
            .filter(ShoppingOrder.order_id == order_id)
            .first()
        )
        items_payload = []
        if items:
            items_payload = [item.dict() if hasattr(item, "dict") else dict(item) for item in items]
        else:
            items_payload = [{"name": item_summary, "qty": 1, "price": amount}]

        items_json_str = json.dumps(items_payload)

        if existing:
            if existing.user_id != user_id:
                raise ValueError("Order ID already exists and belongs to another user account.")
            if existing.payment_status == "PAID":
                raise ValueError("Order is already paid.")
            existing.session_id = session_id
            existing.amount = amount
            existing.item_summary = item_summary
            existing.items_json = items_json_str
            if shipping_address:
                existing.shipping_address = shipping_address
            if payment_method:
                existing.payment_method = payment_method
            if challenge_id:
                existing.challenge_id = challenge_id
            db.commit()
            db.refresh(existing)
            return existing

        new_order = ShoppingOrder(
            order_id=order_id,
            user_id=user_id,
            session_id=session_id,
            amount=amount,
            currency="INR",
            item_summary=item_summary,
            items_json=items_json_str,
            shipping_address=shipping_address or "Indiranagar, Bengaluru - 560038",
            payment_method=payment_method or "UPI_1TAP",
            payment_status="PENDING",
            challenge_id=challenge_id
        )
        db.add(new_order)
        db.commit()
        db.refresh(new_order)
        return new_order

