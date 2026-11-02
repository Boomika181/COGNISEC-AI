import pytest
import hmac
import time
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app
from app.core.config import settings
from app.database.connection import SessionLocal
from app.models.user import User
from app.models.session import Session as DbSession
from app.models.shopping_order import ShoppingOrder
from app.models.application_grant import ApplicationGrant
from app.services.step_up_service import StepUpService
from app.services.email_service import EmailService

client = TestClient(app)

CUSTOMER_EMAIL = "customer.jane@auraluxe.com"
CUSTOMER_PASS = "Customer@123"
DELIVERY_TARGET = "boomikaram35@gmail.com"
MASKED_TARGET = "b***5@gmail.com"


@pytest.fixture(autouse=True)
def clean_challenges():
    StepUpService.reset()
    yield
    StepUpService.reset()


def create_active_shopping_session():
    """Helper to log in customer, advance 20s observation, and verify login OTP to obtain ACTIVE session."""
    res = client.post("/api/auth/login", json={
        "email": CUSTOMER_EMAIL,
        "password": CUSTOMER_PASS,
        "application": "shopping",
        "device_fingerprint": f"fp_shop_test_{int(time.time() * 1000)}",
        "browser": "TestClient/Browser",
        "os": "MacIntel"
    })
    assert res.status_code == 200, f"Login failed: {res.text}"
    data = res.json()
    token = data["access_token"]
    sid = data["session_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Simulate 20s observation elapsed
    db = SessionLocal()
    try:
        sess = db.query(DbSession).filter(DbSession.id == sid).first()
        sess.observation_started_at = datetime.now(timezone.utc) - timedelta(seconds=25)
        db.commit()
    finally:
        db.close()

    # Request and verify initial login OTP
    r_otp = client.post("/api/auth/login-otp/request", headers=headers, json={"session_id": sid})
    assert r_otp.status_code == 200, f"Login OTP request failed: {r_otp.text}"
    otp_data = r_otp.json()
    chal_id = otp_data["challenge_id"]

    # Inject known code into in-memory verifier
    known_code = "773912"
    with StepUpService._lock:
        if sid in StepUpService._challenges:
            StepUpService._challenges[sid]["otp_hash"] = StepUpService._hash_otp(known_code)

    r_ver = client.post("/api/auth/login-otp/verify", headers=headers, json={
        "session_id": sid,
        "challenge_id": chal_id,
        "otp_code": known_code
    })
    assert r_ver.status_code == 200, f"Login OTP verify failed: {r_ver.text}"
    assert r_ver.json()["session_status"] == "ACTIVE"

    return token, sid, headers


def test_payment_otp_request_dispatches_email_and_binds_order():
    """Requirement 1, 2, 3: Clicking Pay sends real email OTP to boomikaram35@gmail.com and displays masked recipient."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841920"
    amount = 14999.0

    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": amount,
        "currency": "INR",
        "item_summary": "Nyraa Titan Chronograph Watch",
        "items": [{"name": "Nyraa Titan Chronograph Watch", "qty": 1, "price": amount, "icon": "⌚"}],
        "shipping_address": "Jane Doe, Indiranagar, Bengaluru - 560038",
        "payment_method": "UPI_1TAP"
    }

    res = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    assert res.status_code == 200, f"Payment OTP request failed: {res.text}"
    data = res.json()

    assert data["success"] is True
    assert data["order_id"] == order_id
    assert data["masked_email"] == MASKED_TARGET
    assert data["amount"] == amount
    assert data["challenge_id"].startswith("chal_pay_")
    assert "b***5@gmail.com" in data["message"]

    # Verify order is recorded in DB as PENDING
    db = SessionLocal()
    try:
        order = db.query(ShoppingOrder).filter(ShoppingOrder.order_id == order_id).first()
        assert order is not None
        assert order.payment_status == "PENDING"
        assert order.amount == amount
        assert order.payment_reference is None
    finally:
        db.close()


def test_payment_otp_resend_cooldown_enforced():
    """Requirement 8: Resend cooldown is enforced (15s)."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841921"

    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": 4999.0,
        "item_summary": "Silk Scarf"
    }
    r1 = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    assert r1.status_code == 200

    # Immediate second request must trigger HTTP 429
    r2 = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    assert r2.status_code == 429
    assert "Please wait" in r2.json()["detail"]


def test_incorrect_otp_rejects_payment_and_decrements_attempts():
    """Requirement 5: Incorrect OTP rejects payment, leaves order PENDING, and limits attempts."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841922"

    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": 8999.0,
        "item_summary": "Leather Messenger Bag"
    }
    r_req = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    assert r_req.status_code == 200
    chal_id = r_req.json()["challenge_id"]

    # Attempt 1: bad OTP
    r_bad1 = client.post("/api/shopping/payment-otp/verify", headers=headers, json={
        "session_id": sid,
        "order_id": order_id,
        "challenge_id": chal_id,
        "otp_code": "000000"
    })
    assert r_bad1.status_code == 400
    assert "2 attempt(s) remaining" in r_bad1.json()["detail"]

    # Verify order is still PENDING
    db = SessionLocal()
    try:
        order = db.query(ShoppingOrder).filter(ShoppingOrder.order_id == order_id).first()
        assert order.payment_status == "PENDING"
        assert order.paid_at is None
    finally:
        db.close()

    # Attempt 2: bad OTP
    r_bad2 = client.post("/api/shopping/payment-otp/verify", headers=headers, json={
        "session_id": sid,
        "order_id": order_id,
        "challenge_id": chal_id,
        "otp_code": "111111"
    })
    assert r_bad2.status_code == 400
    assert "1 attempt(s) remaining" in r_bad2.json()["detail"]

    # Attempt 3: bad OTP -> locks challenge
    r_bad3 = client.post("/api/shopping/payment-otp/verify", headers=headers, json={
        "session_id": sid,
        "order_id": order_id,
        "challenge_id": chal_id,
        "otp_code": "222222"
    })
    assert r_bad3.status_code == 400
    assert "Maximum attempts exceeded" in r_bad3.json()["detail"]


def test_expired_otp_is_rejected():
    """Requirement 6: Expired OTP is rejected and challenge is purged."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841923"

    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": 3499.0,
        "item_summary": "Sunglasses"
    }
    r_req = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    chal_id = r_req.json()["challenge_id"]

    # Expire the challenge in memory
    with StepUpService._lock:
        if chal_id in StepUpService._challenges:
            StepUpService._challenges[chal_id]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=10)

    r_exp = client.post("/api/shopping/payment-otp/verify", headers=headers, json={
        "session_id": sid,
        "order_id": order_id,
        "challenge_id": chal_id,
        "otp_code": "123456"
    })
    assert r_exp.status_code == 400
    assert "expired" in r_exp.json()["detail"].lower()


def test_correct_otp_marks_order_paid_and_prevents_replay():
    """Requirement 4, 7: Correct OTP marks order PAID with payment reference, and cannot be reused."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841924"
    amount = 18999.0

    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": amount,
        "item_summary": "Studio ANC Headphones"
    }
    r_req = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    chal_id = r_req.json()["challenge_id"]

    known_code = "842915"
    with StepUpService._lock:
        if chal_id in StepUpService._challenges:
            StepUpService._challenges[chal_id]["otp_hash"] = StepUpService._hash_otp(known_code)

    r_ver = client.post("/api/shopping/payment-otp/verify", headers=headers, json={
        "session_id": sid,
        "order_id": order_id,
        "challenge_id": chal_id,
        "otp_code": known_code
    })
    assert r_ver.status_code == 200, f"Payment verify failed: {r_ver.text}"
    v_data = r_ver.json()

    assert v_data["success"] is True
    assert v_data["order_id"] == order_id
    assert v_data["payment_status"] == "PAID"
    assert v_data["payment_reference"].startswith("SIM-PAY-")
    assert v_data["amount"] == amount

    # Database verification
    db = SessionLocal()
    try:
        order = db.query(ShoppingOrder).filter(ShoppingOrder.order_id == order_id).first()
        assert order.payment_status == "PAID"
        assert order.payment_reference == v_data["payment_reference"]
        assert order.paid_at is not None
    finally:
        db.close()

    # Replay attempt with same challenge and code must fail
    r_replay = client.post("/api/shopping/payment-otp/verify", headers=headers, json={
        "session_id": sid,
        "order_id": order_id,
        "challenge_id": chal_id,
        "otp_code": known_code
    })
    assert r_replay.status_code == 400
    assert "No active payment verification challenge found" in r_replay.json()["detail"]


def test_smtp_failure_blocks_payment_challenge_creation():
    """Requirement 9: SMTP failure does not issue challenge or mark order paid."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841925"

    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": 2999.0,
        "item_summary": "Leather Wallet"
    }

    with patch.object(EmailService, "send_payment_otp_email", return_value=(False, "SMTP host connection timeout")):
        res = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
        assert res.status_code == 502
        assert "Email OTP transmission failed" in res.json()["detail"]

    # Verify no challenge exists in StepUpService
    assert StepUpService.get_challenge(sid) is None

    # Verify order in DB is not paid
    db = SessionLocal()
    try:
        order = db.query(ShoppingOrder).filter(ShoppingOrder.order_id == order_id).first()
        assert order is not None
        assert order.payment_status == "PENDING"
    finally:
        db.close()


def test_payment_otp_cannot_unlock_confidential_vault():
    """Requirement 10, 11: Payment OTP challenge ID cannot unlock Financial Vault; Vault strictly requires NeuralTrace."""
    token, sid, headers = create_active_shopping_session()
    order_id = "#NYR-841926"

    # Generate a payment OTP challenge
    payload = {
        "session_id": sid,
        "order_id": order_id,
        "amount": 14999.0,
        "item_summary": "Titan Chronograph"
    }
    r_pay = client.post("/api/shopping/payment-otp/request", headers=headers, json=payload)
    pay_chal_id = r_pay.json()["challenge_id"]

    # 1. Access decision for financial_vault strictly requires NeuralTrace (GESTURE_PATTERN)
    r_dec = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sid,
        "resource": "financial_vault",
        "application": "shopping"
    })
    assert r_dec.status_code == 200
    d_data = r_dec.json()
    assert d_data["decision"] == "STEP_UP_VERIFICATION"
    assert d_data["required_factor"] in ("GESTURE_PATTERN", "NEURALTRACE")
    assert d_data["required_factor"] != "OTP", "Confidential vault must NEVER use OTP!"

    # 2. Attempting to pass payment challenge ID to vault step-up verify is rejected
    r_bad_vault = client.post("/api/security/step-up/verify", headers=headers, json={
        "session_id": sid,
        "challenge_id": pay_chal_id,
        "challenge_type": "OTP",
        "challenge_code": "123456"
    })
    # Should fail because chal_pay is SHOPPING_PAYMENT, not vault step-up OTP
    assert r_bad_vault.status_code in (400, 401)

    # 3. Verify financial_vault remains locked
    r_vault = client.get("/api/security/vault/financial_vault", headers=headers)
    assert r_vault.status_code == 403


def test_high_and_critical_risk_vault_policy_preserved():
    """Requirement 12: High risk requires sequential dual cognitive verification; Critical risk terminates session."""
    token, sid, headers = create_active_shopping_session()

    # Elevate session to HIGH risk
    db = SessionLocal()
    try:
        sess = db.query(DbSession).filter(DbSession.id == sid).first()
        sess.current_risk_level = "HIGH"
        db.commit()
    finally:
        db.close()

    r_high = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sid,
        "resource": "financial_vault",
        "application": "shopping"
    })
    assert r_high.status_code == 200
    assert r_high.json()["required_factor"] == "HIGH_RISK_DUAL"

    # Elevate to CRITICAL risk
    db = SessionLocal()
    try:
        sess = db.query(DbSession).filter(DbSession.id == sid).first()
        sess.current_risk_level = "CRITICAL"
        db.commit()
    finally:
        db.close()

    r_crit = client.post("/api/security/access-decision", headers=headers, json={
        "session_id": sid,
        "resource": "financial_vault",
        "application": "shopping"
    })
    assert r_crit.status_code == 200
    assert r_crit.json()["decision"] == "TERMINATE_SESSION"


def test_unauthenticated_api_bypass_rejected():
    """Requirement 13: Direct API calls without valid authentication/session cannot mark orders paid."""
    # Without Authorization header
    r_no_auth = client.post("/api/shopping/payment-otp/request", json={
        "session_id": "sess_fake",
        "order_id": "#NYR-FAKE",
        "amount": 1000.0
    })
    assert r_no_auth.status_code in (401, 403)

    r_verify_no_auth = client.post("/api/shopping/payment-otp/verify", json={
        "session_id": "sess_fake",
        "order_id": "#NYR-FAKE",
        "challenge_id": "chal_fake",
        "otp_code": "123456"
    })
    assert r_verify_no_auth.status_code in (401, 403)
