import uuid
import pytest
from app.models.user import User
from app.models.device import Device
from app.models.notification import DeviceNotification
from app.services.notification_service import NotificationService


@pytest.fixture
def test_user_pair(client):
    """Creates two distinct isolated user accounts with unique emails per test run."""
    uid = uuid.uuid4().hex[:8]
    email_a = f"alpha_{uid}@cognisec.ai"
    email_b = f"beta_{uid}@cognisec.ai"

    res_a = client.post("/api/auth/register", json={
        "name": f"User Alpha {uid}",
        "email": email_a,
        "password": "Password123!",
        "role": "USER"
    })
    assert res_a.status_code == 201

    res_b = client.post("/api/auth/register", json={
        "name": f"User Beta {uid}",
        "email": email_b,
        "password": "Password123!",
        "role": "USER"
    })
    assert res_b.status_code == 201

    return res_a.json(), res_b.json()


def test_unauthenticated_notification_endpoints_return_401(client):
    """Verify unauthenticated requests cannot access any notification endpoints."""
    # 1. GET notifications
    res_get = client.get("/api/notifications")
    assert res_get.status_code == 401

    # 2. POST mark single read
    res_read = client.post("/api/notifications/test-notif-id/read")
    assert res_read.status_code == 401

    # 3. POST mark all read
    res_all_read = client.post("/api/notifications/mark-all-read")
    assert res_all_read.status_code == 401

    # 4. POST respond
    res_respond = client.post("/api/notifications/test-notif-id/respond", json={"decision": "yes"})
    assert res_respond.status_code == 401


def test_user_isolation_in_notification_retrieval(client, test_user_pair, db_session):
    """Verify User A cannot see User B's notifications under any circumstance."""
    user_a, user_b = test_user_pair

    # Login both users
    login_a = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_a_{user_a['id']}"
    }).json()
    tok_a = login_a["access_token"]

    login_b = client.post("/api/auth/login", json={
        "email": user_b["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_b_{user_b['id']}"
    }).json()
    tok_b = login_b["access_token"]

    # Create a unique confidential notification belonging exclusively to User B
    notif_b = DeviceNotification(
        user_id=user_b["id"],
        notification_type="CONFIDENTIAL_ALERT",
        title="User B Secret Security Alert",
        message="Confidential alert for User B only",
        status="PENDING_CONFIRMATION",
        email_delivery_status="SKIPPED_UNCONFIGURED",
        is_read=False
    )
    db_session.add(notif_b)
    db_session.commit()
    db_session.refresh(notif_b)

    # User A requests notifications
    res_a = client.get("/api/notifications", headers={"Authorization": f"Bearer {tok_a}"})
    assert res_a.status_code == 200
    data_a = res_a.json()
    # Confirm every notification seen by User A belongs to User A, and User B's notification is never present
    for item in data_a["notifications"]:
        assert item["user_id"] == user_a["id"]
        assert item["notification_id"] != notif_b.notification_id
        assert item["title"] != notif_b.title

    # User B requests notifications
    res_b = client.get("/api/notifications", headers={"Authorization": f"Bearer {tok_b}"})
    assert res_b.status_code == 200
    data_b = res_b.json()
    b_notif_ids = [n["notification_id"] for n in data_b["notifications"]]
    assert notif_b.notification_id in b_notif_ids
    for item in data_b["notifications"]:
        assert item["user_id"] == user_b["id"]


def test_cross_user_mark_read_forbidden(client, test_user_pair, db_session):
    """Verify User A cannot mark User B's notification as read."""
    user_a, user_b = test_user_pair

    login_a = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_a_{user_a['id']}"
    }).json()
    tok_a = login_a["access_token"]

    login_b = client.post("/api/auth/login", json={
        "email": user_b["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_b_{user_b['id']}"
    }).json()
    tok_b = login_b["access_token"]

    notif_b = DeviceNotification(
        user_id=user_b["id"],
        notification_type="NEW_DEVICE_LOGIN",
        title="User B Alert",
        message="Private alert for B",
        status="PENDING_CONFIRMATION",
        email_delivery_status="SKIPPED_UNCONFIGURED",
        is_read=False
    )
    db_session.add(notif_b)
    db_session.commit()
    db_session.refresh(notif_b)

    # User A tries to mark User B's notification as read
    res_a = client.post(
        f"/api/notifications/{notif_b.notification_id}/read",
        headers={"Authorization": f"Bearer {tok_a}"}
    )
    assert res_a.status_code == 404

    # Ensure not marked as read in database
    db_session.refresh(notif_b)
    assert notif_b.is_read is False

    # User B marks own notification as read
    res_b = client.post(
        f"/api/notifications/{notif_b.notification_id}/read",
        headers={"Authorization": f"Bearer {tok_b}"}
    )
    assert res_b.status_code == 200
    db_session.refresh(notif_b)
    assert notif_b.is_read is True


def test_cross_user_respond_decision_forbidden(client, test_user_pair, db_session):
    """Verify User A cannot respond to User B's notification alert."""
    user_a, user_b = test_user_pair

    login_a = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_a_{user_a['id']}"
    }).json()
    tok_a = login_a["access_token"]

    notif_b = DeviceNotification(
        user_id=user_b["id"],
        notification_type="NEW_DEVICE_LOGIN",
        title="User B Security Alert",
        message="Decision alert for B",
        status="PENDING_CONFIRMATION",
        email_delivery_status="SKIPPED_UNCONFIGURED",
        is_read=False
    )
    db_session.add(notif_b)
    db_session.commit()
    db_session.refresh(notif_b)

    # User A attempts to confirm/deny User B's notification
    res = client.post(
        f"/api/notifications/{notif_b.notification_id}/respond",
        headers={"Authorization": f"Bearer {tok_a}"},
        json={"decision": "yes"}
    )
    assert res.status_code == 403
    assert "forbidden" in res.json()["detail"].lower()


def test_mark_all_read_isolation(client, test_user_pair, db_session):
    """Verify mark-all-read updates ONLY the requesting user's unread notifications."""
    user_a, user_b = test_user_pair

    login_a = client.post("/api/auth/login", json={
        "email": user_a["email"],
        "password": "Password123!",
        "device_fingerprint": f"fp_a_{user_a['id']}"
    }).json()
    tok_a = login_a["access_token"]

    # 2 additional unread notifications for User A
    n_a1 = DeviceNotification(user_id=user_a["id"], notification_type="ALERT", title="A1", message="A1", is_read=False, email_delivery_status="SKIPPED_UNCONFIGURED")
    n_a2 = DeviceNotification(user_id=user_a["id"], notification_type="ALERT", title="A2", message="A2", is_read=False, email_delivery_status="SKIPPED_UNCONFIGURED")
    # 1 unread notification for User B
    n_b = DeviceNotification(user_id=user_b["id"], notification_type="ALERT", title="B1", message="B1", is_read=False, email_delivery_status="SKIPPED_UNCONFIGURED")
    db_session.add_all([n_a1, n_a2, n_b])
    db_session.commit()

    # Count how many unread notifications User A currently has
    unread_a_before = db_session.query(DeviceNotification).filter(
        DeviceNotification.user_id == user_a["id"],
        DeviceNotification.is_read == False
    ).count()
    assert unread_a_before >= 2

    # User A calls mark-all-read
    res = client.post("/api/notifications/mark-all-read", headers={"Authorization": f"Bearer {tok_a}"})
    assert res.status_code == 200
    assert res.json()["marked_read_count"] == unread_a_before

    # Verify all of User A's notifications are now read
    unread_a_after = db_session.query(DeviceNotification).filter(
        DeviceNotification.user_id == user_a["id"],
        DeviceNotification.is_read == False
    ).count()
    assert unread_a_after == 0

    # Verify User B's notification is STILL unread
    db_session.refresh(n_b)
    assert n_b.is_read is False
