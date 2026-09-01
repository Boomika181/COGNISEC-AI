import pytest
import os
import sys

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.base import Base
from app.database.connection import get_db
from app.main import app
from app.core.security import get_password_hash
from app.models.user import User
from app.models.device import Device
from app.models.behavior import BehaviorProfile

TEST_DB_URL = "sqlite:///./test_cognisec.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    
    # Pre-seed test admin and user
    db = TestingSessionLocal()
    admin = User(
        name="Test Admin",
        email="test.admin@cognisec.ai",
        password_hash=get_password_hash("Admin@123"),
        role="ADMIN",
        account_status="ACTIVE"
    )
    user = User(
        name="Test User",
        email="test.user@cognisec.ai",
        password_hash=get_password_hash("User@123"),
        role="USER",
        account_status="ACTIVE"
    )
    db.add(admin)
    db.add(user)
    db.commit()
    db.close()

    yield

    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_cognisec.db"):
        try:
            os.remove("./test_cognisec.db")
        except Exception:
            pass


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def admin_token(client):
    res = client.post("/api/auth/login", json={
        "email": "test.admin@cognisec.ai",
        "password": "Admin@123",
        "application": "platform"
    })
    return res.json()["access_token"]


@pytest.fixture
def user_token(client):
    res = client.post("/api/auth/login", json={
        "email": "test.user@cognisec.ai",
        "password": "User@123",
        "application": "ecommerce"
    })
    return res.json()["access_token"]
