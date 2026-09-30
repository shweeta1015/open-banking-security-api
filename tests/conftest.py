"""Pytest Fixtures and Test Environment Setup."""
import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.database import Base, get_db
from app.main import app
from app.security.crypto import ensure_rsa_keys
from app.security.rate_limiter import partner_limiter
from app.security.dpop import replay_cache
from app.seed import seed_database, DEMO_PARTNER_API_KEY, DEMO_CLIENT_ID

TEST_DB_URL = "sqlite:///./test_open_banking.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_keys():
    """Ensure RSA cryptographic keys exist before test execution."""
    ensure_rsa_keys()


@pytest.fixture(scope="function")
def db_session():
    """Provides a clean database session for each test function."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    seed_database(db)
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session):
    """Provides FastAPI TestClient wired to the test database and clean caches."""
    # Reset in-memory rate limiters and replay cache before each test
    partner_limiter.clear()
    with replay_cache._lock:
        replay_cache._cache.clear()

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
def valid_api_key():
    return DEMO_PARTNER_API_KEY


@pytest.fixture
def valid_client_id():
    return DEMO_CLIENT_ID
