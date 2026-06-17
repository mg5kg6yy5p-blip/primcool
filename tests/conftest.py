import os
from collections.abc import Iterator

import pytest


# Force test-friendly env BEFORE importing the app.
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.setdefault("ADMIN_TOKEN", "test-admin-token")
os.environ.setdefault("ALLOWED_ORIGINS", "*")


from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.models  # noqa: F401, E402  register models with Base
from app.core.context import set_actor  # noqa: E402
from app.core.deps import get_current_user  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.models.enums import UserRole  # noqa: E402
from app.models.user import User  # noqa: E402


@pytest.fixture
def client() -> Iterator[TestClient]:
    # StaticPool keeps a single shared connection so the :memory: DB
    # persists across sessions for the duration of the test.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def _get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    from app.main import app
    from uuid import uuid4

    admin_id = uuid4()
    bootstrap = TestingSession()
    bootstrap.add(User(
        id=admin_id,
        email="test-admin@primecool.local",
        password_hash="x",
        full_name="Test Admin",
        role=UserRole.admin,
        is_active=True,
    ))
    # Seed default billing rates so the Phase 5 billable cascade has rates
    # to look up. Mirrors migration 0007's bulk_insert.
    from app.models.billing import BillingRate
    bootstrap.add_all([
        BillingRate(role=UserRole.technician, hourly_amount=3000.0,
                    currency="JMD", is_active=True),
        BillingRate(role=UserRole.dispatcher, hourly_amount=4000.0,
                    currency="JMD", is_active=True),
        BillingRate(role=UserRole.admin, hourly_amount=5000.0,
                    currency="JMD", is_active=True),
    ])
    bootstrap.commit()
    bootstrap.close()

    from fastapi import Depends
    from sqlalchemy.orm import Session

    def _current_user(db: Session = Depends(_get_db)) -> User:
        # Use the request-cached session so set_actor() writes into the same
        # Session.info that the endpoint will read when calling record_audit.
        user = db.get(User, admin_id)
        set_actor(db, user.id)
        return user

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_user] = _current_user
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def raw_client():
    """A client that does NOT override get_current_user — for auth tests
    that exercise the real Bearer-token flow."""
    from fastapi.testclient import TestClient
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    def _get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    from app.main import app
    app.dependency_overrides[get_db] = _get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
