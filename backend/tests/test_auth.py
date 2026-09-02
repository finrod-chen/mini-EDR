from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.auth import UserSession, get_current_user, require_admin
from app.core.config import settings
from app.main import app
from app.models.base import Base
from app.models.user import ADMIN_ROLE, VIEWER_ROLE
from app.services.users import get_or_create_user

client = TestClient(app)


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_get_or_create_user_bootstraps_first_user_as_admin() -> None:
    session = make_session()
    user = get_or_create_user(session, "first@example.com")
    assert user.role == ADMIN_ROLE


def test_get_or_create_user_second_user_is_viewer() -> None:
    session = make_session()
    get_or_create_user(session, "first@example.com")
    second = get_or_create_user(session, "second@example.com")
    assert second.role == VIEWER_ROLE


def test_get_or_create_user_is_idempotent_for_same_email() -> None:
    session = make_session()
    first = get_or_create_user(session, "same@example.com")
    again = get_or_create_user(session, "same@example.com")
    assert first.id == again.id


def test_get_or_create_user_seed_admin_is_admin_even_when_not_first() -> None:
    session = make_session()
    get_or_create_user(session, "first@example.com")  # 佔掉 bootstrap 的第一個名額

    with patch.object(settings, "seed_admin_emails", "seed-admin@example.com"):
        seed_user = get_or_create_user(session, "seed-admin@example.com")

    assert seed_user.role == ADMIN_ROLE


def test_get_or_create_user_upgrades_existing_seed_admin() -> None:
    session = make_session()
    get_or_create_user(session, "first@example.com")  # bootstrap admin,佔掉名額
    with patch.object(settings, "seed_admin_emails", ""):
        existing = get_or_create_user(session, "later-admin@example.com")
    assert existing.role == VIEWER_ROLE

    with patch.object(settings, "seed_admin_emails", "later-admin@example.com"):
        upgraded = get_or_create_user(session, "later-admin@example.com")

    assert upgraded.id == existing.id
    assert upgraded.role == ADMIN_ROLE


def test_get_or_create_user_seed_admin_match_is_case_insensitive() -> None:
    session = make_session()
    with patch.object(settings, "seed_admin_emails", "Seed-Admin@Example.com"):
        user = get_or_create_user(session, "seed-admin@example.com")
    assert user.role == ADMIN_ROLE


def test_me_endpoint_requires_login() -> None:
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_me_endpoint_returns_current_user_when_overridden() -> None:
    app.dependency_overrides[get_current_user] = lambda: UserSession(
        email="admin@example.com", role=ADMIN_ROLE
    )
    try:
        response = client.get("/auth/me")
        assert response.status_code == 200
        assert response.json() == {"email": "admin@example.com", "role": "admin"}
    finally:
        app.dependency_overrides.clear()


def test_require_admin_rejects_viewer() -> None:
    with pytest.raises(HTTPException) as exc_info:
        require_admin(UserSession(email="viewer@example.com", role=VIEWER_ROLE))
    assert exc_info.value.status_code == 403


def test_require_admin_allows_admin() -> None:
    user = UserSession(email="admin@example.com", role=ADMIN_ROLE)
    assert require_admin(user) is user
