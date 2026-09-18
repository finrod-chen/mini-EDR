from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.main import app
from app.models.base import Base
from app.models.response_action import ResponseAction
from app.models.user import ADMIN_ROLE, VIEWER_ROLE
from app.services import pan_os_remediation


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db_session:
        yield db_session


def make_client(session: Session, role: str) -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: UserSession(
        email="user@example.com", role=role
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def admin_client(session: Session) -> Iterator[TestClient]:
    yield from make_client(session, ADMIN_ROLE)


@pytest.fixture
def viewer_client(session: Session) -> Iterator[TestClient]:
    yield from make_client(session, VIEWER_ROLE)


def test_viewer_can_list_blocked_ips(viewer_client: TestClient) -> None:
    with patch.object(
        pan_os_remediation,
        "list_blocked_ips",
        return_value=[{"ip": "1.2.3.4", "tag": "mini-edr-blocked", "timeout_seconds": 86000}],
    ):
        response = viewer_client.get("/api/firewall/blocked-ips")

    assert response.status_code == 200
    assert response.json() == [
        {"ip": "1.2.3.4", "tag": "mini-edr-blocked", "timeout_seconds": 86000}
    ]


def test_list_blocked_ips_pan_os_error_returns_502(viewer_client: TestClient) -> None:
    with patch.object(
        pan_os_remediation, "list_blocked_ips", side_effect=pan_os_remediation.PanOsApiError("boom")
    ):
        response = viewer_client.get("/api/firewall/blocked-ips")

    assert response.status_code == 502


def test_viewer_cannot_unblock_ip(viewer_client: TestClient) -> None:
    response = viewer_client.post("/api/firewall/blocked-ips/unblock", json={"ip": "1.2.3.4"})
    assert response.status_code == 403


def test_admin_unblock_ip_success_records_response_action(
    admin_client: TestClient, session: Session
) -> None:
    with patch.object(
        pan_os_remediation, "unblock_ip", return_value='<response status="success"/>'
    ) as mocked:
        response = admin_client.post("/api/firewall/blocked-ips/unblock", json={"ip": "1.2.3.4"})

    assert response.status_code == 200
    mocked.assert_called_once_with("1.2.3.4", "mini-edr-blocked")
    action = session.execute(select(ResponseAction)).scalar_one()
    assert action.action_type == "unblock_firewall_ip"
    assert action.alert_id is None
    assert action.performed_by == "user@example.com"
    assert "1.2.3.4" in action.result
    assert "success" in action.result


def test_admin_unblock_ip_failure_returns_502_but_still_records_action(
    admin_client: TestClient, session: Session
) -> None:
    with patch.object(
        pan_os_remediation, "unblock_ip", side_effect=pan_os_remediation.PanOsApiError("boom")
    ):
        response = admin_client.post("/api/firewall/blocked-ips/unblock", json={"ip": "1.2.3.4"})

    assert response.status_code == 502
    action = session.execute(select(ResponseAction)).scalar_one()
    assert action.action_type == "unblock_firewall_ip"
    assert action.result is not None
    assert action.result.startswith("1.2.3.4: failed:")
