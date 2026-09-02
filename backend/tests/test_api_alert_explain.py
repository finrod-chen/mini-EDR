from collections.abc import Iterator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.base import Base
from app.models.user import VIEWER_ROLE
from app.services import ai_explain


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


@pytest.fixture
def client(session: Session) -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: UserSession(
        email="viewer@example.com", role=VIEWER_ROLE
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def add_alert(session: Session, ai_explanation: str | None = None) -> Alert:
    alert = Alert(
        severity="High", rule_name="r", host="PC-01", status="open", ai_explanation=ai_explanation
    )
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


def test_explain_unknown_alert_returns_404(client: TestClient) -> None:
    response = client.post("/api/alerts/00000000-0000-0000-0000-000000000000/explain")
    assert response.status_code == 404


def test_explain_returns_cached_value_without_calling_llm(
    client: TestClient, session: Session
) -> None:
    alert = add_alert(session, ai_explanation="舊的說明")
    with patch.object(ai_explain, "explain_alert") as mocked:
        response = client.post(f"/api/alerts/{alert.alert_id}/explain")

    assert response.status_code == 200
    assert response.json()["ai_explanation"] == "舊的說明"
    mocked.assert_not_called()


def test_explain_force_regenerates(client: TestClient, session: Session) -> None:
    alert = add_alert(session, ai_explanation="舊的說明")
    with patch.object(ai_explain, "explain_alert", return_value="新的說明"):
        response = client.post(f"/api/alerts/{alert.alert_id}/explain", params={"force": "true"})

    assert response.status_code == 200
    assert response.json()["ai_explanation"] == "新的說明"


def test_explain_not_configured_returns_503(client: TestClient, session: Session) -> None:
    alert = add_alert(session)
    with patch.object(
        ai_explain, "explain_alert", side_effect=ai_explain.LlmNotConfiguredError("no config")
    ):
        response = client.post(f"/api/alerts/{alert.alert_id}/explain")

    assert response.status_code == 503


def test_explain_llm_http_error_returns_502(client: TestClient, session: Session) -> None:
    import httpx

    alert = add_alert(session)
    with patch.object(
        ai_explain, "explain_alert", side_effect=httpx.HTTPError("boom")
    ):
        response = client.post(f"/api/alerts/{alert.alert_id}/explain")

    assert response.status_code == 502
