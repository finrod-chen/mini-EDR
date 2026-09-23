from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.main import app
from app.models.base import Base
from app.models.syslog_message import SyslogMessage
from app.models.user import VIEWER_ROLE

_BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


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
def viewer_client(session: Session) -> Iterator[TestClient]:
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: UserSession(
        email="user@example.com", role=VIEWER_ROLE
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def add_message(
    session: Session,
    *,
    received_at: datetime,
    source_ip: str = "192.168.2.200",
    source_type: str = "pan410",
    raw_message: str = "raw",
) -> None:
    session.add(
        SyslogMessage(
            received_at=received_at,
            source_ip=source_ip,
            source_type=source_type,
            raw_message=raw_message,
        )
    )
    session.commit()


def test_list_syslog_requires_login() -> None:
    with TestClient(app) as anon_client:
        response = anon_client.get("/api/syslog")
    assert response.status_code == 401


def test_list_syslog_returns_newest_first(viewer_client: TestClient, session: Session) -> None:
    add_message(session, received_at=_BASE, raw_message="older")
    add_message(session, received_at=_BASE + timedelta(seconds=10), raw_message="newer")

    response = viewer_client.get("/api/syslog")

    assert response.status_code == 200
    body = response.json()
    assert [row["raw_message"] for row in body] == ["newer", "older"]


def test_list_syslog_filters_by_source_type(viewer_client: TestClient, session: Session) -> None:
    add_message(session, received_at=_BASE, source_type="pan410", raw_message="from firewall")
    add_message(
        session,
        received_at=_BASE + timedelta(seconds=1),
        source_type="synology_nas",
        raw_message="from nas",
    )

    response = viewer_client.get("/api/syslog", params={"source_type": "synology_nas"})

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["raw_message"] == "from nas"


def test_list_syslog_filters_by_search_text(viewer_client: TestClient, session: Session) -> None:
    add_message(session, received_at=_BASE, raw_message="failed to log in from 1.2.3.4")
    add_message(
        session, received_at=_BASE + timedelta(seconds=1), raw_message="logged in successfully"
    )

    response = viewer_client.get("/api/syslog", params={"q": "failed"})

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert "failed" in body[0]["raw_message"]
