import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.base import Base
from app.models.events import ProcessEvent
from app.models.response_action import ResponseAction
from app.models.user import ADMIN_ROLE, VIEWER_ROLE
from app.services import file_verification, velociraptor_remediation


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


def add_alert(session: Session, host: str | None = "PC-01") -> Alert:
    alert = Alert(severity="High", rule_name="r", host=host, status="open", created_at=None)
    session.add(alert)
    session.commit()
    session.refresh(alert)
    return alert


def test_viewer_cannot_perform_actions(viewer_client: TestClient, session: Session) -> None:
    alert = add_alert(session)
    response = viewer_client.post(
        f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "ignore"}
    )
    assert response.status_code == 403


def test_unknown_alert_returns_404(admin_client: TestClient) -> None:
    response = admin_client.post(
        "/api/alerts/00000000-0000-0000-0000-000000000000/actions",
        json={"action_type": "ignore"},
    )
    assert response.status_code == 404


def test_ignore_marks_alert_resolved(admin_client: TestClient, session: Session) -> None:
    alert = add_alert(session)
    response = admin_client.post(
        f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "ignore"}
    )
    assert response.status_code == 200
    session.refresh(alert)
    assert alert.status == "resolved"
    assert session.execute(select(ResponseAction)).scalar_one().action_type == "ignore"


def test_mark_false_positive_updates_status(admin_client: TestClient, session: Session) -> None:
    alert = add_alert(session)
    response = admin_client.post(
        f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "mark_false_positive"}
    )
    assert response.status_code == 200
    session.refresh(alert)
    assert alert.status == "false_positive"


def test_kill_process_without_pid_is_rejected(admin_client: TestClient, session: Session) -> None:
    alert = add_alert(session)
    response = admin_client.post(
        f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "kill_process"}
    )
    assert response.status_code == 422


def test_quarantine_without_host_is_rejected(admin_client: TestClient, session: Session) -> None:
    alert = add_alert(session, host=None)
    response = admin_client.post(
        f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "quarantine"}
    )
    assert response.status_code == 422


def test_quarantine_success_calls_velociraptor_and_acknowledges(
    admin_client: TestClient, session: Session
) -> None:
    alert = add_alert(session, host="PC-01")
    with patch.object(
        velociraptor_remediation, "quarantine_host", return_value='{"flow_id": "F.ABC"}'
    ) as mocked:
        response = admin_client.post(
            f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "quarantine"}
        )

    assert response.status_code == 200
    mocked.assert_called_once_with("PC-01")
    session.refresh(alert)
    assert alert.status == "acknowledged"
    body = response.json()
    assert "F.ABC" in body["result"]


def test_kill_process_success_passes_pid(admin_client: TestClient, session: Session) -> None:
    alert = add_alert(session, host="PC-01")
    with patch.object(
        velociraptor_remediation, "kill_process", return_value='{"flow_id": "F.XYZ"}'
    ) as mocked:
        response = admin_client.post(
            f"/api/alerts/{alert.alert_id}/actions",
            json={"action_type": "kill_process", "pid": 4321},
        )

    assert response.status_code == 200
    mocked.assert_called_once_with("PC-01", 4321)
    session.refresh(alert)
    assert alert.status == "acknowledged"


def test_quarantine_failure_is_recorded_but_alert_stays_open(
    admin_client: TestClient, session: Session
) -> None:
    alert = add_alert(session, host="PC-01")
    with patch.object(
        velociraptor_remediation,
        "quarantine_host",
        side_effect=velociraptor_remediation.ClientNotFoundError("boom"),
    ):
        response = admin_client.post(
            f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "quarantine"}
        )

    assert response.status_code == 200
    body = response.json()
    assert body["result"].startswith("failed:")
    session.refresh(alert)
    assert alert.status == "open"


def test_verify_file_without_file_path_is_rejected(
    admin_client: TestClient, session: Session
) -> None:
    alert = add_alert(session)
    response = admin_client.post(
        f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "verify_file"}
    )
    assert response.status_code == 422


def test_verify_file_without_host_is_rejected(admin_client: TestClient, session: Session) -> None:
    alert = add_alert(session, host=None)
    response = admin_client.post(
        f"/api/alerts/{alert.alert_id}/actions",
        json={"action_type": "verify_file", "file_path": "C:\\Windows\\win.ini"},
    )
    assert response.status_code == 422


def test_verify_file_success_does_not_change_alert_status(
    admin_client: TestClient, session: Session
) -> None:
    alert = add_alert(session, host="PC-01")
    classification = file_verification.ClassificationResult(
        declared_path="C:\\Windows\\win.ini",
        file_size=92,
        sha256="abc123",
        detected_label="ini",
        detected_mime_type="text/plain",
        detected_extensions=["ini"],
        extension_mismatch=False,
    )
    with patch.object(
        file_verification, "verify_file", return_value=classification
    ) as mocked:
        response = admin_client.post(
            f"/api/alerts/{alert.alert_id}/actions",
            json={"action_type": "verify_file", "file_path": "C:\\Windows\\win.ini"},
        )

    assert response.status_code == 200
    mocked.assert_called_once_with("PC-01", "C:\\Windows\\win.ini")
    session.refresh(alert)
    # 唯讀調查動作,不像 quarantine/kill_process 會把 alert 狀態改成 acknowledged。
    assert alert.status == "open"
    body = response.json()
    assert body["result"] is not None
    result_payload = json.loads(body["result"])
    assert result_payload["detected_label"] == "ini"
    assert result_payload["extension_mismatch"] is False


def test_verify_file_failure_is_recorded_but_alert_stays_open(
    admin_client: TestClient, session: Session
) -> None:
    alert = add_alert(session, host="PC-01")
    with patch.object(
        file_verification,
        "verify_file",
        side_effect=file_verification.FileNotFoundOnClientError("boom"),
    ):
        response = admin_client.post(
            f"/api/alerts/{alert.alert_id}/actions",
            json={"action_type": "verify_file", "file_path": "C:\\nope.exe"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["result"].startswith("failed:")
    session.refresh(alert)
    assert alert.status == "open"


def test_response_action_records_performed_by_and_time(
    admin_client: TestClient, session: Session
) -> None:
    alert = add_alert(session)
    before = datetime.now(UTC)
    admin_client.post(f"/api/alerts/{alert.alert_id}/actions", json={"action_type": "ignore"})

    action = session.execute(select(ResponseAction)).scalar_one()
    assert action.performed_by == "user@example.com"
    assert action.performed_at is not None
    assert action.performed_at.replace(tzinfo=UTC) >= before


def test_related_events_returns_process_events_in_time_window(
    viewer_client: TestClient, session: Session
) -> None:
    # 這是唯讀調查資料,不像 quarantine/kill_process/verify_file 需要 admin,
    # 用 viewer_client 測正好確認這一點。
    alert_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    alert = Alert(
        severity="High", rule_name="r", host="PC-01", status="open", created_at=alert_time
    )
    session.add(alert)
    session.add(
        ProcessEvent(
            timestamp=alert_time,
            hostname="PC-01",
            pid=1234,
            ppid=1,
            user="DOMAIN\\alice",
            image="C:\\Users\\Public\\invoice.pdf.exe",
            command_line="invoice.pdf.exe",
        )
    )
    # 時間窗外、不同主機的事件都不該出現。
    session.add(
        ProcessEvent(
            timestamp=alert_time - timedelta(hours=1),
            hostname="PC-01",
            pid=1,
            image="C:\\Windows\\explorer.exe",
        )
    )
    session.add(
        ProcessEvent(timestamp=alert_time, hostname="PC-99", pid=1, image="C:\\other.exe")
    )
    session.commit()
    session.refresh(alert)

    response = viewer_client.get(f"/api/alerts/{alert.alert_id}/related-events")

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["pid"] == 1234
    assert body[0]["image"] == "C:\\Users\\Public\\invoice.pdf.exe"
    assert body[0]["user"] == "DOMAIN\\alice"


def test_related_events_unknown_alert_returns_404(viewer_client: TestClient) -> None:
    response = viewer_client.get(
        "/api/alerts/00000000-0000-0000-0000-000000000000/related-events"
    )
    assert response.status_code == 404
