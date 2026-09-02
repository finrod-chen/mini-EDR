from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.auth import UserSession, get_current_user
from app.core.db import get_db
from app.main import app
from app.models.alert import Alert
from app.models.asset import AssetInventory, SoftwareInventory
from app.models.base import Base
from app.models.response_action import ResponseAction
from app.models.user import VIEWER_ROLE


@pytest.fixture
def session() -> Iterator[Session]:
    # TestClient 會在另一個 thread 裡實際處理 request(anyio portal),跟這個
    # fixture 建立連線的 thread 不同。SQLite in-memory 預設每個新連線是各自
    # 獨立的資料庫,加上預設也不允許跨 thread 共用連線,兩個問題一起解:
    # StaticPool 讓整個 engine 永遠重用同一個實體連線,check_same_thread=False
    # 允許這個連線跨 thread 用(正式環境是 Postgres,沒有這些限制)。
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


def test_list_alerts_requires_login() -> None:
    with TestClient(app) as anon_client:
        response = anon_client.get("/api/alerts")
    assert response.status_code == 401


def test_list_alerts_returns_rows_ordered_by_created_at_desc(
    client: TestClient, session: Session
) -> None:
    session.add_all(
        [
            Alert(
                severity="Critical",
                rule_name="rule-a",
                host="PC-01",
                status="open",
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
            Alert(
                severity="Medium",
                rule_name="rule-b",
                host="PC-02",
                status="open",
                created_at=datetime(2026, 1, 2, tzinfo=UTC),
            ),
        ]
    )
    session.commit()

    response = client.get("/api/alerts")

    assert response.status_code == 200
    body = response.json()
    assert [row["rule_name"] for row in body] == ["rule-b", "rule-a"]


def test_list_alerts_filters_by_severity(client: TestClient, session: Session) -> None:
    session.add_all(
        [
            Alert(severity="Critical", rule_name="a", host="PC-01", status="open", created_at=None),
            Alert(severity="Medium", rule_name="b", host="PC-02", status="open", created_at=None),
        ]
    )
    session.commit()

    response = client.get("/api/alerts", params={"severity": "Critical"})

    assert [row["rule_name"] for row in response.json()] == ["a"]


def test_list_response_actions_filters_by_date_range(client: TestClient, session: Session) -> None:
    session.add_all(
        [
            ResponseAction(action_type="quarantine", performed_at=datetime(2026, 1, 1, tzinfo=UTC)),
            ResponseAction(
                action_type="kill_process", performed_at=datetime(2026, 2, 1, tzinfo=UTC)
            ),
        ]
    )
    session.commit()

    response = client.get(
        "/api/response-actions",
        params={"since": "2026-01-15T00:00:00Z"},
    )

    assert response.status_code == 200
    body = response.json()
    assert [row["action_type"] for row in body] == ["kill_process"]


def test_list_response_actions_includes_host_from_related_alert(
    client: TestClient, session: Session
) -> None:
    alert = Alert(severity="High", rule_name="r", host="PC-99", status="open", created_at=None)
    session.add(alert)
    session.commit()
    session.refresh(alert)

    session.add(
        ResponseAction(
            alert_id=alert.alert_id,
            action_type="quarantine",
            performed_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    session.commit()

    response = client.get("/api/response-actions")

    assert response.json()[0]["host"] == "PC-99"


def test_list_assets_includes_health_score(client: TestClient, session: Session) -> None:
    session.add(
        AssetInventory(
            hostname="PC-01",
            os_version="Windows 10 Pro",
            defender_status="disabled",
            last_seen=datetime(2020, 1, 1, tzinfo=UTC),
        )
    )
    session.commit()

    response = client.get("/api/assets")

    assert response.status_code == 200
    body = response.json()
    assert body[0]["health_score"] == 50  # 100 - 20(舊OS) - 20(Defender關閉) - 10(太久沒回報)


def test_list_asset_software_returns_only_matching_asset(
    client: TestClient, session: Session
) -> None:
    asset = AssetInventory(hostname="PC-01")
    session.add(asset)
    session.commit()
    session.refresh(asset)

    session.add(SoftwareInventory(asset_id=asset.asset_id, software_name="7-Zip", version="23.01"))
    session.commit()

    response = client.get(f"/api/assets/{asset.asset_id}/software")

    assert response.status_code == 200
    assert response.json() == [
        {
            "software_name": "7-Zip",
            "version": "23.01",
            "publisher": None,
            "install_date": None,
        }
    ]
