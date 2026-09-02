from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.base import Base
from app.models.events import ProcessEvent
from app.services import ai_explain

NOW = datetime.now(UTC)


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_mask_value_keeps_prefix_and_masks_rest() -> None:
    assert ai_explain.mask_value("DESKTOP-ABC123") == "DESK***"


def test_mask_value_handles_none_and_empty() -> None:
    assert ai_explain.mask_value(None) is None
    assert ai_explain.mask_value("") == ""


def test_build_alert_context_masks_host_and_includes_nearby_events() -> None:
    session = make_session()
    alert = Alert(
        severity="High",
        rule_name="PowerShell -EncodedCommand",
        host="PC-01",
        status="open",
        created_at=NOW,
    )
    session.add(alert)
    session.add(
        ProcessEvent(
            timestamp=NOW - timedelta(minutes=1),
            hostname="PC-01",
            image="powershell.exe",
            command_line="powershell -encodedcommand abcd",
            user="CORP\\alice",
        )
    )
    # 不同主機,不該出現在關聯事件裡
    session.add(
        ProcessEvent(
            timestamp=NOW,
            hostname="PC-99",
            image="cmd.exe",
            command_line="whoami",
            user="CORP\\bob",
        )
    )
    session.commit()

    context = ai_explain.build_alert_context(session, alert)

    assert context["host"] == "PC-0***"
    related = context["related_process_events"]
    assert len(related) == 1
    assert related[0]["image"] == "powershell.exe"
    assert related[0]["user"] == "CORP***"


def test_build_alert_context_empty_when_no_host_or_time() -> None:
    session = make_session()
    alert = Alert(severity="High", rule_name="r", host=None, status="open", created_at=None)
    context = ai_explain.build_alert_context(session, alert)
    assert context["related_process_events"] == []


def test_explain_alert_raises_when_not_configured() -> None:
    session = make_session()
    alert = Alert(severity="High", rule_name="r", host="PC-01", status="open", created_at=NOW)
    with patch.object(ai_explain.settings, "llm_base_url", ""):
        with pytest.raises(ai_explain.LlmNotConfiguredError):
            ai_explain.explain_alert(session, alert)


def test_explain_alert_calls_chat_completions_and_returns_content() -> None:
    session = make_session()
    alert = Alert(severity="High", rule_name="r", host="PC-01", status="open", created_at=NOW)

    fake_response = MagicMock()
    fake_response.raise_for_status = MagicMock()
    fake_response.json.return_value = {"choices": [{"message": {"content": "  這是說明  "}}]}

    with (
        patch.object(ai_explain.settings, "llm_base_url", "https://llm.example.com/v1"),
        patch.object(ai_explain.settings, "llm_api_key", "test-key"),
        patch.object(ai_explain.settings, "llm_model", "test-model"),
        patch.object(ai_explain.httpx, "post", return_value=fake_response) as mocked_post,
    ):
        result = ai_explain.explain_alert(session, alert)

    assert result == "這是說明"
    called_url = mocked_post.call_args.args[0]
    assert called_url == "https://llm.example.com/v1/chat/completions"
