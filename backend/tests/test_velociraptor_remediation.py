from unittest.mock import patch

import pytest

from app.services import velociraptor_remediation as remediation


def test_resolve_client_id_returns_first_match() -> None:
    with patch.object(
        remediation.velociraptor_client, "query", return_value=[{"client_id": "C.1111"}]
    ):
        assert remediation.resolve_client_id("PC-01") == "C.1111"


def test_resolve_client_id_raises_when_not_found() -> None:
    with patch.object(remediation.velociraptor_client, "query", return_value=[]):
        with pytest.raises(remediation.ClientNotFoundError):
            remediation.resolve_client_id("PC-UNKNOWN")


def test_quarantine_host_resolves_client_and_collects() -> None:
    calls = []

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        calls.append((vql, kwargs))
        if "clients(" in vql:
            return [{"client_id": "C.1111"}]
        return [{"Result": {"flow_id": "F.ABC"}}]

    with patch.object(remediation.velociraptor_client, "query", side_effect=fake_query):
        result = remediation.quarantine_host("PC-01")

    assert "F.ABC" in result
    # 第二次呼叫是實際的 collect_client,確認 artifact 名稱與 client_id 有正確傳入
    _, kwargs = calls[1]
    assert kwargs["ClientId"] == "C.1111"
    assert kwargs["Artifact"] == remediation.QUARANTINE_ARTIFACT


def test_kill_process_passes_pid_regex() -> None:
    calls = []

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        calls.append((vql, kwargs))
        if "clients(" in vql:
            return [{"client_id": "C.2222"}]
        return [{"Result": {"flow_id": "F.XYZ"}}]

    with patch.object(remediation.velociraptor_client, "query", side_effect=fake_query):
        result = remediation.kill_process("PC-02", 4321)

    assert "F.XYZ" in result
    _, kwargs = calls[1]
    assert kwargs["PidRegex"] == "^4321$"
    assert kwargs["Artifact"] == remediation.KILL_PROCESS_ARTIFACT
