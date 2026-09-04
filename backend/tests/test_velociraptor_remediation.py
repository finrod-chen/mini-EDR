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
    # 第二次呼叫是實際的 collect_client,確認 client_id 有正確傳入,artifact
    # 名稱則是直接寫死在 VQL 字串裡(見 velociraptor_remediation.py 開頭的
    # 說明:ACL 檢查需要靜態解析 artifact 名稱,不能走 env 變數)。
    vql, kwargs = calls[1]
    assert kwargs["ClientId"] == "C.1111"
    assert "Artifact" not in kwargs
    assert remediation.QUARANTINE_ARTIFACT in vql


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
    vql, kwargs = calls[1]
    assert kwargs["PidRegex"] == "^4321$"
    assert "Artifact" not in kwargs
    assert remediation.KILL_PROCESS_ARTIFACT in vql
