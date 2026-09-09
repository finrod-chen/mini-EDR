from unittest.mock import patch

import pytest

from app.services import velociraptor_remediation as remediation


def test_resolve_client_id_returns_exact_match() -> None:
    with patch.object(
        remediation.velociraptor_client,
        "query",
        return_value=[{"client_id": "C.1111", "hostname": "PC-01"}],
    ):
        assert remediation.resolve_client_id("PC-01") == "C.1111"


def test_resolve_client_id_strips_fqdn_and_matches_short_hostname() -> None:
    # 實機測試發現 Velociraptor 的 host: 搜尋索引只收錄短主機名,alert.host
    # 常常是 FQDN(見 sync_sysmon_events),要先切掉網域部分才查得到。
    calls = []

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        calls.append((vql, kwargs))
        return [{"client_id": "C.74a4", "hostname": "G60010"}]

    with patch.object(remediation.velociraptor_client, "query", side_effect=fake_query):
        client_id = remediation.resolve_client_id("G60010.ad.xiyuebiomed.com.tw")

    assert client_id == "C.74a4"
    _, kwargs = calls[0]
    assert kwargs["Search"] == "host:G60010*"


def test_resolve_client_id_filters_out_prefix_collisions() -> None:
    # 萬用字元搜尋 "host:PC1*" 也會撈到 PC10、PC100 這種前綴重疊的機器,
    # 一定要靠精確比對挑出真正對得上的那一筆,不能只看第一筆——隔離主機/
    # 砍進程這種高風險動作選錯機器後果嚴重。
    rows = [
        {"client_id": "C.wrong", "hostname": "PC10"},
        {"client_id": "C.right", "hostname": "PC1"},
    ]
    with patch.object(remediation.velociraptor_client, "query", return_value=rows):
        assert remediation.resolve_client_id("PC1") == "C.right"


def test_resolve_client_id_matches_case_insensitively() -> None:
    with patch.object(
        remediation.velociraptor_client,
        "query",
        return_value=[{"client_id": "C.1111", "hostname": "pc-01"}],
    ):
        assert remediation.resolve_client_id("PC-01") == "C.1111"


def test_resolve_client_id_raises_when_not_found() -> None:
    with patch.object(remediation.velociraptor_client, "query", return_value=[]):
        with pytest.raises(remediation.ClientNotFoundError):
            remediation.resolve_client_id("PC-UNKNOWN")


def test_resolve_client_id_raises_when_only_prefix_collisions_found() -> None:
    rows = [{"client_id": "C.wrong", "hostname": "PC10"}]
    with patch.object(remediation.velociraptor_client, "query", return_value=rows):
        with pytest.raises(remediation.ClientNotFoundError):
            remediation.resolve_client_id("PC1")


def test_quarantine_host_resolves_client_and_collects() -> None:
    calls = []

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        calls.append((vql, kwargs))
        if "clients(" in vql:
            return [{"client_id": "C.1111", "hostname": "PC-01"}]
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
            return [{"client_id": "C.2222", "hostname": "PC-02"}]
        return [{"Result": {"flow_id": "F.XYZ"}}]

    with patch.object(remediation.velociraptor_client, "query", side_effect=fake_query):
        result = remediation.kill_process("PC-02", 4321)

    assert "F.XYZ" in result
    vql, kwargs = calls[1]
    assert kwargs["PidRegex"] == "^4321$"
    assert "Artifact" not in kwargs
    assert remediation.KILL_PROCESS_ARTIFACT in vql
