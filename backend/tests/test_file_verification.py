import hashlib
from unittest.mock import MagicMock, patch

import pytest

from app.services import file_verification


def test_split_root_and_glob_valid() -> None:
    assert file_verification._split_root_and_glob("C:\\Windows\\win.ini") == (
        "C:",
        "\\Windows\\win.ini",
    )


def test_split_root_and_glob_rejects_non_windows_path() -> None:
    with pytest.raises(file_verification.InvalidPathError):
        file_verification._split_root_and_glob("/etc/passwd")


def test_split_root_and_glob_rejects_bare_drive() -> None:
    with pytest.raises(file_verification.InvalidPathError):
        file_verification._split_root_and_glob("C:")


def test_build_collection_spec_csv_has_glob_header() -> None:
    # collectionSpec 收到字串時會被當成 CSV 文字解析(見 file_verification.py
    # 開頭的說明),一定要有 "Glob" 標頭列,不能只塞裸路徑。
    csv_text = file_verification._build_collection_spec_csv("\\Windows\\win.ini")
    assert csv_text == "Glob\r\n\\Windows\\win.ini\r\n"


def _fake_magika_result(label: str, mime_type: str, extensions: list[str]) -> MagicMock:
    result = MagicMock()
    result.output.label = label
    result.output.mime_type = mime_type
    result.output.extensions = extensions
    return result


def test_verify_file_happy_path_matching_extension() -> None:
    content = b"[fonts]\n[extensions]\n"
    expected_sha256 = hashlib.sha256(content).hexdigest()
    calls: list[tuple[str, dict[str, object]]] = []

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        calls.append((vql, kwargs))
        if "clients(" in vql:
            return [{"client_id": "C.1111", "hostname": "PC-01"}]
        if "collect_client(" in vql:
            return [{"Result": {"flow_id": "F.ABC"}}]
        return [
            {
                "SourceFile": "C:\\Windows\\win.ini",
                "FileSize": 92,
                "SourceFileSha256": expected_sha256,
            }
        ]

    with (
        patch.object(file_verification.velociraptor_client, "query", side_effect=fake_query),
        patch.object(
            file_verification, "_fetch_uploaded_bytes", return_value=content
        ) as fetch_mock,
        patch.object(
            file_verification._magika,
            "identify_bytes",
            return_value=_fake_magika_result("ini", "text/plain", ["ini"]),
        ),
    ):
        result = file_verification.verify_file("PC-01", "C:\\Windows\\win.ini")

    assert result.sha256 == expected_sha256
    assert result.file_size == len(content)
    assert result.detected_label == "ini"
    assert result.extension_mismatch is False
    fetch_mock.assert_called_once_with("C.1111", "F.ABC", "C:\\Windows\\win.ini")

    # collect_client 呼叫要收到正確的 Root/CollectionSpec/ClientId,artifact
    # 名稱寫死在 VQL 字串裡,不走變數(跟 quarantine/kill_process 同樣的
    # ACL 限制,見 velociraptor_remediation.py 開頭的說明)。
    collect_vql, collect_kwargs = calls[1]
    assert collect_kwargs["ClientId"] == "C.1111"
    assert collect_kwargs["Root"] == "C:"
    assert collect_kwargs["CollectionSpec"] == "Glob\r\n\\Windows\\win.ini\r\n"
    assert file_verification.COLLECT_ARTIFACT in collect_vql


def test_verify_file_detects_extension_mismatch() -> None:
    content = b"MZ\x90\x00fake-pe-bytes"
    expected_sha256 = hashlib.sha256(content).hexdigest()

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        if "clients(" in vql:
            return [{"client_id": "C.1111", "hostname": "PC-01"}]
        if "collect_client(" in vql:
            return [{"Result": {"flow_id": "F.ABC"}}]
        return [{"SourceFile": "x", "FileSize": len(content), "SourceFileSha256": expected_sha256}]

    with (
        patch.object(file_verification.velociraptor_client, "query", side_effect=fake_query),
        patch.object(file_verification, "_fetch_uploaded_bytes", return_value=content),
        patch.object(
            file_verification._magika,
            "identify_bytes",
            return_value=_fake_magika_result("pebin", "application/x-dosexec", ["exe", "dll"]),
        ),
    ):
        result = file_verification.verify_file("PC-01", "C:\\Users\\Public\\invoice.pdf")

    assert result.extension_mismatch is True
    assert result.detected_label == "pebin"


def test_verify_file_raises_on_hash_mismatch() -> None:
    content = b"actual content"

    def fake_query(vql: str, **kwargs: object) -> list[dict[str, object]]:
        if "clients(" in vql:
            return [{"client_id": "C.1111", "hostname": "PC-01"}]
        if "collect_client(" in vql:
            return [{"Result": {"flow_id": "F.ABC"}}]
        return [{"SourceFile": "x", "FileSize": 1, "SourceFileSha256": "0" * 64}]

    with (
        patch.object(file_verification.velociraptor_client, "query", side_effect=fake_query),
        patch.object(file_verification, "_fetch_uploaded_bytes", return_value=content),
    ):
        with pytest.raises(file_verification.UploadIntegrityError):
            file_verification.verify_file("PC-01", "C:\\Windows\\win.ini")


def test_verify_file_rejects_invalid_path_before_resolving_client() -> None:
    with patch.object(file_verification.velociraptor_client, "query") as mocked_query:
        with pytest.raises(file_verification.InvalidPathError):
            file_verification.verify_file("PC-01", "not-a-windows-path")
    mocked_query.assert_not_called()


def test_launch_collection_raises_when_flow_id_missing() -> None:
    # 2026-09-09 實機測試撞到過:回傳的鍵是小寫 flow_id,一開始誤用大寫
    # FlowId 導致這裡永遠讀不到值——這個測試釘住正確的鍵名,避免回歸。
    with patch.object(
        file_verification.velociraptor_client, "query", return_value=[{"Result": {}}]
    ):
        with pytest.raises(RuntimeError, match="flow_id"):
            file_verification._launch_collection("C.1111", "C:", "\\Windows\\win.ini")


def test_poll_upload_times_out_when_no_upload_arrives() -> None:
    with (
        patch.object(file_verification.velociraptor_client, "query", return_value=[]),
        patch.object(file_verification.time, "sleep"),
    ):
        with pytest.raises(file_verification.FileNotFoundOnClientError):
            file_verification._poll_upload("C.1111", "F.ABC", timeout=0, poll_interval=0)
