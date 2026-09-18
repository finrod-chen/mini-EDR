from unittest.mock import MagicMock, patch

import pytest

from app.services import pan_os_remediation


def _mock_response(text: str, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    return resp


def test_block_ip_rejects_invalid_ip_without_http_call() -> None:
    with patch("app.services.pan_os_remediation.httpx.post") as mocked_post:
        with pytest.raises(pan_os_remediation.PanOsApiError):
            pan_os_remediation.block_ip("not-an-ip", "mini-edr-blocked")
    mocked_post.assert_not_called()


def test_block_ip_success_returns_response_text() -> None:
    success_xml = '<response status="success"><result>ok</result></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.post", return_value=_mock_response(success_xml)
    ) as mocked_post:
        result = pan_os_remediation.block_ip("1.2.3.4", "mini-edr-blocked")

    assert result == success_xml
    mocked_post.assert_called_once()
    _, kwargs = mocked_post.call_args
    assert kwargs["params"]["type"] == "user-id"
    assert '<entry ip="1.2.3.4">' in kwargs["data"]["cmd"]
    assert "mini-edr-blocked" in kwargs["data"]["cmd"]


def test_block_ip_non_success_status_raises() -> None:
    failure_xml = '<response status="error"><msg><line>Invalid key</line></msg></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.post", return_value=_mock_response(failure_xml)
    ):
        with pytest.raises(pan_os_remediation.PanOsApiError, match="Invalid key"):
            pan_os_remediation.block_ip("1.2.3.4", "mini-edr-blocked")


def test_block_ip_result_is_truncated() -> None:
    huge_text = '<response status="success">' + ("x" * 5000) + "</response>"
    with patch(
        "app.services.pan_os_remediation.httpx.post", return_value=_mock_response(huge_text)
    ):
        result = pan_os_remediation.block_ip("1.2.3.4", "mini-edr-blocked")
    assert len(result) == 2000


def test_block_ip_malformed_xml_response_raises() -> None:
    with patch(
        "app.services.pan_os_remediation.httpx.post",
        return_value=_mock_response("not xml at all"),
    ):
        with pytest.raises(pan_os_remediation.PanOsApiError):
            pan_os_remediation.block_ip("1.2.3.4", "mini-edr-blocked")


def test_clear_all_registered_ips_success() -> None:
    success_xml = '<response status="success"><result/></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.get", return_value=_mock_response(success_xml)
    ) as mocked_get:
        result = pan_os_remediation.clear_all_registered_ips()

    assert result == success_xml
    _, kwargs = mocked_get.call_args
    assert kwargs["params"]["type"] == "op"
    assert kwargs["params"]["cmd"] == "<clear><registered-ip><all/></registered-ip></clear>"


def test_clear_all_registered_ips_failure_raises() -> None:
    failure_xml = '<response status="error"><msg>boom</msg></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.get", return_value=_mock_response(failure_xml)
    ):
        with pytest.raises(pan_os_remediation.PanOsApiError):
            pan_os_remediation.clear_all_registered_ips()


def test_unblock_ip_rejects_invalid_ip_without_http_call() -> None:
    with patch("app.services.pan_os_remediation.httpx.post") as mocked_post:
        with pytest.raises(pan_os_remediation.PanOsApiError):
            pan_os_remediation.unblock_ip("not-an-ip", "mini-edr-blocked")
    mocked_post.assert_not_called()


def test_unblock_ip_success_sends_unregister_payload() -> None:
    success_xml = '<response status="success"><result>ok</result></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.post", return_value=_mock_response(success_xml)
    ) as mocked_post:
        result = pan_os_remediation.unblock_ip("1.2.3.4", "mini-edr-blocked")

    assert result == success_xml
    mocked_post.assert_called_once()
    _, kwargs = mocked_post.call_args
    assert kwargs["params"]["type"] == "user-id"
    cmd = kwargs["data"]["cmd"]
    assert "<unregister>" in cmd
    assert '<entry ip="1.2.3.4">' in cmd
    assert "mini-edr-blocked" in cmd


def test_unblock_ip_non_success_status_raises() -> None:
    failure_xml = '<response status="error"><msg><line>Invalid key</line></msg></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.post", return_value=_mock_response(failure_xml)
    ):
        with pytest.raises(pan_os_remediation.PanOsApiError, match="Invalid key"):
            pan_os_remediation.unblock_ip("1.2.3.4", "mini-edr-blocked")


def test_list_blocked_ips_filters_by_tag() -> None:
    xml = """
    <response status="success">
      <result>
        <entry ip="1.2.3.4">
          <tag><member timeout="86000">mini-edr-blocked</member></tag>
        </entry>
        <entry ip="5.6.7.8">
          <tag><member>some-other-tag</member></tag>
        </entry>
        <entry ip="9.9.9.9">
          <tag><member>mini-edr-blocked</member></tag>
        </entry>
      </result>
    </response>
    """
    with patch(
        "app.services.pan_os_remediation.httpx.get", return_value=_mock_response(xml)
    ) as mocked_get:
        result = pan_os_remediation.list_blocked_ips("mini-edr-blocked")

    _, kwargs = mocked_get.call_args
    assert kwargs["params"]["type"] == "op"
    assert result == [
        {"ip": "1.2.3.4", "tag": "mini-edr-blocked", "timeout_seconds": 86000},
        {"ip": "9.9.9.9", "tag": "mini-edr-blocked", "timeout_seconds": None},
    ]


def test_list_blocked_ips_empty_result_returns_empty_list() -> None:
    xml = '<response status="success"><result/></response>'
    with patch("app.services.pan_os_remediation.httpx.get", return_value=_mock_response(xml)):
        assert pan_os_remediation.list_blocked_ips("mini-edr-blocked") == []


def test_list_blocked_ips_failure_raises() -> None:
    failure_xml = '<response status="error"><msg>boom</msg></response>'
    with patch(
        "app.services.pan_os_remediation.httpx.get", return_value=_mock_response(failure_xml)
    ):
        with pytest.raises(pan_os_remediation.PanOsApiError):
            pan_os_remediation.list_blocked_ips("mini-edr-blocked")
