from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.services.syslog_listener as listener_module
from app.core.config import settings
from app.models.alert import Alert
from app.models.base import Base
from app.models.syslog_message import SyslogMessage
from app.services.firewall_scan_detector import ScanDetector
from app.services.synology_log_analyzer import SynologyLogAnalyzer
from app.services.syslog_listener import (
    SOURCE_TYPE_OTHER,
    SOURCE_TYPE_PAN410,
    SOURCE_TYPE_SYNOLOGY_NAS,
    classify_source,
    handle_fields,
    handle_synology_line,
    parse_line,
    persist_raw_message,
)

_BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


def make_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def make_detector() -> ScanDetector:
    return ScanDetector(
        port_scan_threshold=3,
        port_scan_window=timedelta(seconds=60),
        host_sweep_threshold=3,
        host_sweep_window=timedelta(seconds=60),
        state_ttl=timedelta(seconds=300),
    )


def make_synology_analyzer(*, nas_host: str = "192.168.2.185") -> SynologyLogAnalyzer:
    return SynologyLogAnalyzer(
        login_failure_threshold=3,
        login_failure_window=timedelta(seconds=300),
        malicious_login_recent_failures=2,
        file_op_threshold=5,
        file_op_window=timedelta(seconds=60),
        state_ttl=timedelta(seconds=300),
        nas_host=nas_host,
    )


def test_parse_line_extracts_key_value_pairs_ignoring_envelope() -> None:
    # 前面模擬真實 syslog 信封(facility/priority/hostname 前綴),不含
    # key="value" 格式,應該被 parse_line 自然忽略。
    line = (
        "<14>Jan  1 12:00:00 PA-410 "
        'type="TRAFFIC" subtype="end" src="1.2.3.4" dst="10.0.0.1" '
        'sport="12345" dport="443" proto="tcp" action="allow" rule="Allow-Out"'
    )

    fields = parse_line(line)

    assert fields == {
        "type": "TRAFFIC",
        "subtype": "end",
        "src": "1.2.3.4",
        "dst": "10.0.0.1",
        "sport": "12345",
        "dport": "443",
        "proto": "tcp",
        "action": "allow",
        "rule": "Allow-Out",
    }


def test_parse_line_handles_malformed_input_without_crashing() -> None:
    assert parse_line("not a valid syslog line at all") == {}
    assert parse_line("") == {}


def test_handle_fields_port_scan_creates_alert(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    detector = make_detector()
    test_session = make_session()

    # handle_fields 內部自己開 SessionLocal()(見 syslog_listener.py 開頭的
    # 設計說明:每次「偵測到異常」才開一個 session,不是每行原始 log 都開),
    # 換成回傳同一個 in-memory session 才能檢查寫入結果——SQLAlchemy Session
    # 本身就是 context manager(__exit__ 只是 close(),之後還能繼續用),
    # 不需要額外包一層 fake context manager class。
    monkeypatch.setattr(listener_module, "SessionLocal", lambda: test_session)

    for i, port in enumerate((10, 20, 30)):
        now = _BASE + timedelta(seconds=i)
        fields = {"type": "TRAFFIC", "src": "1.2.3.4", "dst": "10.0.0.1", "dport": str(port)}
        handle_fields(detector, fields, now)

    alerts = test_session.execute(select(Alert)).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].host == "1.2.3.4"
    assert alerts[0].rule_name == "PA-410 疑似連接埠掃描"
    assert alerts[0].severity == "Medium"


def test_handle_fields_ignores_line_missing_src() -> None:
    detector = make_detector()
    # 沒有 src 欄位直接 return,不該嘗試開 DB session(不會因為缺欄位而
    # 拋例外弄壞監聽迴圈)。
    handle_fields(detector, {"type": "TRAFFIC", "dst": "10.0.0.1", "dport": "80"}, _BASE)


def test_handle_fields_ignores_unknown_log_type() -> None:
    detector = make_detector()
    handle_fields(detector, {"type": "SYSTEM", "src": "1.2.3.4"}, _BASE)


def test_handle_fields_high_severity_threat_uses_high_severity_rule_name(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    detector = make_detector()
    test_session = make_session()
    monkeypatch.setattr(listener_module, "SessionLocal", lambda: test_session)

    fields = {
        "type": "THREAT",
        "src": "1.2.3.4",
        "subtype": "virus",
        "category": "malware",
        "threatid": "1",
        "severity": "critical",
    }
    handle_fields(detector, fields, _BASE)

    alert = test_session.execute(select(Alert)).scalar_one()
    assert alert.rule_name == "PA-410 Threat Log 高風險事件"
    assert alert.severity == "Critical"


_SYNOLOGY_LINE = "<14>Sep 24 09:07:49 Xiyue-NAS Connection: User [admin] logged in successfully."
_PAN410_ENVELOPE = '<14>Jan  1 12:00:00 PA-410 type="TRAFFIC" subtype="end"'


def test_classify_source_by_pan410_content(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(settings, "synology_nas_syslog_hostname", "Xiyue-NAS")
    assert classify_source(_PAN410_ENVELOPE, {"type": "TRAFFIC"}) == SOURCE_TYPE_PAN410
    assert classify_source(_PAN410_ENVELOPE, {"type": "THREAT"}) == SOURCE_TYPE_PAN410


def test_classify_source_by_synology_hostname(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # 靠 syslog 信封裡的主機名稱判斷,不是 UDP 來源 IP——實機測試發現
    # Docker 會把進來的封包來源位址重寫成 bridge gateway IP,不管哪個
    # 外部裝置送的都長一樣,IP 沒辦法拿來判斷來源(見
    # syslog_listener.py 模組開頭的說明)。
    monkeypatch.setattr(settings, "synology_nas_syslog_hostname", "Xiyue-NAS")
    assert classify_source(_SYNOLOGY_LINE, {}) == SOURCE_TYPE_SYNOLOGY_NAS


def test_classify_source_unmatched_hostname_is_other(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(settings, "synology_nas_syslog_hostname", "Xiyue-NAS")
    other_line = (
        "<14>Sep 24 09:07:49 Some-Other-Host Connection: User [admin] logged in successfully."
    )
    assert classify_source(other_line, {}) == SOURCE_TYPE_OTHER


def test_classify_source_synology_hostname_unset_falls_back_to_other(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # 空字串 = 不比對(見 settings.synology_nas_syslog_hostname 預設值),
    # 沒設定的話任何非 PA-410 內容都歸 other,不會誤判成 synology_nas。
    monkeypatch.setattr(settings, "synology_nas_syslog_hostname", "")
    assert classify_source(_SYNOLOGY_LINE, {}) == SOURCE_TYPE_OTHER


def test_classify_source_envelope_without_hostname_is_other(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # 不符合 BSD syslog 信封格式的畸形行,_extract_syslog_hostname 抓不到
    # 主機名稱,一樣安全地歸類 other,不該拋例外。
    monkeypatch.setattr(settings, "synology_nas_syslog_hostname", "Xiyue-NAS")
    assert classify_source("not a valid syslog line", {}) == SOURCE_TYPE_OTHER


def test_persist_raw_message_writes_every_line(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    test_session = make_session()
    monkeypatch.setattr(listener_module, "SessionLocal", lambda: test_session)

    persist_raw_message("1.2.3.4", SOURCE_TYPE_PAN410, "some raw line", _BASE)

    row = test_session.execute(select(SyslogMessage)).scalar_one()
    assert row.source_ip == "1.2.3.4"
    assert row.source_type == SOURCE_TYPE_PAN410
    assert row.raw_message == "some raw line"
    # SQLite 不保留 tzinfo,讀回來是 naive datetime,補回 UTC 才能比較
    # (跟其他測試對 TIMESTAMP(timezone=True) 欄位的既有比較方式一致)。
    assert row.received_at.replace(tzinfo=UTC) == _BASE


def test_handle_synology_line_creates_alert_on_failure_burst(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    analyzer = make_synology_analyzer()
    test_session = make_session()
    monkeypatch.setattr(listener_module, "SessionLocal", lambda: test_session)

    line = "User [admin] failed to log in via [DSM] from [1.2.3.4] using [password]."
    for i in range(3):
        handle_synology_line(analyzer, line, _BASE + timedelta(seconds=i))

    alert = test_session.execute(select(Alert)).scalar_one()
    assert alert.host == "1.2.3.4"
    assert alert.rule_name == "Synology NAS 登入失敗次數異常(疑似暴力破解)"


def test_handle_synology_line_ignores_unrelated_line() -> None:
    analyzer = make_synology_analyzer()
    # 不是登入/檔案操作相關的行,不該拋例外、也不該開 DB session(這裡沒
    # monkeypatch SessionLocal,真的呼叫下去如果有開 session 會失敗)。
    handle_synology_line(analyzer, "some unrelated log line", _BASE)
