from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import app.services.syslog_listener as listener_module
from app.models.alert import Alert
from app.models.base import Base
from app.services.firewall_scan_detector import ScanDetector
from app.services.syslog_listener import handle_fields, parse_line

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


def test_parse_line_extracts_key_value_pairs_ignoring_envelope() -> None:
    # 前面模擬真實 syslog 信封(facility/priority/hostname 前綴),不含
    # key="value" 格式,應該被 parse_line 自然忽略。
    line = (
        '<14>Jan  1 12:00:00 PA-410 '
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
