from datetime import UTC, datetime, timedelta

from app.services.synology_log_analyzer import (
    RULE_NAME_FILE_OP_BURST,
    RULE_NAME_LOGIN_FAILURE,
    RULE_NAME_MALICIOUS_LOGIN,
    SynologyLogAnalyzer,
)

_BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
_NAS_HOST = "192.168.2.185"

# 照 DSM 記錄查看器裡的真實輸出格式(見 synology_log_analyzer.py 模組
# 開頭的說明,不是憑印象猜的)。
_FAILED_LOGIN = (
    "User [admin] from [1.2.3.4] failed to sign in to [DSM] via [password] "
    "due to authorization failure."
)
_SUCCESS_LOGIN = "User [admin] from [1.2.3.4] signed in to [DSM] successfully via [password]."


def make_analyzer(
    *,
    login_failure_threshold: int = 3,
    login_failure_window_seconds: int = 300,
    malicious_login_recent_failures: int = 2,
    file_op_threshold: int = 3,
    file_op_window_seconds: int = 60,
    state_ttl_seconds: int = 300,
    nas_host: str = _NAS_HOST,
) -> SynologyLogAnalyzer:
    return SynologyLogAnalyzer(
        login_failure_threshold=login_failure_threshold,
        login_failure_window=timedelta(seconds=login_failure_window_seconds),
        malicious_login_recent_failures=malicious_login_recent_failures,
        file_op_threshold=file_op_threshold,
        file_op_window=timedelta(seconds=file_op_window_seconds),
        state_ttl=timedelta(seconds=state_ttl_seconds),
        nas_host=nas_host,
    )


def test_login_failure_triggers_at_threshold() -> None:
    analyzer = make_analyzer(login_failure_threshold=3)
    findings = []
    for i in range(3):
        findings = analyzer.record_line(_FAILED_LOGIN, _BASE + timedelta(seconds=i))

    assert len(findings) == 1
    assert findings[0].rule_name == RULE_NAME_LOGIN_FAILURE
    assert findings[0].host == "1.2.3.4"
    assert findings[0].severity == "Medium"


def test_login_failure_below_threshold_does_not_trigger() -> None:
    analyzer = make_analyzer(login_failure_threshold=3)
    findings = []
    for i in range(2):
        findings = analyzer.record_line(_FAILED_LOGIN, _BASE + timedelta(seconds=i))

    assert findings == []


def test_pure_success_login_does_not_trigger() -> None:
    analyzer = make_analyzer()
    findings = analyzer.record_line(_SUCCESS_LOGIN, _BASE)
    assert findings == []


def test_success_after_recent_failures_triggers_malicious_login() -> None:
    analyzer = make_analyzer(malicious_login_recent_failures=2, login_failure_threshold=99)
    # 門檻設 99,確定不是靠「純失敗告警」觸發,而是靠暴力破解成功判斷。
    analyzer.record_line(_FAILED_LOGIN, _BASE)
    analyzer.record_line(_FAILED_LOGIN, _BASE + timedelta(seconds=1))

    findings = analyzer.record_line(_SUCCESS_LOGIN, _BASE + timedelta(seconds=2))

    assert len(findings) == 1
    assert findings[0].rule_name == RULE_NAME_MALICIOUS_LOGIN
    assert findings[0].host == "1.2.3.4"
    assert findings[0].severity == "Critical"


def test_malicious_login_clears_failure_count_to_avoid_repeat_trigger() -> None:
    analyzer = make_analyzer(malicious_login_recent_failures=2, login_failure_threshold=99)
    analyzer.record_line(_FAILED_LOGIN, _BASE)
    analyzer.record_line(_FAILED_LOGIN, _BASE + timedelta(seconds=1))
    analyzer.record_line(_SUCCESS_LOGIN, _BASE + timedelta(seconds=2))

    # 清空之後,馬上再一次成功登入不該又觸發(沒有新的失敗紀錄可看)。
    findings = analyzer.record_line(_SUCCESS_LOGIN, _BASE + timedelta(seconds=3))

    assert findings == []


def _win_file_service_line(action: str, user: str) -> str:
    # 照實機真實輸出的格式(見 synology_log_analyzer.py 模組開頭的說明),
    # 不是憑印象猜的。
    return (
        f"<14>Sep 24 09:52:54 Xiyue-NAS WinFileService Event: {action}, "
        f"Path: /007-LAB/a/b.docx, File/Folder: File, Size: 27.35 KB, "
        f"User: {user}, IP: 192.168.2.53"
    )


def test_file_op_burst_triggers_at_threshold() -> None:
    analyzer = make_analyzer(file_op_threshold=3, nas_host=_NAS_HOST)
    line = _win_file_service_line("delete", "admin")
    findings = []
    for i in range(3):
        findings = analyzer.record_line(line, _BASE + timedelta(seconds=i))

    assert len(findings) == 1
    assert findings[0].rule_name == RULE_NAME_FILE_OP_BURST
    assert findings[0].host == _NAS_HOST
    assert findings[0].severity == "High"


def test_file_op_move_also_counts_toward_threshold() -> None:
    analyzer = make_analyzer(file_op_threshold=2)
    delete_line = _win_file_service_line("delete", "admin")
    move_line = _win_file_service_line("move", "admin")

    analyzer.record_line(delete_line, _BASE)
    findings = analyzer.record_line(move_line, _BASE + timedelta(seconds=1))

    assert len(findings) == 1
    assert findings[0].rule_name == RULE_NAME_FILE_OP_BURST


def test_file_op_read_and_create_do_not_count() -> None:
    # 只有 delete/move 算風險操作,一般的讀取/新增不該累計進門檻。
    analyzer = make_analyzer(file_op_threshold=2)
    findings = analyzer.record_line(_win_file_service_line("read", "admin"), _BASE)
    assert findings == []
    findings = analyzer.record_line(
        _win_file_service_line("create", "admin"), _BASE + timedelta(seconds=1)
    )
    assert findings == []


def test_file_op_below_threshold_does_not_trigger() -> None:
    analyzer = make_analyzer(file_op_threshold=5)
    line = _win_file_service_line("delete", "admin")
    findings = analyzer.record_line(line, _BASE)
    assert findings == []


def test_different_users_file_ops_counted_separately() -> None:
    analyzer = make_analyzer(file_op_threshold=2)
    alice_line = _win_file_service_line("delete", "alice")
    bob_line = _win_file_service_line("delete", "bob")

    findings = analyzer.record_line(alice_line, _BASE)
    assert findings == []
    findings = analyzer.record_line(bob_line, _BASE + timedelta(seconds=1))
    assert findings == []  # bob 只操作一次,不該因為 alice 的計數而誤觸發


def test_unrelated_line_is_ignored() -> None:
    analyzer = make_analyzer()
    assert analyzer.record_line("some unrelated log line", _BASE) == []


def test_stale_state_is_evicted_after_ttl() -> None:
    analyzer = make_analyzer(login_failure_threshold=3, state_ttl_seconds=60)
    analyzer.record_line(_FAILED_LOGIN, _BASE)
    analyzer.record_line(_FAILED_LOGIN, _BASE + timedelta(seconds=1))

    # 超過 TTL 之後,舊的失敗計數應該被清掉,不會延續累加到達門檻。
    far_future = _BASE + timedelta(seconds=200)
    findings = analyzer.record_line(_FAILED_LOGIN, far_future)

    assert findings == []
