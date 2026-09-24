"""Synology NAS syslog 分析(登入失敗/暴力破解成功登入/大量刪除搬移檔案)。

純邏輯、無 I/O,風格照抄 app/services/firewall_scan_detector.py——`now`
一律由呼叫端傳入,方便單元測試;真正的收發跟寫 alert 在
app/services/syslog_listener.py。

這幾個 regex 抓的是 DSM Connection log/File log 公開文件、社群(含
fail2ban 的 Synology filter)廣泛驗證過的固定句型,例如:

    User [admin] failed to log in via [DSM] from [1.2.3.4] using [password].
    User [admin] logged in successfully via [DSM] from [1.2.3.4].
    User [admin] deleted file/folder [/volume1/share/secret.txt].

但沒有拿使用者實機的真實輸出驗證過——尤其是檔案操作那段,DSM File log
的確切句型比登入格式更沒把握(登入格式有很多公開來源可以交叉確認,檔案
操作沒有),部署後很可能要依真實 log 重新調整這幾個 regex,見 deploy
文件的說明。
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

RULE_NAME_LOGIN_FAILURE = "Synology NAS 登入失敗次數異常(疑似暴力破解)"
RULE_NAME_MALICIOUS_LOGIN = "Synology NAS 疑似暴力破解成功登入"
RULE_NAME_FILE_OP_BURST = "Synology NAS 大量刪除/搬移檔案"

_FAILED_LOGIN_RE = re.compile(r"failed to log in via \[(\w+)\] from \[([\d.]+)\]")
_SUCCESS_LOGIN_RE = re.compile(r"logged in successfully via \[(\w+)\] from \[([\d.]+)\]")
# 只認「刪除/搬移」這兩個動詞,不含「新增/修改」——這次要抓的是使用者
# 明確點名的風險情境(資料被清空/搬走),不是泛用的檔案異動監控。
_FILE_OP_RE = re.compile(r"User \[([^\]]+)\] (?:deleted|moved) file/folder")

_EVICTION_CHECK_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True)
class SynologyFinding:
    rule_name: str
    reason: str
    severity: str
    host: str


@dataclass
class _KeyState:
    events: deque[datetime] = field(default_factory=deque)
    last_seen: datetime | None = None


class SynologyLogAnalyzer:
    def __init__(
        self,
        *,
        login_failure_threshold: int,
        login_failure_window: timedelta,
        malicious_login_recent_failures: int,
        file_op_threshold: int,
        file_op_window: timedelta,
        state_ttl: timedelta,
        nas_host: str,
    ) -> None:
        self._login_failure_threshold = login_failure_threshold
        self._login_failure_window = login_failure_window
        self._malicious_login_recent_failures = malicious_login_recent_failures
        self._file_op_threshold = file_op_threshold
        self._file_op_window = file_op_window
        self._state_ttl = state_ttl
        # 檔案操作的 alert 沒有可以從 log 行本身解析出來的「攻擊來源」,
        # host 固定填 NAS 自己的 IP(見 app/core/config.py 的
        # synology_nas_ip——注意這跟 syslog_listener.py 的
        # classify_source() 判斷來源用的 synology_nas_syslog_hostname 是
        # 兩個不同的設定值,一個是拿來認「這行是不是 NAS 送的」,一個是
        # 「alert 要顯示成哪個 IP」)。注入而非讀 app.core.config,維持這個
        # class 零 I/O、零 settings 耦合。
        self._nas_host = nas_host
        self._login_failures: dict[str, _KeyState] = {}  # key = 攻擊來源 IP
        self._file_ops: dict[str, _KeyState] = {}  # key = DSM 使用者帳號
        self._next_eviction: datetime | None = None

    def _evict_stale(self, now: datetime) -> None:
        """不用額外的計時器,只有距離上次清理超過 _EVICTION_CHECK_INTERVAL
        才整批掃一次,避免每一行都做一次全表清理(比照 ScanDetector)。"""
        if self._next_eviction is not None and now < self._next_eviction:
            return
        cutoff = now - self._state_ttl
        for store in (self._login_failures, self._file_ops):
            stale_keys = [
                key
                for key, state in store.items()
                if state.last_seen is not None and state.last_seen < cutoff
            ]
            for key in stale_keys:
                del store[key]
        self._next_eviction = now + _EVICTION_CHECK_INTERVAL

    @staticmethod
    def _trim(events: deque[datetime], window: timedelta, now: datetime) -> None:
        cutoff = now - window
        while events and events[0] < cutoff:
            events.popleft()

    def _count_in_window(
        self, store: dict[str, _KeyState], key: str, window: timedelta, now: datetime
    ) -> int:
        state = store.setdefault(key, _KeyState())
        state.last_seen = now
        state.events.append(now)
        self._trim(state.events, window, now)
        return len(state.events)

    def _recent_failure_count(self, attacker_ip: str, now: datetime) -> int:
        """成功登入時查「這個來源 IP 視窗內最近累積了幾次失敗」,純查詢,
        不算一次新的失敗事件(不呼叫 _count_in_window,那支會多算一筆)。"""
        state = self._login_failures.get(attacker_ip)
        if state is None:
            return 0
        state.last_seen = now
        self._trim(state.events, self._login_failure_window, now)
        return len(state.events)

    def record_line(self, raw_line: str, now: datetime) -> list[SynologyFinding]:
        """理論上一行只會命中下面三種模式其中一種,回傳 list 是為了介面
        單純(呼叫端不用分開呼叫三支函式),不是真的預期同一行觸發多筆。"""
        self._evict_stale(now)

        success_match = _SUCCESS_LOGIN_RE.search(raw_line)
        if success_match:
            attacker_ip = success_match.group(2)
            failure_count = self._recent_failure_count(attacker_ip, now)
            if failure_count >= self._malicious_login_recent_failures:
                # 這波攻擊已經有結果了(成功登入),清空失敗計數,避免
                # 同一波攻擊被重複觸發。
                del self._login_failures[attacker_ip]
                window_seconds = int(self._login_failure_window.total_seconds())
                return [
                    SynologyFinding(
                        rule_name=RULE_NAME_MALICIOUS_LOGIN,
                        reason=(
                            f"{attacker_ip} 在成功登入前的 {window_seconds} 秒內"
                            f"失敗 {failure_count} 次,疑似暴力破解成功"
                        ),
                        severity="Critical",
                        host=attacker_ip,
                    )
                ]
            return []

        failed_match = _FAILED_LOGIN_RE.search(raw_line)
        if failed_match:
            attacker_ip = failed_match.group(2)
            count = self._count_in_window(
                self._login_failures, attacker_ip, self._login_failure_window, now
            )
            if count >= self._login_failure_threshold:
                window_seconds = int(self._login_failure_window.total_seconds())
                return [
                    SynologyFinding(
                        rule_name=RULE_NAME_LOGIN_FAILURE,
                        reason=f"{window_seconds} 秒內登入失敗 {count} 次",
                        severity="Medium",
                        host=attacker_ip,
                    )
                ]
            return []

        file_op_match = _FILE_OP_RE.search(raw_line)
        if file_op_match:
            user = file_op_match.group(1)
            count = self._count_in_window(self._file_ops, user, self._file_op_window, now)
            if count >= self._file_op_threshold:
                window_seconds = int(self._file_op_window.total_seconds())
                return [
                    SynologyFinding(
                        rule_name=RULE_NAME_FILE_OP_BURST,
                        reason=f"使用者 {user} 在 {window_seconds} 秒內刪除/搬移 {count} 個檔案",
                        severity="High",
                        host=self._nas_host,
                    )
                ]
            return []

        return []
