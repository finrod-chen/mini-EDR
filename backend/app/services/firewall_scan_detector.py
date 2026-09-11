"""PA-410 syslog 即時掃描偵測(port scan / host sweep / PAN-OS 自己的
Threat log 掃描特徵)。純邏輯、無 I/O——不呼叫 SNMP/DB/網路,方便單元測試,
真正的 syslog 收發跟寫 alert 在 app/services/syslog_listener.py。

`now` 一律由呼叫端傳入,這個模組內部不呼叫 datetime.now(),延續
sync_snmp_assets.py 已經用過的「注入時間/結果方便測試」慣例。

三個偵測路徑對應使用者確認的範圍:
- port scan:同一來源 IP 在時間視窗內連到過多不同目的連接埠
- host sweep:同一來源 IP 在時間視窗內連到過多不同目的主機
- Threat log 掃描特徵:PAN-OS 自己的 threat 引擎已經把某個連線標成
  subtype="scan",直接信任這個判斷、立即觸發,不需要累積視窗——這是
  簽章比對出來的結果,不是我們自己發明的門檻式判斷。
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# PAN-OS Threat log 的 subtype 值,"scan" 是官方文件定義的掃描/偵察分類。
THREAT_SUBTYPE_SCAN = "scan"

_EVICTION_CHECK_INTERVAL = timedelta(seconds=60)


@dataclass
class _SourceState:
    ports: deque[tuple[datetime, int]] = field(default_factory=deque)
    dests: deque[tuple[datetime, str]] = field(default_factory=deque)
    last_seen: datetime | None = None


def _severity_from_panos(raw: str) -> str:
    """把 PAN-OS 自己的 $severity(informational/low/medium/high/critical)
    對應到這個專案的 Severity 型別(Critical/High/Medium/Low)。解析不出來
    的值預設 High——這是簽章判斷出來的結果,寧可判重一點也不要漏掉。"""
    mapping = {
        "informational": "Low",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }
    return mapping.get(raw.strip().lower(), "High")


class ScanDetector:
    def __init__(
        self,
        *,
        port_scan_threshold: int,
        port_scan_window: timedelta,
        host_sweep_threshold: int,
        host_sweep_window: timedelta,
        state_ttl: timedelta,
    ) -> None:
        self._port_scan_threshold = port_scan_threshold
        self._port_scan_window = port_scan_window
        self._host_sweep_threshold = host_sweep_threshold
        self._host_sweep_window = host_sweep_window
        self._state_ttl = state_ttl
        self._state: dict[str, _SourceState] = {}
        self._next_eviction: datetime | None = None

    def _get_state(self, src_ip: str, now: datetime) -> _SourceState:
        state = self._state.get(src_ip)
        if state is None:
            state = _SourceState()
            self._state[src_ip] = state
        state.last_seen = now
        return state

    def _evict_stale(self, now: datetime) -> None:
        """不用額外的計時器,只有距離上次清理超過 _EVICTION_CHECK_INTERVAL
        才整批掃一次,避免每個封包都做一次全表清理。"""
        if self._next_eviction is not None and now < self._next_eviction:
            return
        cutoff = now - self._state_ttl
        stale_ips = [
            ip
            for ip, state in self._state.items()
            if state.last_seen is not None and state.last_seen < cutoff
        ]
        for ip in stale_ips:
            del self._state[ip]
        self._next_eviction = now + _EVICTION_CHECK_INTERVAL

    def record_traffic(
        self, *, src_ip: str, dst_ip: str, dst_port: int, now: datetime
    ) -> tuple[str, str] | None:
        """回傳 (原因字串, kind) 的 tuple,kind 是 "port_scan" 或
        "host_sweep"——用結構化的 kind 給呼叫端(syslog_listener.py)分派
        rule_name,不要求呼叫端反過來解析原因字串的文字內容。"""
        self._evict_stale(now)
        state = self._get_state(src_ip, now)

        state.ports.append((now, dst_port))
        port_cutoff = now - self._port_scan_window
        while state.ports and state.ports[0][0] < port_cutoff:
            state.ports.popleft()
        distinct_ports = {p for _, p in state.ports}
        if len(distinct_ports) >= self._port_scan_threshold:
            window_seconds = int(self._port_scan_window.total_seconds())
            reason = f"{window_seconds} 秒內掃描 {len(distinct_ports)} 個不同連接埠"
            return reason, "port_scan"

        state.dests.append((now, dst_ip))
        dest_cutoff = now - self._host_sweep_window
        while state.dests and state.dests[0][0] < dest_cutoff:
            state.dests.popleft()
        distinct_dests = {d for _, d in state.dests}
        if len(distinct_dests) >= self._host_sweep_threshold:
            window_seconds = int(self._host_sweep_window.total_seconds())
            reason = f"{window_seconds} 秒內掃描 {len(distinct_dests)} 台不同主機"
            return reason, "host_sweep"

        return None

    def record_threat(
        self, *, src_ip: str, subtype: str, category: str, threatid: str, severity: str
    ) -> tuple[str, str] | None:
        """回傳 (原因字串, 對應到本專案 Severity 的字串) 的 tuple,沒觸發回
        None。跟 record_traffic 不同,這裡不需要 now/累積視窗——PAN-OS
        自己的簽章引擎已經判斷完了,這裡只是把結果轉換成本專案的格式。"""
        if subtype != THREAT_SUBTYPE_SCAN:
            return None
        category_text = category or "未知"
        threatid_text = threatid or "未知"
        reason = f"PAN-OS 判定為掃描/偵察特徵(category={category_text}, threatid={threatid_text})"
        return reason, _severity_from_panos(severity)
