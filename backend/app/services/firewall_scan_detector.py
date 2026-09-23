"""PA-410 syslog 即時掃描偵測(port scan / host sweep / PAN-OS 自己的
Threat log 掃描特徵)。純邏輯、無 I/O——不呼叫 SNMP/DB/網路,方便單元測試,
真正的 syslog 收發跟寫 alert 在 app/services/syslog_listener.py。

`now` 一律由呼叫端傳入,這個模組內部不呼叫 datetime.now(),延續
sync_snmp_assets.py 已經用過的「注入時間/結果方便測試」慣例。

四個偵測路徑對應使用者確認的範圍:
- port scan:同一來源 IP 在時間視窗內對「同一個目的主機」連到過多不同
  連接埠
- host sweep:同一來源 IP 在時間視窗內連到過多不同「內網」目的主機
- Threat log 掃描特徵:PAN-OS 自己的 threat 引擎已經把某個連線標成
  subtype="scan",直接信任這個判斷、立即觸發,不需要累積視窗——這是
  簽章比對出來的結果,不是我們自己發明的門檻式判斷。
- Threat log 高風險事件:subtype 不是 "scan",但 PAN-OS 判定的嚴重度是
  high/critical——這是補的缺口,原本只有 subtype=="scan" 才會觸發
  alert,代表 PAN-OS 自己抓到的真正惡意程式/漏洞攻擊(非掃描類)完全
  沒有變成 alert,直接被丟掉;跟 subtype=="scan" 一樣不需要累積視窗,
  一樣是簽章比對出來的結果。

這兩個門檻式判斷(port scan / host sweep)都是實機上線後第一批真實流量
就抓到誤判、修正過的:

- host sweep 刻意只算目的地是私有位址(RFC1918,
  `ipaddress.ip_address(...).is_private`)的連線——一般上網瀏覽在 60 秒內
  輕鬆連到十幾個不同的外部 IP(CDN、廣告/分析網域、雲端服務各自不同
  IP),遠比真的內網橫向掃描更容易踩到「連到 N 個不同主機」這個門檻。
  host sweep 的威脅情境本來就是「內網偵察/橫向移動」,只算內網目的地
  才符合情境,也直接排除外部流量這個雜訊來源。
- port scan 一開始的實作是「這個來源 IP 在視窗內連過幾個不同 port 數值,
  不分是對哪個目的地」——這樣一台工作站在一分鐘內正常存取好幾個不同的
  內部服務(例如印表機 9100、檔案伺服器 445、某個內部網頁 8080,各自
  不同主機各自不同 port)就會被誤判成「連接埠掃描」,但這根本不是掃描:
  真正的 port scan 定義是「對『同一個』目的主機打很多不同 port」,不是
  「累計連過的相異 port 種類很多」。現在改成以目的地 IP 為單位分開累計,
  只有同一個目的地底下的相異 port 數量達門檻才觸發。
"""

from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# PAN-OS Threat log 的 subtype 值,"scan" 是官方文件定義的掃描/偵察分類。
THREAT_SUBTYPE_SCAN = "scan"
# record_threat() 回傳的第三個值(kind),呼叫端(syslog_listener.py)用
# 這個決定 rule_name,不用反過來解析 reason 字串的文字內容。
THREAT_KIND_SCAN = "scan"
THREAT_KIND_HIGH_SEVERITY = "high_severity"
# 非掃描類的 Threat log,嚴重度達這個等級才觸發 alert——中低風險的
# 非掃描事件只靠原始 syslog 存檔可查,不逐筆開 alert(見
# app/services/syslog_listener.py 現在會把每一行原始 log 都存進
# syslog_messages)。
_HIGH_SEVERITY_LEVELS = frozenset({"High", "Critical"})

_EVICTION_CHECK_INTERVAL = timedelta(seconds=60)


@dataclass
class _SourceState:
    # 以目的地 IP 分開累計連過的 port——port scan 是「對同一台主機打很多
    # 不同 port」,不是「今天累計連過的 port 種類很多」(後者是任何正常
    # 使用者存取多個不同服務就會發生的事)。
    ports_by_dest: dict[str, deque[tuple[datetime, int]]] = field(default_factory=dict)
    dests: deque[tuple[datetime, str]] = field(default_factory=deque)
    last_seen: datetime | None = None


def _is_private_destination(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        # 解析不出來的目的地(理論上不該發生,PAN-OS 一定給合法 IP)寧可
        # 不計入 host sweep 判斷,不要因為一筆壞資料誤觸發告警。
        return False


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

        port_deque = state.ports_by_dest.setdefault(dst_ip, deque())
        port_deque.append((now, dst_port))
        port_cutoff = now - self._port_scan_window
        while port_deque and port_deque[0][0] < port_cutoff:
            port_deque.popleft()
        if not port_deque:
            # 這個目的地在視窗內已經沒有活動了,清掉這個 key——避免長時間
            # 運行下,每個曾經聯絡過的目的地都留一個空 deque 慢慢累積。
            del state.ports_by_dest[dst_ip]
        else:
            distinct_ports = {p for _, p in port_deque}
            if len(distinct_ports) >= self._port_scan_threshold:
                window_seconds = int(self._port_scan_window.total_seconds())
                reason = f"{window_seconds} 秒內對 {dst_ip} 掃描 {len(distinct_ports)} 個不同連接埠"
                return reason, "port_scan"

        if _is_private_destination(dst_ip):
            state.dests.append((now, dst_ip))
        dest_cutoff = now - self._host_sweep_window
        while state.dests and state.dests[0][0] < dest_cutoff:
            state.dests.popleft()
        distinct_dests = {d for _, d in state.dests}
        if len(distinct_dests) >= self._host_sweep_threshold:
            window_seconds = int(self._host_sweep_window.total_seconds())
            reason = f"{window_seconds} 秒內掃描 {len(distinct_dests)} 台不同內網主機"
            return reason, "host_sweep"

        return None

    def record_threat(
        self, *, src_ip: str, subtype: str, category: str, threatid: str, severity: str
    ) -> tuple[str, str, str] | None:
        """回傳 (原因字串, 對應到本專案 Severity 的字串, kind) 的 tuple,
        沒觸發回 None。跟 record_traffic 不同,這裡不需要 now/累積視窗
        ——PAN-OS 自己的簽章引擎已經判斷完了,這裡只是把結果轉換成本專案
        的格式。subtype=="scan" 優先判斷,不會同時被兩種 kind 判定命中。
        """
        mapped_severity = _severity_from_panos(severity)
        category_text = category or "未知"
        threatid_text = threatid or "未知"

        if subtype == THREAT_SUBTYPE_SCAN:
            reason = (
                f"PAN-OS 判定為掃描/偵察特徵(category={category_text}, threatid={threatid_text})"
            )
            return reason, mapped_severity, THREAT_KIND_SCAN

        if mapped_severity in _HIGH_SEVERITY_LEVELS:
            reason = (
                f"PAN-OS Threat Log 高風險事件(category={category_text}, threatid={threatid_text})"
            )
            return reason, mapped_severity, THREAT_KIND_HIGH_SEVERITY

        return None
