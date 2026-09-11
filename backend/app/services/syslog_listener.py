"""PA-410 syslog 接收器(UDP)+ 即時掃描偵測的接線。

只收這一台防火牆的 Traffic/Threat log,不是通用 syslog 收集平台。PA-410
端要設定自訂 log 格式(`key="value"`,不是版本敏感的預設 CSV——PAN-OS
syslog server profile 支援這個,見 deploy 文件的設定清單),這樣 parse_line
才能用一個通用 regex 抽欄位,不用管 PAN-OS 版本的欄位數量/順序差異。

傳輸機制用背景 thread + 阻塞式 UDP socket,不是 asyncio.DatagramProtocol
——這個專案除了被 pysnmp 7.x 強制的 asyncio.run() 之外沒有任何真正的 async
程式碼路徑,偵測到異常要呼叫的 create_alert_if_not_open() 也是同步
SQLAlchemy;用 asyncio 一樣要 run_in_executor 跳回 thread 才能不卡住
event loop,不如直接用 thread。單一防火牆的流量規模也遠遠用不到 asyncio
的優勢。

每一行原始 log 都會呼叫 parse_line/ScanDetector(記憶體內操作,便宜),
但只有真正偵測到異常時才開一個 SessionLocal() 寫 alert——原始流量遠比
「觸發異常」的次數多,不能每一行都開一個 DB session。
"""

from __future__ import annotations

import logging
import re
import socket
import threading
from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.core.db import SessionLocal
from app.rules.engine import create_alert_if_not_open
from app.services.firewall_scan_detector import ScanDetector

logger = logging.getLogger(__name__)

# 通用抽取所有 key="value",不依賴固定欄位順序/位置。PAN-OS 標準 syslog
# 信封(facility/priority/hostname 前綴)裡不會出現這種 key="value" token,
# 天然被這個 regex 忽略,不用另外切開信封跟本文。
_FIELD_RE = re.compile(r'(\w+)="([^"]*)"')

RULE_NAME_PORT_SCAN = "PA-410 疑似連接埠掃描"
RULE_NAME_HOST_SWEEP = "PA-410 疑似主機掃描"
RULE_NAME_THREAT_SCAN = "PA-410 Threat Log 掃描/偵察特徵"

_RECV_BUFFER_SIZE = 65535
_SOCKET_TIMEOUT_SECONDS = 1.0

_detector: ScanDetector | None = None
_socket: socket.socket | None = None
_thread: threading.Thread | None = None
_stop_event = threading.Event()


def parse_line(line: str) -> dict[str, str]:
    return dict(_FIELD_RE.findall(line))


def handle_fields(detector: ScanDetector, fields: dict[str, str], now: datetime) -> None:
    """依 fields["type"] 分派到 record_traffic/record_threat,命中就開一個
    SessionLocal() 寫 alert。缺欄位/型別不對的畸形行直接忽略(log debug),
    不能讓一行壞資料弄壞整個監聽迴圈。"""
    log_type = fields.get("type")

    reason: str | None = None
    severity = "Medium"
    rule_name = ""
    src_ip = fields.get("src")
    if not src_ip:
        return

    if log_type == "TRAFFIC":
        dst_ip = fields.get("dst")
        dport = fields.get("dport")
        if not dst_ip or not dport:
            return
        try:
            dst_port = int(dport)
        except ValueError:
            return
        traffic_result = detector.record_traffic(
            src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, now=now
        )
        if traffic_result is not None:
            reason, kind = traffic_result
            rule_name = RULE_NAME_PORT_SCAN if kind == "port_scan" else RULE_NAME_HOST_SWEEP
    elif log_type == "THREAT":
        result = detector.record_threat(
            src_ip=src_ip,
            subtype=fields.get("subtype", ""),
            category=fields.get("category", ""),
            threatid=fields.get("threatid", ""),
            severity=fields.get("severity", ""),
        )
        if result is not None:
            reason, severity = result
            rule_name = RULE_NAME_THREAT_SCAN
    else:
        return

    if reason is None:
        return

    logger.info("firewall scan detected: %s (%s)", src_ip, reason)
    with SessionLocal() as session:
        create_alert_if_not_open(session, rule_name=rule_name, host=src_ip, severity=severity)
        session.commit()


def _make_detector() -> ScanDetector:
    return ScanDetector(
        port_scan_threshold=settings.syslog_port_scan_threshold,
        port_scan_window=timedelta(seconds=settings.syslog_port_scan_window_seconds),
        host_sweep_threshold=settings.syslog_host_sweep_threshold,
        host_sweep_window=timedelta(seconds=settings.syslog_host_sweep_window_seconds),
        state_ttl=timedelta(seconds=settings.syslog_state_ttl_seconds),
    )


def _run(sock: socket.socket, detector: ScanDetector) -> None:
    while not _stop_event.is_set():
        try:
            data, _addr = sock.recvfrom(_RECV_BUFFER_SIZE)
        except TimeoutError:
            continue
        except OSError:
            # stop() 主動關 socket 時,阻塞中的 recvfrom() 會拋這個——正常
            # 收尾路徑,不用當錯誤處理。
            break
        try:
            line = data.decode("utf-8", errors="replace")
            fields = parse_line(line)
            handle_fields(detector, fields, datetime.now(UTC))
        except Exception:
            # 單一行(不管是格式問題還是 DB 一時連不上)壞掉,不能讓整個
            # 監聽 thread 死掉——log 起來繼續收下一行。
            logger.exception("failed to process syslog line")


def start() -> None:
    global _detector, _socket, _thread
    if _thread is not None:
        return
    _stop_event.clear()
    _detector = _make_detector()
    _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _socket.settimeout(_SOCKET_TIMEOUT_SECONDS)
    _socket.bind((settings.syslog_listen_host, settings.syslog_listen_port))
    _thread = threading.Thread(target=_run, args=(_socket, _detector), daemon=True)
    _thread.start()
    logger.info(
        "syslog listener started on %s:%s", settings.syslog_listen_host, settings.syslog_listen_port
    )


def stop() -> None:
    global _detector, _socket, _thread
    _stop_event.set()
    if _socket is not None:
        _socket.close()
    if _thread is not None:
        _thread.join(timeout=2)
    _detector = None
    _socket = None
    _thread = None
