"""syslog 接收器(UDP)——PA-410 防火牆 + Synology NAS 共用同一個 port。

傳輸機制用背景 thread + 阻塞式 UDP socket,不是 asyncio.DatagramProtocol
——這個專案除了被 pysnmp 7.x 強制的 asyncio.run() 之外沒有任何真正的 async
程式碼路徑,偵測到異常要呼叫的 create_alert_if_not_open() 也是同步
SQLAlchemy;用 asyncio 一樣要 run_in_executor 跳回 thread 才能不卡住
event loop,不如直接用 thread。這個規模的流量也遠遠用不到 asyncio 的
優勢。

**每一行原始 log,不管有沒有命中任何分析規則,一律先存進
`syslog_messages`**(見 persist_raw_message())——這是跟舊版最大的差異:
舊版只有真正偵測到異常時才開 SessionLocal() 寫 alert,平時的流量看過即
丟,事後想查一行舊 log 根本查不到。

來源判斷(classify_source())：
- PA-410:內容含 `type="TRAFFIC"`/`type="THREAT"` 這種 key=value 欄位
  (PA-410 端要設定自訂 log 格式,不是版本敏感的預設 CSV——PAN-OS syslog
  server profile 支援這個,見 deploy 文件的設定清單),用一個通用 regex
  抽欄位,不用管 PAN-OS 版本的欄位數量/順序差異。
- Synology NAS:內容格式跟 PAN-OS 完全不同(不是 key=value,是
  `Connection: User [admin] failed to log in via [DSM] from [...]` 這種
  帶中括號的敘述句),沒辦法用同一套 key=value regex 判斷。**原本想比對
  UDP 封包的來源 IP,但實機測試發現 Docker 會把進來的封包來源位址重寫成
  docker bridge 的 gateway IP(不管哪個外部裝置送的,container 看到的
  source_ip 全部一樣),完全不可靠**——改成比對 syslog 信封裡帶的主機
  名稱(見 _extract_syslog_hostname(),DSM/PAN-OS 在 BSD syslog 開頭
  固定會帶自己的主機名稱,不受 Docker NAT 影響,見
  app/core/config.py 的 synology_nas_syslog_hostname)。
- 兩者都比對不到:歸類 `other`,只存原始 log、不跑分析。之後要加其他
  來源,一樣是「多一個主機名稱設定 + 一支 analyzer」,不用動這支共用的
  收送邏輯。
"""

from __future__ import annotations

import logging
import re
import socket
import threading
from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.core.db import SessionLocal
from app.models.syslog_message import SyslogMessage
from app.rules.engine import create_alert_if_not_open
from app.services.firewall_scan_detector import (
    THREAT_KIND_SCAN,
    ScanDetector,
)
from app.services.synology_log_analyzer import SynologyLogAnalyzer

logger = logging.getLogger(__name__)

# 通用抽取所有 key="value",不依賴固定欄位順序/位置。PAN-OS 標準 syslog
# 信封(facility/priority/hostname 前綴)裡不會出現這種 key="value" token,
# 天然被這個 regex 忽略,不用另外切開信封跟本文;Synology 的敘述句型
# 也不含這種 token,同樣自然被忽略,回傳空字典。
_FIELD_RE = re.compile(r'(\w+)="([^"]*)"')

# BSD syslog(RFC 3164)信封:<PRI>Mon DD HH:MM:SS HOSTNAME TAG: message。
# PA-410/DSM 都遵守這個格式,HOSTNAME 是發送端自己配置的主機名稱,不受
# Docker NAT 影響(見上面模組說明)。
_SYSLOG_HOSTNAME_RE = re.compile(r"^<\d+>\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s")

RULE_NAME_PORT_SCAN = "PA-410 疑似連接埠掃描"
RULE_NAME_HOST_SWEEP = "PA-410 疑似主機掃描"
RULE_NAME_THREAT_SCAN = "PA-410 Threat Log 掃描/偵察特徵"
RULE_NAME_THREAT_HIGH_SEVERITY = "PA-410 Threat Log 高風險事件"

SOURCE_TYPE_PAN410 = "pan410"
SOURCE_TYPE_SYNOLOGY_NAS = "synology_nas"
SOURCE_TYPE_OTHER = "other"

_RECV_BUFFER_SIZE = 65535
_SOCKET_TIMEOUT_SECONDS = 1.0

_detector: ScanDetector | None = None
_synology_analyzer: SynologyLogAnalyzer | None = None
_socket: socket.socket | None = None
_thread: threading.Thread | None = None
_stop_event = threading.Event()


def parse_line(line: str) -> dict[str, str]:
    return dict(_FIELD_RE.findall(line))


def _extract_syslog_hostname(raw_line: str) -> str | None:
    match = _SYSLOG_HOSTNAME_RE.match(raw_line)
    return match.group(1) if match else None


def classify_source(raw_line: str, fields: dict[str, str]) -> str:
    """決定這一行的來源類型,見模組開頭的說明。PA-410 靠內容判斷優先於
    Synology 的主機名稱比對——PA-410 沒有另外設定一個 settings 值去比對,
    內容判斷本身已經是既有、零設定升級不會壞掉的路徑。"""
    if fields.get("type") in ("TRAFFIC", "THREAT"):
        return SOURCE_TYPE_PAN410
    hostname = _extract_syslog_hostname(raw_line)
    if (
        hostname
        and settings.synology_nas_syslog_hostname
        and hostname == settings.synology_nas_syslog_hostname
    ):
        return SOURCE_TYPE_SYNOLOGY_NAS
    return SOURCE_TYPE_OTHER


def persist_raw_message(source_ip: str, source_type: str, raw_line: str, now: datetime) -> None:
    """每一行都呼叫,不像下面的 handle_fields/handle_synology_line 只在
    命中規則才開 session——這是有意的取捨,原始流量遠比「觸發異常」的
    次數多,量若之後真的變成瓶頸,批次寫入是下一步,先不做(YAGNI)。"""
    with SessionLocal() as session:
        session.add(
            SyslogMessage(
                received_at=now, source_ip=source_ip, source_type=source_type, raw_message=raw_line
            )
        )
        session.commit()


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
            reason, severity, kind = result
            rule_name = (
                RULE_NAME_THREAT_SCAN
                if kind == THREAT_KIND_SCAN
                else RULE_NAME_THREAT_HIGH_SEVERITY
            )
    else:
        return

    if reason is None:
        return

    logger.info("firewall scan detected: %s (%s)", src_ip, reason)
    with SessionLocal() as session:
        create_alert_if_not_open(session, rule_name=rule_name, host=src_ip, severity=severity)
        session.commit()


def handle_synology_line(analyzer: SynologyLogAnalyzer, raw_line: str, now: datetime) -> None:
    """SynologyLogAnalyzer.record_line() 命中的每一筆 finding 都開一個
    SessionLocal() 寫 alert,跟 handle_fields 同一種「只在命中規則才開
    session」的取捨。"""
    for finding in analyzer.record_line(raw_line, now):
        logger.info("synology nas event detected: %s (%s)", finding.host, finding.reason)
        with SessionLocal() as session:
            create_alert_if_not_open(
                session, rule_name=finding.rule_name, host=finding.host, severity=finding.severity
            )
            session.commit()


def _make_detector() -> ScanDetector:
    return ScanDetector(
        port_scan_threshold=settings.syslog_port_scan_threshold,
        port_scan_window=timedelta(seconds=settings.syslog_port_scan_window_seconds),
        host_sweep_threshold=settings.syslog_host_sweep_threshold,
        host_sweep_window=timedelta(seconds=settings.syslog_host_sweep_window_seconds),
        state_ttl=timedelta(seconds=settings.syslog_state_ttl_seconds),
    )


def _make_synology_analyzer() -> SynologyLogAnalyzer:
    return SynologyLogAnalyzer(
        login_failure_threshold=settings.synology_login_failure_threshold,
        login_failure_window=timedelta(seconds=settings.synology_login_failure_window_seconds),
        malicious_login_recent_failures=settings.synology_malicious_login_recent_failures,
        file_op_threshold=settings.synology_file_op_threshold,
        file_op_window=timedelta(seconds=settings.synology_file_op_window_seconds),
        state_ttl=timedelta(seconds=settings.synology_state_ttl_seconds),
        nas_host=settings.synology_nas_ip,
    )


def _run(
    sock: socket.socket, detector: ScanDetector, synology_analyzer: SynologyLogAnalyzer
) -> None:
    while not _stop_event.is_set():
        try:
            data, addr = sock.recvfrom(_RECV_BUFFER_SIZE)
        except TimeoutError:
            continue
        except OSError:
            # stop() 主動關 socket 時,阻塞中的 recvfrom() 會拋這個——正常
            # 收尾路徑,不用當錯誤處理。
            break
        try:
            # 注意:在 Docker 部署下這個 source_ip 常常是 docker bridge 的
            # gateway IP,不是真正的外部發送端(見模組開頭的說明)——只當
            # 除錯用的輔助資訊存進 syslog_messages,不能拿來判斷來源。
            source_ip = addr[0]
            line = data.decode("utf-8", errors="replace")
            fields = parse_line(line)
            now = datetime.now(UTC)
            source_type = classify_source(line, fields)

            persist_raw_message(source_ip, source_type, line, now)

            if source_type == SOURCE_TYPE_PAN410:
                handle_fields(detector, fields, now)
            elif source_type == SOURCE_TYPE_SYNOLOGY_NAS:
                handle_synology_line(synology_analyzer, line, now)
            # SOURCE_TYPE_OTHER:只有原始存檔,不跑分析。
        except Exception:
            # 單一行(不管是格式問題還是 DB 一時連不上)壞掉,不能讓整個
            # 監聽 thread 死掉——log 起來繼續收下一行。
            logger.exception("failed to process syslog line")


def start() -> None:
    global _detector, _synology_analyzer, _socket, _thread
    if _thread is not None:
        return
    _stop_event.clear()
    _detector = _make_detector()
    _synology_analyzer = _make_synology_analyzer()
    _socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _socket.settimeout(_SOCKET_TIMEOUT_SECONDS)
    _socket.bind((settings.syslog_listen_host, settings.syslog_listen_port))
    _thread = threading.Thread(
        target=_run, args=(_socket, _detector, _synology_analyzer), daemon=True
    )
    _thread.start()
    logger.info(
        "syslog listener started on %s:%s", settings.syslog_listen_host, settings.syslog_listen_port
    )


def stop() -> None:
    global _detector, _synology_analyzer, _socket, _thread
    _stop_event.set()
    if _socket is not None:
        _socket.close()
    if _thread is not None:
        _thread.join(timeout=2)
    _detector = None
    _synology_analyzer = None
    _socket = None
    _thread = None
