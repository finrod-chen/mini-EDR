"""偵測規則定義(Phase 3)。

前 9 條對應規格〈偵測規則清單〉表格,其餘是常見 Sigma-style 偵測邏輯的延伸,
用來湊到規格說的「15~20 條起步」。全部只查詢現有 schema(process_events/
network_events/defender_events/asset_inventory)已經有的欄位——不發明資料
來源裡沒有的偵測面向,例如 Sysmon ProcessAccess/registry/file 事件目前完全
沒有收集(見 app/jobs/sync_sysmon_events.py 的說明),所以規格提到的「LSASS
存取異常(非常見進程存取 lsass.exe)」這裡退而求其次,改成命令列字串比對。

每條規則多半是社群常見的啟發式(heuristic),不是精準的行為簽章,上線後
一定需要依實際告警噪音調整字串比對條件與門檻值;規則 docstring 裡有特別
標注比較容易誤報的地方。
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, aliased

from app.models.asset import AssetInventory
from app.models.events import DefenderEvent, NetworkEvent, ProcessEvent
from app.rules.engine import Rule

# 事件型規則的掃描回溯範圍。dedup 由 engine.create_alert_if_not_open 處理
# (同一 rule+host 有未結案 alert 就不重複開),這裡只是避免每次都重新掃過
# 整張表,跟排程頻率(5~10 分鐘)抓同一個量級、留一點緩衝。
LOOKBACK = timedelta(minutes=15)


def _since() -> datetime:
    return datetime.now(UTC) - LOOKBACK


def _distinct_hosts(session: Session, stmt: Select[Any]) -> list[str]:
    return [row[0] for row in session.execute(stmt) if row[0]]


# ---------- AV ----------


def rule_defender_protection_disabled(session: Session) -> list[str]:
    """Defender 即時防護被關閉(defender_events.event_type='protection_disabled',對應 5001)。"""
    stmt = (
        select(DefenderEvent.hostname)
        .where(
            DefenderEvent.event_type == "protection_disabled",
            DefenderEvent.timestamp >= _since(),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_defender_detect_without_action(session: Session) -> list[str]:
    """Defender 偵測到惡意軟體(1006/1116)但一小時內沒有對應的 action_taken(1117)。"""
    since = _since()
    detections = session.execute(
        select(DefenderEvent.hostname, DefenderEvent.threat_name, DefenderEvent.timestamp).where(
            DefenderEvent.event_type == "detect", DefenderEvent.timestamp >= since
        )
    ).all()

    hosts: list[str] = []
    for hostname, threat_name, ts in detections:
        if hostname is None or ts is None:
            continue
        remediated = session.execute(
            select(DefenderEvent.event_id).where(
                DefenderEvent.hostname == hostname,
                DefenderEvent.threat_name == threat_name,
                DefenderEvent.event_type == "action_taken",
                DefenderEvent.timestamp >= ts,
                DefenderEvent.timestamp <= ts + timedelta(hours=1),
            )
        ).first()
        if remediated is None:
            hosts.append(hostname)
    return hosts


# ---------- 憑證存取 ----------


def rule_lsass_credential_dump_command_line(session: Session) -> list[str]:
    """command_line 提到 lsass(常見手法如 procdump 或 comsvcs.dll MiniDump 對 lsass 傾印)。

    這不是「非常見進程存取 lsass.exe」的行為監控(Sysmon ProcessAccess
    Event ID 10,目前完全沒有收集),是退而求其次的命令列字串比對,偵測
    範圍比較窄、容易被繞過,見本檔案開頭說明。
    """
    stmt = (
        select(ProcessEvent.hostname)
        .where(ProcessEvent.timestamp >= _since(), ProcessEvent.command_line.ilike("%lsass%"))
        .distinct()
    )
    return _distinct_hosts(session, stmt)


# ---------- 執行 ----------


def rule_powershell_encoded_command(session: Session) -> list[str]:
    """PowerShell -EncodedCommand。"""
    stmt = (
        select(ProcessEvent.hostname)
        .where(
            ProcessEvent.timestamp >= _since(),
            ProcessEvent.image.ilike("%powershell%"),
            ProcessEvent.command_line.ilike("%-encodedcommand%"),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_powershell_hidden_or_bypass(session: Session) -> list[str]:
    """PowerShell 帶 -ExecutionPolicy Bypass / -WindowStyle Hidden 之類的隱蔽啟動旗標。"""
    stmt = (
        select(ProcessEvent.hostname)
        .where(
            ProcessEvent.timestamp >= _since(),
            ProcessEvent.image.ilike("%powershell%"),
            (
                ProcessEvent.command_line.ilike("%executionpolicy bypass%")
                | ProcessEvent.command_line.ilike("%-w hidden%")
                | ProcessEvent.command_line.ilike("%-windowstyle hidden%")
            ),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_office_spawns_shell(session: Session) -> list[str]:
    """Office(winword/excel/powerpnt)啟動 PowerShell/CMD——常見巨集攻擊手法。

    用 ppid/pid 在同一台主機內對 process_events 自 join,並限制父進程要在
    子進程建立前 5 分鐘內出現過,降低 pid 被系統重複使用造成的誤配對。
    """
    parent = aliased(ProcessEvent)
    since = _since()
    stmt = (
        select(ProcessEvent.hostname)
        .join(
            parent,
            (ProcessEvent.ppid == parent.pid) & (ProcessEvent.hostname == parent.hostname),
        )
        .where(
            ProcessEvent.timestamp >= since,
            parent.timestamp <= ProcessEvent.timestamp,
            parent.timestamp >= ProcessEvent.timestamp - timedelta(minutes=5),
            (
                parent.image.ilike("%winword.exe%")
                | parent.image.ilike("%excel.exe%")
                | parent.image.ilike("%powerpnt.exe%")
            ),
            (ProcessEvent.image.ilike("%powershell.exe%") | ProcessEvent.image.ilike("%cmd.exe%")),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_lolbin_download(session: Session) -> list[str]:
    """certutil -urlcache / bitsadmin transfer,常見 LOLBin 下載手法。"""
    stmt = (
        select(ProcessEvent.hostname)
        .where(
            ProcessEvent.timestamp >= _since(),
            (
                (
                    ProcessEvent.image.ilike("%certutil.exe%")
                    & ProcessEvent.command_line.ilike("%urlcache%")
                )
                | (
                    ProcessEvent.image.ilike("%bitsadmin.exe%")
                    & ProcessEvent.command_line.ilike("%transfer%")
                )
            ),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_mshta_execution(session: Session) -> list[str]:
    """mshta.exe 執行——一般業務很少用到,常被用來執行遠端 HTA/腳本。"""
    stmt = (
        select(ProcessEvent.hostname)
        .where(ProcessEvent.timestamp >= _since(), ProcessEvent.image.ilike("%mshta.exe%"))
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_rundll32_suspicious_args(session: Session) -> list[str]:
    """rundll32.exe 帶 javascript: 或網址參數——常見腳本注入/下載手法。"""
    stmt = (
        select(ProcessEvent.hostname)
        .where(
            ProcessEvent.timestamp >= _since(),
            ProcessEvent.image.ilike("%rundll32.exe%"),
            (
                ProcessEvent.command_line.ilike("%javascript:%")
                | ProcessEvent.command_line.ilike("%http://%")
                | ProcessEvent.command_line.ilike("%https://%")
            ),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


# ---------- 持久化 / 防禦規避 ----------


def rule_process_from_temp_or_public(session: Session) -> list[str]:
    """進程執行檔位於 Temp/Public 這類使用者可寫目錄——常見 malware 落地位置。

    也常有合法安裝程式誤中,先訂 Medium,預期上線後需要調整排除清單。
    """
    stmt = (
        select(ProcessEvent.hostname)
        .where(
            ProcessEvent.timestamp >= _since(),
            (
                ProcessEvent.image.ilike("%\\appdata\\local\\temp\\%")
                | ProcessEvent.image.ilike("%\\users\\public\\%")
                | ProcessEvent.image.ilike("%\\windows\\temp\\%")
            ),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


# ---------- 橫向移動 ----------


def rule_psexec_activity(session: Session) -> list[str]:
    """PsExec 遠端執行行為(目標主機會出現 PSEXESVC.exe 服務進程)。"""
    stmt = (
        select(ProcessEvent.hostname)
        .where(
            ProcessEvent.timestamp >= _since(),
            (
                ProcessEvent.image.ilike("%psexesvc.exe%")
                | ProcessEvent.command_line.ilike("%psexec%")
            ),
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_winrm_network_activity(session: Session) -> list[str]:
    """WinRM 慣用連接埠(5985/5986)出現網路連線。

    起步先用連接埠當訊號,之後有更細的資料(例如目的主機身分)再收斂,
    避免正常 WinRM 管理流量被反覆誤報。
    """
    stmt = (
        select(NetworkEvent.hostname)
        .where(NetworkEvent.timestamp >= _since(), NetworkEvent.dst_port.in_((5985, 5986)))
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_network_scan_many_destinations(session: Session) -> list[str]:
    """同一台主機短時間內對很多不同目的地 IP 建立連線——疑似掃描/橫向移動。"""
    threshold = 10
    stmt = (
        select(NetworkEvent.hostname)
        .where(NetworkEvent.timestamp >= _since())
        .group_by(NetworkEvent.hostname)
        .having(func.count(func.distinct(NetworkEvent.dst_ip)) >= threshold)
    )
    return _distinct_hosts(session, stmt)


# ---------- 探測 ----------

_DISCOVERY_IMAGES = ("%whoami.exe%", "%net.exe%", "%nltest.exe%", "%systeminfo.exe%")


def rule_discovery_command_burst(session: Session) -> list[str]:
    """短時間內同一台主機連續執行多個偵察指令(whoami/net/nltest/systeminfo)。"""
    threshold = 3
    condition = or_(*(ProcessEvent.image.ilike(pattern) for pattern in _DISCOVERY_IMAGES))

    stmt = (
        select(ProcessEvent.hostname)
        .where(ProcessEvent.timestamp >= _since(), condition)
        .group_by(ProcessEvent.hostname)
        .having(func.count() >= threshold)
    )
    return _distinct_hosts(session, stmt)


# ---------- 網路 ----------

_SUSPICIOUS_PORTS = (4444, 1337, 31337, 6666, 6667)


def rule_connection_to_known_bad_ports(session: Session) -> list[str]:
    """對外連線到常見惡意工具慣用連接埠(如 Metasploit/Cobalt Strike 預設 4444)。

    連接埠本身不是惡意的鐵證,只是粗略啟發式,刻意不含 8080/8443 這類太
    常見的合法連接埠避免誤報過多。
    """
    stmt = (
        select(NetworkEvent.hostname)
        .where(NetworkEvent.timestamp >= _since(), NetworkEvent.dst_port.in_(_SUSPICIOUS_PORTS))
        .distinct()
    )
    return _distinct_hosts(session, stmt)


# ---------- 資產 ----------


def rule_asset_stale(session: Session) -> list[str]:
    """端點超過 7 天未回報(last_seen)。"""
    cutoff = datetime.now(UTC) - timedelta(days=7)
    stmt = (
        select(AssetInventory.hostname)
        .where(AssetInventory.last_seen.is_not(None), AssetInventory.last_seen < cutoff)
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_defender_signature_outdated(session: Session) -> list[str]:
    """Defender 病毒碼超過 3 天未更新。"""
    cutoff = datetime.now(UTC) - timedelta(days=3)
    stmt = (
        select(AssetInventory.hostname)
        .where(
            AssetInventory.defender_signature_date.is_not(None),
            AssetInventory.defender_signature_date < cutoff,
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


def rule_defender_disabled(session: Session) -> list[str]:
    """asset_inventory.defender_status 不是 'enabled'。

    這個欄位目前還沒有同步 job 在填(Phase 1 的已知 TODO,見
    app/jobs/sync_assets.py 的 sync_hardware_details),規則先定義好等
    欄位有資料再生效,現在不會撈到任何列。
    """
    stmt = (
        select(AssetInventory.hostname)
        .where(
            AssetInventory.defender_status.is_not(None),
            AssetInventory.defender_status != "enabled",
        )
        .distinct()
    )
    return _distinct_hosts(session, stmt)


ALL_RULES: list[Rule] = [
    Rule("Defender 即時防護被關閉", "Critical", rule_defender_protection_disabled),
    Rule("Defender 偵測到惡意軟體但未清除成功", "Critical", rule_defender_detect_without_action),
    Rule("疑似 LSASS 憑證傾印(命令列含 lsass)", "High", rule_lsass_credential_dump_command_line),
    Rule("PowerShell -EncodedCommand", "High", rule_powershell_encoded_command),
    Rule("PowerShell 隱蔽啟動旗標(Bypass/Hidden)", "High", rule_powershell_hidden_or_bypass),
    Rule("Office 啟動 PowerShell/CMD", "High", rule_office_spawns_shell),
    Rule("LOLBin 下載(certutil/bitsadmin)", "High", rule_lolbin_download),
    Rule("mshta.exe 執行", "High", rule_mshta_execution),
    Rule("rundll32.exe 疑似腳本注入", "High", rule_rundll32_suspicious_args),
    Rule("進程執行於 Temp/Public 目錄", "Medium", rule_process_from_temp_or_public),
    Rule("PsExec 橫向移動行為", "High", rule_psexec_activity),
    Rule("WinRM 連接埠網路活動", "Medium", rule_winrm_network_activity),
    Rule("疑似掃描(短時間連線多個目的地)", "Medium", rule_network_scan_many_destinations),
    Rule("偵察指令連續執行", "Medium", rule_discovery_command_burst),
    Rule("對外連線至已知高風險連接埠", "Medium", rule_connection_to_known_bad_ports),
    Rule("端點超過 7 天未回報", "Medium", rule_asset_stale),
    Rule("Defender 病毒碼超過 3 天未更新", "Medium", rule_defender_signature_outdated),
    Rule("Defender 未啟用", "High", rule_defender_disabled),
]
