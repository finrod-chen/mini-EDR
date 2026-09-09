"""資產健康分數計算(對應規格〈資產管理頁面〉的 Asset Health Score)。

規格給的範例扣分項目:「作業系統過舊 -20、Defender 未啟用 -20、超過 30 天
未更新 -10」,沒有明確定義怎麼判斷「過舊」「未更新」,這裡採用以下詮釋
(不是規格逐字定義,是合理但需要之後跟使用者確認的假設):

- 作業系統過舊:os_version 命中 KNOWN_EOL_OS_KEYWORDS 的關鍵字比對。清單
  刻意只放官方公告已經很久、日期確定不會再變的舊版本(Windows 7/8.1/10 已
  全面停止支援),更細的功能更新層級 EOL(例如 Windows 11 個別 xxH2)日期
  會隨時間持續增加,需要另外維護一份會變動的清單,先不做,避免寫入之後
  可能過時或記錯的日期。
- Defender 未啟用:defender_status 不是 'enabled'(這個欄位目前還沒有
  同步 job 在填,見 app/jobs/sync_assets.py 的已知 TODO)。
- 超過 30 天未更新:asset_inventory 沒有獨立的「最後修補/更新時間」欄位,
  用 last_seen 當代理指標(端點太久沒回報,也代表太久沒被管理/更新)。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.models.asset import AssetInventory

KNOWN_EOL_OS_KEYWORDS = ("windows 7", "windows 8.1", "windows 10")
STALE_LAST_SEEN_DAYS = 30

OS_EOL_PENALTY = 20
DEFENDER_DISABLED_PENALTY = 20
STALE_LAST_SEEN_PENALTY = 10


@dataclass
class HealthScoreDeduction:
    reason: str
    points: int


def calculate_health_score_breakdown(asset: AssetInventory) -> list[HealthScoreDeduction]:
    """列出實際命中的每一項扣分理由,供資產管理頁面展開明細用。

    起始分數固定 100,不列進 breakdown——UI 端用 100 減掉這裡回傳的
    points 總和重新算出總分,兩邊資料來源保持一致,不用另外傳一個
    起始值欄位。
    """
    deductions: list[HealthScoreDeduction] = []

    os_version = (asset.os_version or "").lower()
    if any(keyword in os_version for keyword in KNOWN_EOL_OS_KEYWORDS):
        deductions.append(
            HealthScoreDeduction(f"作業系統過舊({asset.os_version})", OS_EOL_PENALTY)
        )

    if asset.defender_status and asset.defender_status.lower() != "enabled":
        deductions.append(
            HealthScoreDeduction(
                f"Defender 未啟用(目前狀態:{asset.defender_status})", DEFENDER_DISABLED_PENALTY
            )
        )

    if asset.last_seen is not None:
        last_seen = asset.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        if last_seen < datetime.now(UTC) - timedelta(days=STALE_LAST_SEEN_DAYS):
            deductions.append(
                HealthScoreDeduction(
                    f"超過 {STALE_LAST_SEEN_DAYS} 天未回報", STALE_LAST_SEEN_PENALTY
                )
            )

    return deductions


def calculate_health_score(asset: AssetInventory) -> int:
    total_deduction = sum(d.points for d in calculate_health_score_breakdown(asset))
    return max(100 - total_deduction, 0)
