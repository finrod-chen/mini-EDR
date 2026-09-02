"""AI Alert Explain(Phase 6,選配)。

規格的設計原則:「AI 僅用於輔助說明,不參與偵測判斷本身」,這裡的 system
prompt 刻意要求模型不下判斷、不建議具體應變動作,只描述行為模式與調查
方向。

LLM API 用 OpenAI-compatible 的 `/chat/completions` REST 介面,不綁定特定
供應商(規劃決策:openai-compatible 設計)——只要目標端點相容這個介面
規格就能換供應商,不用改程式碼,只要改 `LLM_BASE_URL` / `LLM_API_KEY` /
`LLM_MODEL` 設定值。

送出去的告警上下文會先做基本遮罩(規劃決策:先遮罩再送,較保守):
hostname/user 只保留前 4 個字元、其餘用 *** 蓋掉,不送完整實體名稱;
command_line 保留完整內容不遮罩——遮罩掉指令內容會讓可疑行為失去可判讀性,
這是規劃時明確接受的取捨,不是遺漏。
"""

from __future__ import annotations

import json
from datetime import timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.alert import Alert
from app.models.events import ProcessEvent

MASK_KEEP_CHARS = 4
COMMAND_LINE_MAX_LEN = 500
RELATED_EVENTS_WINDOW = timedelta(minutes=10)
RELATED_EVENTS_LIMIT = 5
REQUEST_TIMEOUT_SECONDS = 30.0

SYSTEM_PROMPT = (
    "你是內部 EDR 平台的告警輔助說明助理。你的任務只是幫資安分析師「解釋」"
    "這筆告警可能代表什麼、有哪些後續調查方向,用繁體中文回答,控制在 150 字"
    "以內。你不做偵測判斷,不下達「這是/不是攻擊」的結論,也不建議具體的"
    "隔離主機/砍進程等應變動作(那是分析師的職責),只描述觀察到的行為模式"
    "與可能的解讀方向。"
)


class LlmNotConfiguredError(Exception):
    """LLM_BASE_URL / LLM_API_KEY 沒有設定。"""


def mask_value(value: str | None, keep: int = MASK_KEEP_CHARS) -> str | None:
    if not value:
        return value
    return f"{value[:keep]}***"


def _related_process_events(session: Session, alert: Alert) -> list[dict[str, str | None]]:
    if not alert.host or not alert.created_at:
        return []

    since = alert.created_at - RELATED_EVENTS_WINDOW
    until = alert.created_at + RELATED_EVENTS_WINDOW
    stmt = (
        select(ProcessEvent)
        .where(
            ProcessEvent.hostname == alert.host,
            ProcessEvent.timestamp >= since,
            ProcessEvent.timestamp <= until,
        )
        .order_by(ProcessEvent.timestamp.desc())
        .limit(RELATED_EVENTS_LIMIT)
    )
    events = session.execute(stmt).scalars().all()
    return [
        {
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "image": event.image,
            "command_line": (event.command_line or "")[:COMMAND_LINE_MAX_LEN],
            "user": mask_value(event.user),
        }
        for event in events
    ]


def build_alert_context(session: Session, alert: Alert) -> dict[str, object]:
    return {
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "host": mask_value(alert.host),
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "related_process_events": _related_process_events(session, alert),
    }


def explain_alert(session: Session, alert: Alert) -> str:
    if not settings.llm_base_url or not settings.llm_api_key:
        raise LlmNotConfiguredError("LLM_BASE_URL / LLM_API_KEY 沒有設定")

    context = build_alert_context(session, alert)
    response = httpx.post(
        f"{settings.llm_base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {settings.llm_api_key}"},
        json={
            "model": settings.llm_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
            ],
            "max_tokens": 400,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    data = response.json()
    return str(data["choices"][0]["message"]["content"]).strip()
