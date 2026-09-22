import uuid
from datetime import datetime

from sqlalchemy import TIMESTAMP, ForeignKey, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Alert(Base):
    """對應規格 schema 的 alerts 表(自製規則 + Defender 事件統一寫入同一張表)。"""

    __tablename__ = "alerts"

    alert_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    severity: Mapped[str | None] = mapped_column(Text)  # Critical / High / Medium / Low
    rule_name: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str | None] = mapped_column(Text)
    # open / acknowledged / resolved / false_positive
    status: Mapped[str | None] = mapped_column(Text)
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class AlertSuppression(Base):
    """標記誤判後,同一 (rule_name, host) 在到期前暫時不再開新 alert。

    這是「誤判」跟「忽略」目前唯一有實際行為差異的地方——忽略只改
    alert.status,不寫這張表,規則引擎(見 app/rules/engine.py)下次一樣會
    正常開新 alert。誤判則會 upsert 一筆到這裡,suppressed_until 之前同一
    (rule_name, host) 再次觸發不會產生新 alert,避免分析師重複確認同一個
    已知誤判。刻意給到期時間而不是永久 allowlist,因為同一台主機/同一條
    規則之後也可能是真的事件,不該永久靜音;到期時間見
    Settings.false_positive_suppression_days。
    """

    __tablename__ = "alert_suppressions"
    __table_args__ = (
        UniqueConstraint("rule_name", "host", name="uq_alert_suppressions_rule_host"),
    )

    suppression_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(Text, nullable=False)
    suppressed_until: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    # 觸發這次抑制的那筆 alert,純粹方便追查來源,alert 被刪除不影響抑制本身。
    source_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("alerts.alert_id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
