from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.events import random_bigint


class SyslogMessage(Base):
    """收到的每一行原始 syslog(見 app/services/syslog_listener.py),不管
    有沒有命中任何分析規則都存一筆——舊的做法只有偵測規則命中才寫 DB,
    平時的流量看過即丟,事後查不到任何一行舊 log。

    TimescaleDB hypertable,PK 設計理由跟 app/models/events.py 的
    ProcessEvent/NetworkEvent 一致:hypertable 的唯一鍵限制必須包含分區
    欄位(received_at),所以用 (id, received_at) composite PK,不是單一
    surrogate id。保留期限用 migration 裡的原生
    `add_retention_policy(..., INTERVAL '30 days')` 處理,不像
    defender_events 那樣另外寫清除 job。
    """

    __tablename__ = "syslog_messages"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=random_bigint)
    received_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    source_ip: Mapped[str | None] = mapped_column(Text)
    # 'pan410' / 'synology_nas' / 'other'(見 syslog_listener.py 的
    # classify_source())。不用 DB enum——來源類型之後會持續增加,字串
    # 欄位比每加一種來源就要跑一次 migration 改 enum 值務實。
    source_type: Mapped[str | None] = mapped_column(Text)
    raw_message: Mapped[str | None] = mapped_column(Text)
