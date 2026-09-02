import random
from datetime import datetime

from sqlalchemy import TIMESTAMP, BigInteger, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


def random_bigint() -> int:
    """這幾張事件表的 surrogate id 欄位用這個當 client 端預設值,不靠 DB 端
    identity/serial 生成。

    SQLite(單元測試用)的 autoincrement/rowid 別名只在「單一 integer 欄位
    當 PK」時才會自動生效,ProcessEvent/NetworkEvent 是 (id, timestamp)
    composite PK、完全不支援,DefenderEvent 雖是單一欄位 PK,但用
    `sa.Identity()` 一樣沒有讓 SQLite 生效——都會導致測試環境 insert 直接
    失敗。正式環境是 Postgres,不靠 DB identity 生成 id 一樣正確運作,只是
    不是嚴格遞增,但這個 id 本來就只是拿來滿足 PK 唯一性,沒有業務上的
    意義,不要求遞增。
    """
    return random.getrandbits(63)


class ProcessEvent(Base):
    """對應規格 schema 的 process_events 表(Sysmon 進程事件,TimescaleDB hypertable)。

    規格原表沒有定義 primary key。TimescaleDB hypertable 若要有唯一/主鍵限制,
    必須包含分區欄位(timestamp),所以這裡用 (id, timestamp) 當 composite PK,
    而不是單一 surrogate id——單一 id PK 會不滿足 hypertable 的限制。
    """

    __tablename__ = "process_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=random_bigint)
    timestamp: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    hostname: Mapped[str | None] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    user: Mapped[str | None] = mapped_column(Text)
    image: Mapped[str | None] = mapped_column(Text)
    command_line: Mapped[str | None] = mapped_column(Text)
    hash: Mapped[str | None] = mapped_column(Text)


class NetworkEvent(Base):
    """對應規格 schema 的 network_events 表(Sysmon 網路事件,TimescaleDB hypertable)。

    PK 設計理由同 ProcessEvent。
    """

    __tablename__ = "network_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=random_bigint)
    timestamp: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    hostname: Mapped[str | None] = mapped_column(Text)
    process_name: Mapped[str | None] = mapped_column(Text)
    src_ip: Mapped[str | None] = mapped_column(Text)
    dst_ip: Mapped[str | None] = mapped_column(Text)
    dst_port: Mapped[int | None] = mapped_column(Integer)


class DefenderEvent(Base):
    """對應規格 schema 的 defender_events 表(Defender AV 事件)。

    規格明訂 `event_id BIGSERIAL PRIMARY KEY`(不含 timestamp),不符合
    TimescaleDB hypertable 對唯一鍵需含分區欄位的限制,所以這張表維持一般表,
    不轉 hypertable;6 個月保留期限改用排程清除(見 app/jobs/retention.py),
    不是原生 TimescaleDB retention policy。
    """

    __tablename__ = "defender_events"

    event_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=random_bigint)
    hostname: Mapped[str | None] = mapped_column(Text)
    event_type: Mapped[str | None] = mapped_column(Text)
    threat_name: Mapped[str | None] = mapped_column(Text)
    timestamp: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
