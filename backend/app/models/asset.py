import uuid
from datetime import datetime

from sqlalchemy import JSON, TIMESTAMP, BigInteger, Boolean, ForeignKey, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssetInventory(Base):
    """對應規格 schema 的 asset_inventory 表(資產清單)。

    monitor_type 區分這筆資產是怎麼來的:'velociraptor'(裝了 agent 的端點,
    見 app/jobs/sync_assets.py,以 hostname 當 upsert key)或 'snmp'(印表機/
    NAS/防火牆這類裝不了 agent、只能用 SNMP 輪詢的裝置,見
    app/jobs/sync_snmp_assets.py,以 ip 當 upsert key——這類裝置的 sysName
    常是空的或廠牌預設值,不像 hostname 一樣可靠)。NULL 視同 'velociraptor'
    (這個欄位是後補的,遷移會把既有資料 backfill 成 'velociraptor',但程式
    碼仍防禦性地把 NULL 當同一回事處理)。

    snmp_* 開頭的欄位只有 monitor_type='snmp' 的資產會填,對應 MIB-II 的
    sysDescr/sysObjectID/sysUpTime,以及輪詢本身的成敗狀態——snmp_last_poll_ok
    是健康分數用來判斷「現在連不連得上」的欄位,跟 last_seen 的「多久沒回報」
    是不同語意(見 app/services/health_score.py)。輪詢失敗時不會清空
    hostname/snmp_sys_descr/last_seen 這些既有身分資訊,只更新
    snmp_last_poll_at/snmp_last_poll_ok。
    """

    __tablename__ = "asset_inventory"

    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(Text)
    os_version: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    model: Mapped[str | None] = mapped_column(Text)
    cpu: Mapped[str | None] = mapped_column(Text)
    memory: Mapped[str | None] = mapped_column(Text)
    defender_status: Mapped[str | None] = mapped_column(Text)
    defender_last_scan: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    defender_signature_date: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    monitor_type: Mapped[str | None] = mapped_column(Text)
    device_type: Mapped[str | None] = mapped_column(Text)
    snmp_sys_descr: Mapped[str | None] = mapped_column(Text)
    snmp_sys_object_id: Mapped[str | None] = mapped_column(Text)
    snmp_uptime_seconds: Mapped[int | None] = mapped_column(BigInteger)
    snmp_last_poll_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    snmp_last_poll_ok: Mapped[bool | None] = mapped_column(Boolean)
    # Phase 2:裝置類型專屬指標(印表機碳粉/NAS 磁碟/防火牆與路由器介面),見
    # app/jobs/sync_snmp_assets.py 的 _collect_*_metrics()。這些裝置類型統一
    # 用同一種 [{"label": ..., "value": ...}, ...] 形狀存進 snmp_metric_data,
    # 前端可以用同一套 Label/Value 清單渲染,不用依裝置類型分別刻 UI。
    # snmp_metric_alert 只有命中門檻(碳粉過低/磁碟過高/介面異常)時才非
    # NULL,同時餵給健康分數扣分(見 health_score.py)與前端顯示,一次輪詢
    # 抓到的多個異常併成一句話,不做多筆告警的資料結構。table walk 失敗或
    # 逾時不影響 MIB-II 判定的 snmp_last_poll_ok,也不清空這兩欄的舊值,
    # 邏輯跟 snmp_sys_descr 等欄位的「輪詢失敗保留上次成功值」一致。
    snmp_metric_data: Mapped[list[dict[str, str]] | None] = mapped_column(JSON)
    snmp_metric_alert: Mapped[str | None] = mapped_column(Text)


class SoftwareInventory(Base):
    """對應規格 schema 的 software_inventory 表(軟體清單)。

    規格原表沒有定義 primary key,這裡加一個 surrogate id 純粹是 ORM/
    Alembic 操作需要,不影響規格描述的欄位語意。
    """

    __tablename__ = "software_inventory"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("asset_inventory.asset_id"))
    software_name: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(Text)
    publisher: Mapped[str | None] = mapped_column(Text)
    install_date: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
