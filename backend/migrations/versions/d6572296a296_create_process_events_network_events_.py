"""create process_events network_events defender_events

Revision ID: d6572296a296
Revises: b02c4cdc4f46
Create Date: 2026-09-02 18:18:33.042550

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd6572296a296'
down_revision: Union[str, Sequence[str], None] = 'b02c4cdc4f46'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

RETENTION = "INTERVAL '6 months'"


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")

    # process_events / network_events:TimescaleDB hypertable。規格原表沒有
    # primary key,但 hypertable 的唯一鍵限制必須包含分區欄位(timestamp),
    # 所以用 (id, timestamp) composite PK,而不是單一 surrogate id。
    op.create_table(
        "process_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("hostname", sa.Text()),
        sa.Column("pid", sa.Integer()),
        sa.Column("ppid", sa.Integer()),
        sa.Column("user", sa.Text()),
        sa.Column("image", sa.Text()),
        sa.Column("command_line", sa.Text()),
        sa.Column("hash", sa.Text()),
        sa.PrimaryKeyConstraint("id", "timestamp", name="pk_process_events"),
    )
    op.execute("SELECT create_hypertable('process_events', 'timestamp')")
    op.execute(f"SELECT add_retention_policy('process_events', {RETENTION})")
    op.create_index("ix_process_events_hostname", "process_events", ["hostname"])

    op.create_table(
        "network_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("hostname", sa.Text()),
        sa.Column("process_name", sa.Text()),
        sa.Column("src_ip", sa.Text()),
        sa.Column("dst_ip", sa.Text()),
        sa.Column("dst_port", sa.Integer()),
        sa.PrimaryKeyConstraint("id", "timestamp", name="pk_network_events"),
    )
    op.execute("SELECT create_hypertable('network_events', 'timestamp')")
    op.execute(f"SELECT add_retention_policy('network_events', {RETENTION})")
    op.create_index("ix_network_events_hostname", "network_events", ["hostname"])

    # defender_events:規格明訂 event_id BIGSERIAL PRIMARY KEY(不含
    # timestamp),不符合 hypertable 的唯一鍵限制,維持一般表,6 個月保留期限
    # 改用排程清除(app/jobs/retention.py),不是原生 Timescale retention policy。
    op.create_table(
        "defender_events",
        sa.Column("event_id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("hostname", sa.Text()),
        sa.Column("event_type", sa.Text()),
        sa.Column("threat_name", sa.Text()),
        sa.Column("timestamp", sa.TIMESTAMP(timezone=True)),
    )
    op.create_index("ix_defender_events_timestamp", "defender_events", ["timestamp"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_defender_events_timestamp", table_name="defender_events")
    op.drop_table("defender_events")

    op.drop_index("ix_network_events_hostname", table_name="network_events")
    op.drop_table("network_events")

    op.drop_index("ix_process_events_hostname", table_name="process_events")
    op.drop_table("process_events")
