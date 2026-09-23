"""create syslog_messages table

Revision ID: 978e905ac9e3
Revises: 7674c3c30198
Create Date: 2026-09-23 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '978e905ac9e3'
down_revision: Union[str, Sequence[str], None] = '7674c3c30198'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

RETENTION = "INTERVAL '30 days'"


def upgrade() -> None:
    """Upgrade schema."""
    # 每一行原始 syslog 都存一筆(見 app/services/syslog_listener.py),
    # 量遠比只在命中規則時才寫的 alerts 大,PK 設計理由跟 process_events/
    # network_events(migration d6572296a296)一致:hypertable 的唯一鍵
    # 限制必須包含分區欄位(received_at)。
    op.create_table(
        "syslog_messages",
        sa.Column("id", sa.BigInteger(), sa.Identity(), nullable=False),
        sa.Column("received_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("source_ip", sa.Text()),
        sa.Column("source_type", sa.Text()),
        sa.Column("raw_message", sa.Text()),
        sa.PrimaryKeyConstraint("id", "received_at", name="pk_syslog_messages"),
    )
    op.execute("SELECT create_hypertable('syslog_messages', 'received_at')")
    op.execute(f"SELECT add_retention_policy('syslog_messages', {RETENTION})")
    op.create_index("ix_syslog_messages_source_type", "syslog_messages", ["source_type"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_syslog_messages_source_type", table_name="syslog_messages")
    op.drop_table("syslog_messages")
