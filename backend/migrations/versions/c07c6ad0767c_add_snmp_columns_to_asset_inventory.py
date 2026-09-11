"""add snmp columns to asset_inventory

Revision ID: c07c6ad0767c
Revises: d939764ccf8e
Create Date: 2026-09-11 14:41:38.713256

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c07c6ad0767c'
down_revision: Union[str, Sequence[str], None] = 'd939764ccf8e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("asset_inventory", sa.Column("monitor_type", sa.Text()))
    op.add_column("asset_inventory", sa.Column("device_type", sa.Text()))
    op.add_column("asset_inventory", sa.Column("snmp_sys_descr", sa.Text()))
    op.add_column("asset_inventory", sa.Column("snmp_sys_object_id", sa.Text()))
    op.add_column("asset_inventory", sa.Column("snmp_uptime_seconds", sa.BigInteger()))
    op.add_column("asset_inventory", sa.Column("snmp_last_poll_at", sa.TIMESTAMP(timezone=True)))
    op.add_column("asset_inventory", sa.Column("snmp_last_poll_ok", sa.Boolean()))
    # 既有資產都是 Velociraptor agent 同步進來的,明確 backfill 成
    # 'velociraptor',不留 NULL——之後只有新的 SNMP 資產才會是 'snmp'。
    op.execute("UPDATE asset_inventory SET monitor_type = 'velociraptor' WHERE monitor_type IS NULL")


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("asset_inventory", "snmp_last_poll_ok")
    op.drop_column("asset_inventory", "snmp_last_poll_at")
    op.drop_column("asset_inventory", "snmp_uptime_seconds")
    op.drop_column("asset_inventory", "snmp_sys_object_id")
    op.drop_column("asset_inventory", "snmp_sys_descr")
    op.drop_column("asset_inventory", "device_type")
    op.drop_column("asset_inventory", "monitor_type")
