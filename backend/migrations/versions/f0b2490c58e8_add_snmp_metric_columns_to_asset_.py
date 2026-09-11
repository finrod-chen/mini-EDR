"""add snmp metric columns to asset_inventory

Revision ID: f0b2490c58e8
Revises: c07c6ad0767c
Create Date: 2026-09-11 16:11:08.563264

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f0b2490c58e8'
down_revision: Union[str, Sequence[str], None] = 'c07c6ad0767c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("asset_inventory", sa.Column("snmp_metric_data", sa.JSON()))
    op.add_column("asset_inventory", sa.Column("snmp_metric_alert", sa.Text()))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("asset_inventory", "snmp_metric_alert")
    op.drop_column("asset_inventory", "snmp_metric_data")
