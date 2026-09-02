"""create asset_inventory and software_inventory

Revision ID: b02c4cdc4f46
Revises:
Create Date: 2026-09-02 18:02:09.086225

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b02c4cdc4f46'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "asset_inventory",
        sa.Column("asset_id", sa.Uuid(), primary_key=True),
        sa.Column("hostname", sa.Text()),
        sa.Column("ip", sa.Text()),
        sa.Column("os_version", sa.Text()),
        sa.Column("vendor", sa.Text()),
        sa.Column("model", sa.Text()),
        sa.Column("cpu", sa.Text()),
        sa.Column("memory", sa.Text()),
        sa.Column("defender_status", sa.Text()),
        sa.Column("defender_last_scan", sa.TIMESTAMP(timezone=True)),
        sa.Column("defender_signature_date", sa.TIMESTAMP(timezone=True)),
        sa.Column("last_seen", sa.TIMESTAMP(timezone=True)),
    )

    op.create_table(
        "software_inventory",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "asset_id",
            sa.Uuid(),
            sa.ForeignKey("asset_inventory.asset_id"),
            nullable=False,
        ),
        sa.Column("software_name", sa.Text()),
        sa.Column("version", sa.Text()),
        sa.Column("publisher", sa.Text()),
        sa.Column("install_date", sa.TIMESTAMP(timezone=True)),
    )
    op.create_index(
        "ix_software_inventory_asset_id", "software_inventory", ["asset_id"]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_software_inventory_asset_id", table_name="software_inventory")
    op.drop_table("software_inventory")
    op.drop_table("asset_inventory")
