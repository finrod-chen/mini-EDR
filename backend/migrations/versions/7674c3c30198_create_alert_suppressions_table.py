"""create alert_suppressions table

Revision ID: 7674c3c30198
Revises: f0b2490c58e8
Create Date: 2026-09-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7674c3c30198'
down_revision: Union[str, Sequence[str], None] = 'f0b2490c58e8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "alert_suppressions",
        sa.Column("suppression_id", sa.Uuid(), nullable=False),
        sa.Column("rule_name", sa.Text(), nullable=False),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("suppressed_until", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("source_alert_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_alert_id"], ["alerts.alert_id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("suppression_id"),
        sa.UniqueConstraint("rule_name", "host", name="uq_alert_suppressions_rule_host"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("alert_suppressions")
