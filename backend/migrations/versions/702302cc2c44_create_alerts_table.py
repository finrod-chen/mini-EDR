"""create alerts table

Revision ID: 702302cc2c44
Revises: d6572296a296
Create Date: 2026-09-03 01:57:22.383216

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '702302cc2c44'
down_revision: Union[str, Sequence[str], None] = 'd6572296a296'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.Uuid(), primary_key=True),
        sa.Column("severity", sa.Text()),
        sa.Column("rule_name", sa.Text()),
        sa.Column("host", sa.Text()),
        sa.Column("status", sa.Text()),
        sa.Column("ai_explanation", sa.Text()),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True)),
    )
    op.create_index("ix_alerts_rule_name_host_status", "alerts", ["rule_name", "host", "status"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_alerts_rule_name_host_status", table_name="alerts")
    op.drop_table("alerts")
