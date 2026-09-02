"""create users and response_actions tables

Revision ID: d939764ccf8e
Revises: 702302cc2c44
Create Date: 2026-09-03 02:08:27.607734

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd939764ccf8e'
down_revision: Union[str, Sequence[str], None] = '702302cc2c44'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("role", sa.Text(), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
    )

    op.create_table(
        "response_actions",
        sa.Column("action_id", sa.Uuid(), primary_key=True),
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.alert_id")),
        sa.Column("action_type", sa.Text()),
        sa.Column("performed_by", sa.Text()),
        sa.Column("performed_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("result", sa.Text()),
    )
    op.create_index("ix_response_actions_alert_id", "response_actions", ["alert_id"])
    op.create_index("ix_response_actions_performed_at", "response_actions", ["performed_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_response_actions_performed_at", table_name="response_actions")
    op.drop_index("ix_response_actions_alert_id", table_name="response_actions")
    op.drop_table("response_actions")
    op.drop_table("users")
