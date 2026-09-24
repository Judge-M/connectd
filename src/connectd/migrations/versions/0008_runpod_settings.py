"""Add per-organization RunPod quote fallback switch.

Revision ID: 0008
Revises: 0007
"""

from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("organizations") as batch:
        batch.add_column(sa.Column("allow_unquoted_runpod", sa.Boolean(),
                                   nullable=False, server_default="0"))


def downgrade():
    with op.batch_alter_table("organizations") as batch:
        batch.drop_column("allow_unquoted_runpod")
