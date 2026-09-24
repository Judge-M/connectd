"""Persist reviewed built-in tool handler bindings.

Revision ID: 0010
Revises: 0009
"""

from alembic import op
import sqlalchemy as sa


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("tool_registry", sa.Column("handler_id", sa.String(), nullable=True))


def downgrade():
    with op.batch_alter_table("tool_registry") as batch:
        batch.drop_column("handler_id")
