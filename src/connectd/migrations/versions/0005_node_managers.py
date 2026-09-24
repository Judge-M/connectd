"""Bind registered nodes to configured mTLS managers.

Revision ID: 0005
Revises: 0004
"""

from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("compute_nodes", sa.Column("manager_id", sa.String()))


def downgrade():
    op.drop_column("compute_nodes", "manager_id")
