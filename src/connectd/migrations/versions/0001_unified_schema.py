"""Initial unified control-plane schema.

Revision ID: 0001
Revises:
"""

from alembic import op

from connectd.db import metadata


revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    metadata.create_all(op.get_bind())


def downgrade():
    metadata.drop_all(op.get_bind())
