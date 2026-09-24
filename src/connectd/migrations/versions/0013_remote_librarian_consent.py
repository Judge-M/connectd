"""Require organization consent for remote librarian memory egress.

Revision ID: 0013
Revises: 0012
"""

from alembic import op
import sqlalchemy as sa


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("organizations", sa.Column("allow_remote_librarian", sa.Boolean(),
                                             nullable=False, server_default="0"))


def downgrade():
    with op.batch_alter_table("organizations") as batch:
        batch.drop_column("allow_remote_librarian")
