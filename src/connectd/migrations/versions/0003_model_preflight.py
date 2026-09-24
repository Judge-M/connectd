"""Register provider token-count preflight endpoints.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa


revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("compute_nodes", sa.Column("preflight_url", sa.Text()))


def downgrade():
    op.drop_column("compute_nodes", "preflight_url")
