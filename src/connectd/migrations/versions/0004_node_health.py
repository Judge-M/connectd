"""Track authenticated node health and reported capacity.

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa


revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("compute_nodes", sa.Column("health_url", sa.Text()))
    op.add_column("compute_nodes", sa.Column("last_health_at", sa.String()))
    op.add_column("compute_nodes", sa.Column("capacity_json", sa.Text()))


def downgrade():
    op.drop_column("compute_nodes", "capacity_json")
    op.drop_column("compute_nodes", "last_health_at")
    op.drop_column("compute_nodes", "health_url")
