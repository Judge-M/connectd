"""Record bounded rented Pod leases and budget reservations.

Revision ID: 0014
Revises: 0013
"""

from alembic import op
import sqlalchemy as sa


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("pod_leases",
        sa.Column("lease_id", sa.String(), primary_key=True),
        sa.Column("task_id", sa.String(), sa.ForeignKey("tasks.task_id"), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.org_id"), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("pod_name", sa.String(), nullable=False, unique=True),
        sa.Column("pod_id", sa.String(), unique=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("request_json", sa.Text(), nullable=False),
        sa.Column("hourly_cap_cents", sa.Integer(), nullable=False),
        sa.Column("lease_seconds", sa.Integer(), nullable=False),
        sa.Column("reservation_id", sa.String(), sa.ForeignKey("quota_records.record_id"),
                  nullable=False),
        sa.Column("quoted_gpu_hourly_usd", sa.String()),
        sa.Column("reported_hourly_usd", sa.String()),
        sa.Column("billing_total_usd", sa.String()),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("started_at", sa.String()),
        sa.Column("expires_at", sa.String()),
        sa.Column("ended_at", sa.String()),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("last_error", sa.Text()),
        sa.CheckConstraint("state IN ('creating','active','delete_pending','billing_pending','closed','overrun','failed')"),
        sa.CheckConstraint("hourly_cap_cents > 0"),
        sa.CheckConstraint("lease_seconds BETWEEN 1 AND 86400"))
    op.create_index("idx_pod_leases_due", "pod_leases", ["state", "expires_at"])


def downgrade():
    op.drop_index("idx_pod_leases_due", table_name="pod_leases")
    op.drop_table("pod_leases")
