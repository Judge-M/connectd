"""Persist independent librarian jobs and untrusted organization candidates.

Revision ID: 0012
Revises: 0011
"""

from alembic import op
import sqlalchemy as sa


revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("memory_evaluation_jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column("source_claim_id", sa.String(), sa.ForeignKey("memory_claims.claim_id"),
                  nullable=False, unique=True),
        sa.Column("candidate_claim_id", sa.String(), sa.ForeignKey("memory_claims.claim_id"),
                  nullable=False, unique=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.org_id"), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("evaluator_score", sa.Float()),
        sa.Column("reason", sa.Text()),
        sa.CheckConstraint("status IN ('pending','evaluating','promoted','review_required')"))
    op.create_index("idx_memory_evaluation_queue", "memory_evaluation_jobs",
                    ["status", "created_at"])


def downgrade():
    op.drop_index("idx_memory_evaluation_queue", table_name="memory_evaluation_jobs")
    op.drop_table("memory_evaluation_jobs")
