"""Add organization and local operator identities.

Revision ID: 0006
Revises: 0005
"""

from alembic import op
import sqlalchemy as sa


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("organizations",
        sa.Column("org_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False))
    op.execute("""INSERT INTO organizations(org_id,name,created_at)
        VALUES ('default','Default','1970-01-01T00:00:00+00:00')""")
    op.create_table("operator_users",
        sa.Column("user_id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("organizations.org_id"), nullable=False),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False, unique=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.CheckConstraint("role IN ('admin','operator','viewer')"))
    with op.batch_alter_table("memory_claims", table_args=(
        sa.CheckConstraint("status IN ('pending','promoted','rejected')"),
    )) as batch:
        batch.add_column(sa.Column("org_id", sa.String(), nullable=False,
                                   server_default="default"))
        batch.create_foreign_key("fk_memory_claims_org_id", "organizations",
                                 ["org_id"], ["org_id"])
    with op.batch_alter_table("tasks", table_args=(
        sa.CheckConstraint("privacy_class IN ('public','low_sensitive','repo_sensitive','secret_sensitive')"),
        sa.CheckConstraint("status IN ('active','pending_clarification','completed','failed','legacy_audit_stub')"),
    )) as batch:
        batch.add_column(sa.Column("org_id", sa.String(), nullable=False,
                                   server_default="default"))
        batch.create_foreign_key("fk_tasks_org_id", "organizations", ["org_id"], ["org_id"])


def downgrade():
    with op.batch_alter_table("tasks", table_args=(
        sa.CheckConstraint("privacy_class IN ('public','low_sensitive','repo_sensitive','secret_sensitive')"),
        sa.CheckConstraint("status IN ('active','pending_clarification','completed','failed','legacy_audit_stub')"),
    )) as batch:
        batch.drop_constraint("fk_tasks_org_id", type_="foreignkey")
        batch.drop_column("org_id")
    with op.batch_alter_table("memory_claims", table_args=(
        sa.CheckConstraint("status IN ('pending','promoted','rejected')"),
    )) as batch:
        batch.drop_constraint("fk_memory_claims_org_id", type_="foreignkey")
        batch.drop_column("org_id")
    op.drop_table("operator_users")
    op.drop_table("organizations")
