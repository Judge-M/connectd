"""Add organization ownership and explicit registry shares.

Revision ID: 0007
Revises: 0006
"""

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tool_registry", table_args=(
        sa.CheckConstraint("effect_tier BETWEEN 0 AND 2"),
        sa.CheckConstraint("cost_per_invocation_cents >= 0"),
    )) as batch:
        batch.add_column(sa.Column("owner_org_id", sa.String(), nullable=False,
                                   server_default="default"))
        batch.create_foreign_key("fk_tool_registry_owner_org", "organizations",
                                 ["owner_org_id"], ["org_id"])
    with op.batch_alter_table("compute_nodes", table_args=(
        sa.CheckConstraint("privacy_tier IN ('local_only','private_rented','external')"),
    )) as batch:
        batch.add_column(sa.Column("owner_org_id", sa.String(), nullable=False,
                                   server_default="default"))
        batch.create_foreign_key("fk_compute_nodes_owner_org", "organizations",
                                 ["owner_org_id"], ["org_id"])
    op.create_table("registry_shares",
        sa.Column("owner_org_id", sa.String(), sa.ForeignKey("organizations.org_id"),
                  nullable=False),
        sa.Column("target_org_id", sa.String(), sa.ForeignKey("organizations.org_id"),
                  nullable=False),
        sa.Column("resource_kind", sa.String(), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("owner_org_id", "target_org_id", "resource_kind",
                                "resource_id"),
        sa.CheckConstraint("resource_kind IN ('tool','node')"))
    op.create_index("idx_registry_shares_target", "registry_shares",
                    ["target_org_id", "resource_kind", "resource_id"])


def downgrade():
    op.drop_index("idx_registry_shares_target", table_name="registry_shares")
    op.drop_table("registry_shares")
    with op.batch_alter_table("compute_nodes", table_args=(
        sa.CheckConstraint("privacy_tier IN ('local_only','private_rented','external')"),
    )) as batch:
        batch.drop_constraint("fk_compute_nodes_owner_org", type_="foreignkey")
        batch.drop_column("owner_org_id")
    with op.batch_alter_table("tool_registry", table_args=(
        sa.CheckConstraint("effect_tier BETWEEN 0 AND 2"),
        sa.CheckConstraint("cost_per_invocation_cents >= 0"),
    )) as batch:
        batch.drop_constraint("fk_tool_registry_owner_org", type_="foreignkey")
        batch.drop_column("owner_org_id")
