"""Store per-organization memory authority and task-scoped claims.

Revision ID: 0009
Revises: 0008
"""

from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def _with_sqlite_fk_pause(action):
    if op.get_bind().dialect.name != "sqlite":
        action()
        return
    # SQLite batch table copies must temporarily suspend FK checks while
    # referenced tables are replaced. Check every relation before restoring.
    with op.get_context().autocommit_block():
        op.execute("PRAGMA foreign_keys=OFF")
        try:
            action()
            violations = op.get_bind().exec_driver_sql(
                "PRAGMA foreign_key_check").fetchall()
            if violations:
                raise RuntimeError("memory migration left broken foreign keys")
        finally:
            op.execute("PRAGMA foreign_keys=ON")


def upgrade():
    def apply():
        with op.batch_alter_table("organizations") as batch:
            batch.add_column(sa.Column("memory_authority", sa.String(),
                                       nullable=False, server_default="hybrid"))
            batch.create_check_constraint("ck_org_memory_authority",
                "memory_authority IN ('session_auto','hybrid','human_gated')")
        with op.batch_alter_table("memory_claims", table_args=[
                sa.CheckConstraint("status IN ('pending','promoted','rejected')",
                                   name="ck_memory_status")]) as batch:
            batch.add_column(sa.Column("task_id", sa.String(), nullable=True))
            batch.create_foreign_key("fk_memory_claim_task", "tasks", ["task_id"],
                                     ["task_id"])
        op.create_index("idx_memory_task", "memory_claims",
                        ["org_id", "task_id", "status"])
    _with_sqlite_fk_pause(apply)


def downgrade():
    def apply():
        op.drop_index("idx_memory_task", table_name="memory_claims")
        with op.batch_alter_table("memory_claims", table_args=[
                sa.CheckConstraint("status IN ('pending','promoted','rejected')",
                                   name="ck_memory_status")]) as batch:
            batch.drop_constraint("fk_memory_claim_task", type_="foreignkey")
            batch.drop_column("task_id")
        with op.batch_alter_table("organizations") as batch:
            batch.drop_constraint("ck_org_memory_authority", type_="check")
            batch.drop_column("memory_authority")
    _with_sqlite_fk_pause(apply)
