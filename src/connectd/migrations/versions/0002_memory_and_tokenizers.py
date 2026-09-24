"""Preserve memory authority metadata and register model tokenizers.

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa


revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    for column in (
        sa.Column("confidence", sa.Float()),
        sa.Column("confidence_label", sa.String()),
        sa.Column("valid_from", sa.String()),
        sa.Column("valid_until", sa.String()),
        sa.Column("learned_at", sa.String()),
        sa.Column("last_verified_at", sa.String()),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("superseded_by", sa.String()),
    ):
        op.add_column("memory_claims", column)
    for column in (
        sa.Column("source_id", sa.String()),
        sa.Column("origin", sa.String()),
        sa.Column("title", sa.Text()),
        sa.Column("location", sa.Text()),
        sa.Column("mime_type", sa.String()),
    ):
        op.add_column("claim_provenance", column)
    op.add_column("compute_nodes", sa.Column("tokenizer_json", sa.Text()))


def downgrade():
    op.drop_column("compute_nodes", "tokenizer_json")
    for name in ("mime_type", "location", "title", "origin", "source_id"):
        op.drop_column("claim_provenance", name)
    for name in ("superseded_by", "tags_json", "last_verified_at", "learned_at",
                 "valid_until", "valid_from", "confidence_label", "confidence"):
        op.drop_column("memory_claims", name)
