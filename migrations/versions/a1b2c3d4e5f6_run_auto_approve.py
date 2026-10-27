"""Add Run.auto_approve column.

Operator-opt-in: when true, approvals created for this run are auto-decided (approved,
by="auto-approve"). Audit trail stays intact — the approval record is still created and
approval.decided fires in the ledger. Only use for lab/testing targets.

Revision ID: a1b2c3d4e5f6
Revises: c9b010ffad77
Create Date: 2026-10-21
"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = '054e4eb6fddc'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("runs") as batch:
        batch.add_column(sa.Column("auto_approve", sa.Boolean(),
                                   server_default=sa.text("0"), nullable=False))


def downgrade() -> None:
    with op.batch_alter_table("runs") as batch:
        batch.drop_column("auto_approve")
