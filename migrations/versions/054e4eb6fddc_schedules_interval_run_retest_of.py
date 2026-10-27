"""schedules interval + run retest_of

Revision ID: 054e4eb6fddc
Revises: 0f8638aabfa2
Create Date: 2026-10-13 11:26:31.957873
"""
from alembic import op
import sqlalchemy as sa


revision = '054e4eb6fddc'
down_revision = '0f8638aabfa2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # retest_of is an app-enforced soft link (self-referential). We add the column +
    # index but NOT a DB-level FK: a self-referential FK can't be added via ALTER on
    # SQLite, and MariaDB doesn't need it for this soft link.
    op.add_column('runs', sa.Column('retest_of', sa.CHAR(length=36), nullable=True))
    op.create_index(op.f('ix_runs_retest_of'), 'runs', ['retest_of'], unique=False)
    op.add_column('schedules', sa.Column('interval_minutes', sa.Integer(), nullable=True))
    op.add_column('schedules', sa.Column('next_fire_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('schedules', sa.Column('last_fired_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f('ix_schedules_next_fire_at'), 'schedules', ['next_fire_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_schedules_next_fire_at'), table_name='schedules')
    op.drop_column('schedules', 'last_fired_at')
    op.drop_column('schedules', 'next_fire_at')
    op.drop_column('schedules', 'interval_minutes')
    op.drop_index(op.f('ix_runs_retest_of'), table_name='runs')
    op.drop_column('runs', 'retest_of')
