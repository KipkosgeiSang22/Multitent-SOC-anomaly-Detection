"""add event_issues table

Revision ID: a1b2c3d4e5f6
Revises: fb527bec8768
Create Date: 2026-05-16

"""
from alembic import op
import sqlalchemy as sa

revision = 'a1b2c3d4e5f6'
down_revision = 'fb527bec8768'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'event_issues',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('event_id', sa.Integer(), sa.ForeignKey('operational_events.id'), nullable=False),
        sa.Column('client_id', sa.Integer(), sa.ForeignKey('clients.id'), nullable=False),
        sa.Column('raised_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('issue_text', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('analyst_comment', sa.Text(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted', sa.Boolean(), nullable=False, server_default='false'),
    )
    op.create_index('ix_event_issues_event_id', 'event_issues', ['event_id'])
    op.create_index('ix_event_issues_client_id', 'event_issues', ['client_id'])
    op.create_index(
        'ix_event_issues_open',
        'event_issues',
        ['client_id', 'resolved_at'],
        postgresql_where=sa.text('resolved_at IS NULL AND deleted = false'),
    )


def downgrade() -> None:
    op.drop_table('event_issues')