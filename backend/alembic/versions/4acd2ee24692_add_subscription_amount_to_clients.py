"""add_subscription_amount_to_clients

Revision ID: 4acd2ee24692
Revises: 058ef6587027
Create Date: 2026-06-12 09:05:51.029677

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '4acd2ee24692'
down_revision: Union[str, Sequence[str], None] = '058ef6587027'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('clients', sa.Column('subscription_amount', sa.Numeric(precision=10, scale=2), nullable=True))
    op.alter_column('operational_events', 'all_timestamps',
               existing_type=postgresql.JSON(astext_type=sa.Text()),
               type_=postgresql.JSONB(astext_type=sa.Text()),
               existing_nullable=False,
               existing_server_default=sa.text("'[]'::json"))


def downgrade() -> None:
    op.alter_column('operational_events', 'all_timestamps',
               existing_type=postgresql.JSONB(astext_type=sa.Text()),
               type_=postgresql.JSON(astext_type=sa.Text()),
               existing_nullable=False,
               existing_server_default=sa.text("'[]'::json"))
    op.drop_column('clients', 'subscription_amount')
