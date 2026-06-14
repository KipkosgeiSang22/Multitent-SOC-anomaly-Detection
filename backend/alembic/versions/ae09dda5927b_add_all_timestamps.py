"""add_all_timestamps

Revision ID: ae09dda5927b
Revises: 20f842000e6d
Create Date: 2026-06-01 21:52:03.982383

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ae09dda5927b'
down_revision: Union[str, Sequence[str], None] = '20f842000e6d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
