"""add_all_timestamps

Revision ID: 058ef6587027
Revises: ae09dda5927b
Create Date: 2026-06-01 22:11:58.421656

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '058ef6587027'
down_revision: Union[str, Sequence[str], None] = 'ae09dda5927b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Add the new column with default []
    op.add_column(
        "operational_events",
        sa.Column("all_timestamps", sa.JSON(), nullable=False, server_default="[]"),
    )

    # Backfill existing rows from time_summary
    op.execute(
        """
        UPDATE operational_events
        SET all_timestamps = COALESCE(
            (
                SELECT jsonb_agg(trim(token))
                FROM (
                    SELECT regexp_split_to_table(time_summary, '\|') AS token
                ) AS parts
                WHERE trim(token) <> ''
            ),
            '[]'::jsonb
        );
        """
    )


def downgrade() -> None:
    # Drop the column if rolling back
    op.drop_column("operational_events", "all_timestamps")