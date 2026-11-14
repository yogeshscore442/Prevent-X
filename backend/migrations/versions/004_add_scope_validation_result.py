"""Add scope_validation_result to discovery_jobs for authorization audit evidence

Revision ID: 004_add_scope_validation_result
Revises: 003_attack_surface_refinements
Create Date: 2026-11-14 17:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '004_add_scope_validation_result'
down_revision: Union[str, None] = '003_attack_surface_refinements'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'discovery_jobs',
        sa.Column('scope_validation_result', sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('discovery_jobs', 'scope_validation_result')
