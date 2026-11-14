"""Attack Surface Refinements: policies, verification status, evidence nature

Revision ID: 003_attack_surface_refinements
Revises: 002_attack_surface_schema
Create Date: 2026-11-14 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '003_attack_surface_refinements'
down_revision: Union[str, None] = '002_attack_surface_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add discovery_policy to discovery_jobs
    op.add_column(
        'discovery_jobs',
        sa.Column('discovery_policy', sa.String(50), nullable=False, server_default='PUBLIC_PASSIVE'),
    )
    op.create_index('ix_discovery_jobs_policy', 'discovery_jobs', ['discovery_policy'])

    # 2. Add verification_status and evidence_nature to exposure_findings
    op.add_column(
        'exposure_findings',
        sa.Column('verification_status', sa.String(50), nullable=False, server_default='UNVERIFIED_RESOURCE'),
    )
    op.add_column(
        'exposure_findings',
        sa.Column('evidence_nature', sa.String(50), nullable=False, server_default='POTENTIAL_WEAKNESS'),
    )
    op.create_index('ix_exposure_findings_verification', 'exposure_findings', ['verification_status'])
    op.create_index('ix_exposure_findings_nature', 'exposure_findings', ['evidence_nature'])


def downgrade() -> None:
    op.drop_index('ix_exposure_findings_nature', table_name='exposure_findings')
    op.drop_index('ix_exposure_findings_verification', table_name='exposure_findings')
    op.drop_column('exposure_findings', 'evidence_nature')
    op.drop_column('exposure_findings', 'verification_status')

    op.drop_index('ix_discovery_jobs_policy', table_name='discovery_jobs')
    op.drop_column('discovery_jobs', 'discovery_policy')
