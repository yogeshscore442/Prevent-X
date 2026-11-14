"""Enhance attack paths and add trust relationships, prevention recommendations, and analysis jobs

Revision ID: 007_enhance_attack_path_engine
Revises: 006_enhance_vulnerability_engine
Create Date: 2026-11-14 20:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '007_enhance_attack_path_engine'
down_revision: Union[str, None] = '006_enhance_vulnerability_engine'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Enhance attack_paths table
    op.add_column('attack_paths', sa.Column('severity', sa.String(20), nullable=False, server_default='MEDIUM'))
    op.add_column('attack_paths', sa.Column('confidence', sa.String(30), nullable=False, server_default='POTENTIAL'))
    op.add_column('attack_paths', sa.Column('title', sa.String(255), nullable=True))
    op.add_column('attack_paths', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('path_narrative', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('graph_data', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('mitre_tactics', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('mitre_techniques', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('prerequisites', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('evidence_references', sa.Text(), nullable=True))
    op.add_column('attack_paths', sa.Column('status', sa.String(30), nullable=False, server_default='IDENTIFIED'))

    op.create_index('ix_attack_paths_severity', 'attack_paths', ['severity'])
    op.create_index('ix_attack_paths_confidence', 'attack_paths', ['confidence'])
    op.create_index('ix_attack_paths_status', 'attack_paths', ['status'])

    # 2. Create asset_trust_relationships table
    op.create_table(
        'asset_trust_relationships',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('relationship_type', sa.String(50), nullable=False, server_default='SAME_SUBNET'),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('evidence_source', sa.String(100), nullable=False, server_default='DISCOVERED_SERVICE'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_asset_trust_relationships_org', 'asset_trust_relationships', ['organization_id'])
    op.create_index('ix_asset_trust_relationships_source', 'asset_trust_relationships', ['source_asset_id'])
    op.create_index('ix_asset_trust_relationships_target', 'asset_trust_relationships', ['target_asset_id'])

    # 3. Create prevention_recommendations table
    op.create_table(
        'prevention_recommendations',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('attack_path_id', GUID(), sa.ForeignKey('attack_paths.id', ondelete='CASCADE'), nullable=True),
        sa.Column('target_asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('category', sa.String(50), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('risk_reduction', sa.String(20), nullable=False, server_default='HIGH'),
        sa.Column('implementation_complexity', sa.String(20), nullable=False, server_default='LOW'),
        sa.Column('smb_operational_impact', sa.String(20), nullable=False, server_default='MINIMAL'),
        sa.Column('priority_rank', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('mitre_technique_id', sa.String(50), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='PROPOSED'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_prevention_recommendations_org', 'prevention_recommendations', ['organization_id'])
    op.create_index('ix_prevention_recommendations_path', 'prevention_recommendations', ['attack_path_id'])
    op.create_index('ix_prevention_recommendations_asset', 'prevention_recommendations', ['target_asset_id'])
    op.create_index('ix_prevention_recommendations_rank', 'prevention_recommendations', ['priority_rank'])
    op.create_index('ix_prevention_recommendations_status', 'prevention_recommendations', ['status'])

    # 4. Create attack_path_analysis_jobs table
    op.create_table(
        'attack_path_analysis_jobs',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('initiated_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='PENDING'),
        sa.Column('paths_discovered_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('recommendations_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_attack_path_analysis_jobs_org', 'attack_path_analysis_jobs', ['organization_id'])
    op.create_index('ix_attack_path_analysis_jobs_status', 'attack_path_analysis_jobs', ['status'])


def downgrade() -> None:
    op.drop_table('attack_path_analysis_jobs')
    op.drop_table('prevention_recommendations')
    op.drop_table('asset_trust_relationships')

    op.drop_index('ix_attack_paths_status', 'attack_paths')
    op.drop_index('ix_attack_paths_confidence', 'attack_paths')
    op.drop_index('ix_attack_paths_severity', 'attack_paths')
    op.drop_column('attack_paths', 'status')
    op.drop_column('attack_paths', 'evidence_references')
    op.drop_column('attack_paths', 'prerequisites')
    op.drop_column('attack_paths', 'mitre_techniques')
    op.drop_column('attack_paths', 'mitre_tactics')
    op.drop_column('attack_paths', 'graph_data')
    op.drop_column('attack_paths', 'path_narrative')
    op.drop_column('attack_paths', 'description')
    op.drop_column('attack_paths', 'title')
    op.drop_column('attack_paths', 'confidence')
    op.drop_column('attack_paths', 'severity')
