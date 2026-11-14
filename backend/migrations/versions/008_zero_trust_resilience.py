"""Zero trust assessments, threat intelligence, anomalies, response actions

Revision ID: 008_zero_trust_resilience
Revises: 007_enhance_attack_path_engine
Create Date: 2026-11-14 21:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '008_zero_trust_resilience'
down_revision: Union[str, None] = '007_enhance_attack_path_engine'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Enhance threat_intel_records
    op.add_column('threat_intel_records', sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True))
    op.add_column('threat_intel_records', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('threat_intel_records', sa.Column('severity', sa.String(20), nullable=False, server_default='HIGH'))
    op.add_column('threat_intel_records', sa.Column('tlp', sa.String(20), nullable=False, server_default='WHITE'))
    op.add_column('threat_intel_records', sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'))
    op.add_column('threat_intel_records', sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('threat_intel_records', sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('threat_intel_records', sa.Column('mitre_tactics', sa.Text(), nullable=True))
    op.add_column('threat_intel_records', sa.Column('mitre_techniques', sa.Text(), nullable=True))
    op.add_column('threat_intel_records', sa.Column('tags', sa.Text(), nullable=True))

    op.create_index('ix_threat_intel_records_org', 'threat_intel_records', ['organization_id'])
    op.create_index('ix_threat_intel_records_is_active', 'threat_intel_records', ['is_active'])
    op.create_index('ix_threat_intel_records_expires_at', 'threat_intel_records', ['expires_at'])
    op.create_index('ix_threat_intel_records_type', 'threat_intel_records', ['indicator_type'])

    # 2. Create asset_trust_assessments table
    op.create_table(
        'asset_trust_assessments',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('trust_decision', sa.String(30), nullable=False, server_default='INSUFFICIENT_EVIDENCE'),
        sa.Column('trust_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('positive_factors', sa.Text(), nullable=True),
        sa.Column('risk_factors', sa.Text(), nullable=True),
        sa.Column('least_privilege_recommendations', sa.Text(), nullable=True),
        sa.Column('decision_reason', sa.Text(), nullable=False),
        sa.Column('last_evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_stale', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_asset_trust_assessments_org', 'asset_trust_assessments', ['organization_id'])
    op.create_index('ix_asset_trust_assessments_asset', 'asset_trust_assessments', ['asset_id'])
    op.create_index('ix_asset_trust_assessments_decision', 'asset_trust_assessments', ['trust_decision'])
    op.create_index('ix_asset_trust_assessments_score', 'asset_trust_assessments', ['trust_score'])

    # 3. Create threat_asset_correlations table
    op.create_table(
        'threat_asset_correlations',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('threat_intel_id', GUID(), sa.ForeignKey('threat_intel_records.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('correlation_type', sa.String(50), nullable=False),
        sa.Column('matched_value', sa.String(255), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, server_default='HIGH'),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='80'),
        sa.Column('details', sa.Text(), nullable=False),
        sa.Column('status', sa.String(30), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_threat_asset_correlations_org', 'threat_asset_correlations', ['organization_id'])
    op.create_index('ix_threat_asset_correlations_intel', 'threat_asset_correlations', ['threat_intel_id'])
    op.create_index('ix_threat_asset_correlations_asset', 'threat_asset_correlations', ['asset_id'])
    op.create_index('ix_threat_asset_correlations_status', 'threat_asset_correlations', ['status'])

    # 4. Create behavioral_anomalies table
    op.create_table(
        'behavioral_anomalies',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('anomaly_type', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, server_default='MEDIUM'),
        sa.Column('confidence', sa.String(30), nullable=False, server_default='POTENTIAL'),
        sa.Column('anomaly_score', sa.Float(), nullable=False, server_default='50.0'),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence_data', sa.Text(), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='OPEN'),
        sa.Column('is_zero_day_indicator', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_behavioral_anomalies_org', 'behavioral_anomalies', ['organization_id'])
    op.create_index('ix_behavioral_anomalies_asset', 'behavioral_anomalies', ['asset_id'])
    op.create_index('ix_behavioral_anomalies_type', 'behavioral_anomalies', ['anomaly_type'])
    op.create_index('ix_behavioral_anomalies_severity', 'behavioral_anomalies', ['severity'])
    op.create_index('ix_behavioral_anomalies_status', 'behavioral_anomalies', ['status'])
    op.create_index('ix_behavioral_anomalies_zero_day', 'behavioral_anomalies', ['is_zero_day_indicator'])

    # 5. Create response_actions table
    op.create_table(
        'response_actions',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('anomaly_id', GUID(), sa.ForeignKey('behavioral_anomalies.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_type', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('target_entity', sa.String(255), nullable=False),
        sa.Column('execution_payload', sa.Text(), nullable=True),
        sa.Column('rollback_payload', sa.Text(), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='PENDING_APPROVAL'),
        sa.Column('is_disruptive', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('approved_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('execution_log', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_response_actions_org', 'response_actions', ['organization_id'])
    op.create_index('ix_response_actions_asset', 'response_actions', ['asset_id'])
    op.create_index('ix_response_actions_anomaly', 'response_actions', ['anomaly_id'])
    op.create_index('ix_response_actions_status', 'response_actions', ['status'])


def downgrade() -> None:
    op.drop_table('response_actions')
    op.drop_table('behavioral_anomalies')
    op.drop_table('threat_asset_correlations')
    op.drop_table('asset_trust_assessments')

    op.drop_index('ix_threat_intel_records_type', 'threat_intel_records')
    op.drop_index('ix_threat_intel_records_expires_at', 'threat_intel_records')
    op.drop_index('ix_threat_intel_records_is_active', 'threat_intel_records')
    op.drop_index('ix_threat_intel_records_org', 'threat_intel_records')
    op.drop_column('threat_intel_records', 'tags')
    op.drop_column('threat_intel_records', 'mitre_techniques')
    op.drop_column('threat_intel_records', 'mitre_tactics')
    op.drop_column('threat_intel_records', 'last_seen_at')
    op.drop_column('threat_intel_records', 'expires_at')
    op.drop_column('threat_intel_records', 'is_active')
    op.drop_column('threat_intel_records', 'tlp')
    op.drop_column('threat_intel_records', 'severity')
    op.drop_column('threat_intel_records', 'description')
    op.drop_column('threat_intel_records', 'organization_id')

