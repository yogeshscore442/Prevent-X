"""Real-Time Monitoring, Security Events, Incidents, Alerts, and Retention Policies

Revision ID: 011_monitoring_security_center
Revises: 010_security_validation
Create Date: 2026-11-15 14:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '011_monitoring_security_center'
down_revision: Union[str, None] = '010_security_validation'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create security_incidents table
    op.create_table(
        'security_incidents',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('incident_number', sa.String(32), nullable=False),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(32), nullable=False, server_default='MEDIUM'),
        sa.Column('status', sa.String(32), nullable=False, server_default='OPEN'),
        sa.Column('source', sa.String(64), nullable=False, server_default='CORRELATION_ENGINE'),
        sa.Column('primary_asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('mitre_attack_id', sa.String(32), nullable=True),
        sa.Column('mitre_technique', sa.String(255), nullable=True),
        sa.Column('recommended_action', sa.Text(), nullable=True),
        sa.Column('containment_action_taken', sa.Text(), nullable=True),
        sa.Column('containment_requires_approval', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('containment_approved_by', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('containment_executed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('assigned_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('iocs', sa.JSON(), nullable=True),
        sa.Column('related_event_ids', sa.JSON(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_security_incidents_number', 'security_incidents', ['incident_number'])
    op.create_index('ix_security_incidents_org', 'security_incidents', ['organization_id'])
    op.create_index('ix_security_incidents_asset', 'security_incidents', ['primary_asset_id'])
    op.create_index('ix_security_incidents_assigned', 'security_incidents', ['assigned_user_id'])
    op.create_index('ix_sec_incidents_org_status', 'security_incidents', ['organization_id', 'status'])
    op.create_index('ix_sec_incidents_org_severity', 'security_incidents', ['organization_id', 'severity'])

    # 2. Create security_events table
    op.create_table(
        'security_events',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('incident_id', GUID(), sa.ForeignKey('security_incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('source', sa.String(32), nullable=False, server_default='SYSTEM'),
        sa.Column('category', sa.String(32), nullable=False, server_default='SECURITY'),
        sa.Column('severity', sa.String(32), nullable=False, server_default='INFO'),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('source_ip', sa.String(64), nullable=True),
        sa.Column('target_uri', sa.String(1024), nullable=True),
        sa.Column('http_method', sa.String(16), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('fingerprint', sa.String(64), nullable=False),
        sa.Column('raw_payload', sa.Text(), nullable=True),
        sa.Column('event_metadata', sa.JSON(), nullable=True),
        sa.Column('is_correlated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_security_events_org', 'security_events', ['organization_id'])
    op.create_index('ix_security_events_asset', 'security_events', ['asset_id'])
    op.create_index('ix_security_events_incident', 'security_events', ['incident_id'])
    op.create_index('ix_security_events_source_ip', 'security_events', ['source_ip'])
    op.create_index('ix_security_events_fingerprint', 'security_events', ['fingerprint'])
    op.create_index('ix_sec_events_org_time', 'security_events', ['organization_id', 'timestamp'])
    op.create_index('ix_sec_events_org_severity', 'security_events', ['organization_id', 'severity'])

    # 3. Create incident_timeline_entries table
    op.create_table(
        'incident_timeline_entries',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('incident_id', GUID(), sa.ForeignKey('security_incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('entry_type', sa.String(64), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('evidence_data', sa.JSON(), nullable=True),
        sa.Column('actor_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_timeline_entries_incident', 'incident_timeline_entries', ['incident_id'])
    op.create_index('ix_timeline_entries_org', 'incident_timeline_entries', ['organization_id'])

    # 4. Create security_alerts table
    op.create_table(
        'security_alerts',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('category', sa.String(64), nullable=False),
        sa.Column('severity', sa.String(32), nullable=False, server_default='MEDIUM'),
        sa.Column('is_acknowledged', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('acknowledged_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('related_incident_id', GUID(), sa.ForeignKey('security_incidents.id', ondelete='SET NULL'), nullable=True),
        sa.Column('related_event_id', GUID(), sa.ForeignKey('security_events.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_security_alerts_org', 'security_alerts', ['organization_id'])
    op.create_index('ix_security_alerts_category', 'security_alerts', ['category'])
    op.create_index('ix_security_alerts_is_ack', 'security_alerts', ['is_acknowledged'])

    # 5. Create event_retention_policies table
    op.create_table(
        'event_retention_policies',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), unique=True, nullable=False),
        sa.Column('retention_days', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('max_stored_events', sa.Integer(), nullable=False, server_default='100000'),
        sa.Column('auto_prune_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_pruned_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_retention_policies_org', 'event_retention_policies', ['organization_id'])


def downgrade() -> None:
    op.drop_table('event_retention_policies')
    op.drop_table('security_alerts')
    op.drop_table('incident_timeline_entries')
    op.drop_table('security_events')
    op.drop_table('security_incidents')
