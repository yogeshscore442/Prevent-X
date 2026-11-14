"""Add active_scan_jobs and discovered_services for controlled active discovery

Revision ID: 005_add_active_discovery
Revises: 004_add_scope_validation_result
Create Date: 2026-11-14 18:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '005_add_active_discovery'
down_revision: Union[str, None] = '004_add_scope_validation_result'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Active Scan Jobs Table
    op.create_table(
        'active_scan_jobs',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('target_ip', sa.String(45), nullable=True),
        sa.Column('scan_profile', sa.String(20), nullable=False, server_default='BASIC'),
        sa.Column('selected_ports', sa.Text(), nullable=False),
        sa.Column('max_concurrency', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('timeout_seconds', sa.Float(), nullable=False, server_default='2.0'),
        sa.Column('status', sa.String(50), nullable=False, server_default='PENDING'),
        sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_stage', sa.String(100), nullable=False, server_default='QUEUED'),
        sa.Column('authorized_scope', sa.String(255), nullable=False),
        sa.Column('initiated_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
        sa.Column('authorization_confirmed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('authorized_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('scope_validation_result', sa.Text(), nullable=True),
        sa.Column('services_discovered_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('ports_scanned_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('discovery_policy', sa.String(50), nullable=False, server_default='CONTROLLED_ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_active_scan_jobs_org', 'active_scan_jobs', ['organization_id'])
    op.create_index('ix_active_scan_jobs_asset', 'active_scan_jobs', ['asset_id'])
    op.create_index('ix_active_scan_jobs_target', 'active_scan_jobs', ['target'])
    op.create_index('ix_active_scan_jobs_status', 'active_scan_jobs', ['status'])

    # 2. Discovered Services Table
    op.create_table(
        'discovered_services',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('job_id', GUID(), sa.ForeignKey('active_scan_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('target_ip', sa.String(45), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(10), nullable=False, server_default='tcp'),
        sa.Column('service_name', sa.String(50), nullable=False, server_default='unknown'),
        sa.Column('state', sa.String(20), nullable=False, server_default='OPEN'),
        sa.Column('confidence', sa.String(30), nullable=False, server_default='CONFIRMED_OBSERVATION'),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('tls_metadata', sa.Text(), nullable=True),
        sa.Column('http_metadata', sa.Text(), nullable=True),
        sa.Column('raw_evidence', sa.Text(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_discovered_services_org', 'discovered_services', ['organization_id'])
    op.create_index('ix_discovered_services_asset', 'discovered_services', ['asset_id'])
    op.create_index('ix_discovered_services_job', 'discovered_services', ['job_id'])
    op.create_index('ix_discovered_services_target', 'discovered_services', ['target'])
    op.create_index('ix_discovered_services_ip', 'discovered_services', ['target_ip'])
    op.create_index('ix_discovered_services_port', 'discovered_services', ['port'])
    op.create_index('ix_discovered_services_service', 'discovered_services', ['service_name'])


def downgrade() -> None:
    op.drop_table('discovered_services')
    op.drop_table('active_scan_jobs')

