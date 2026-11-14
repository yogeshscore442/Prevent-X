"""Attack Surface Intelligence schema

Revision ID: 002_attack_surface_schema
Revises: 001_initial_schema
Create Date: 2026-11-14 16:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '002_attack_surface_schema'
down_revision: Union[str, None] = '001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Discovery Jobs
    op.create_table(
        'discovery_jobs',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_domain', sa.String(255), nullable=False),
        sa.Column('status', sa.String(50), nullable=False),
        sa.Column('progress_percent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_stage', sa.String(100), nullable=False, server_default='VALIDATION'),
        sa.Column('authorized_scope', sa.String(255), nullable=False),
        sa.Column('initiated_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('authorization_confirmed', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('authorized_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('stage_errors', sa.Text(), nullable=True),
        sa.Column('domains_discovered_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('initial_exposure_score', sa.Float(), nullable=True),
        sa.Column('risk_score_details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_discovery_jobs_org', 'discovery_jobs', ['organization_id'])
    op.create_index('ix_discovery_jobs_asset', 'discovery_jobs', ['asset_id'])
    op.create_index('ix_discovery_jobs_domain', 'discovery_jobs', ['target_domain'])
    op.create_index('ix_discovery_jobs_status', 'discovery_jobs', ['status'])

    # 2. Discovered Domains
    op.create_table(
        'discovered_domains',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('job_id', GUID(), sa.ForeignKey('discovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain_name', sa.String(255), nullable=False),
        sa.Column('parent_domain', sa.String(255), nullable=True),
        sa.Column('is_subdomain', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('discovery_source', sa.String(50), nullable=False, server_default='CERTIFICATE_TRANSPARENCY'),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('organization_id', 'domain_name', name='uq_org_discovered_domain'),
    )
    op.create_index('ix_discovered_domains_org', 'discovered_domains', ['organization_id'])
    op.create_index('ix_discovered_domains_asset', 'discovered_domains', ['asset_id'])
    op.create_index('ix_discovered_domains_job', 'discovered_domains', ['job_id'])
    op.create_index('ix_discovered_domains_name', 'discovered_domains', ['domain_name'])
    op.create_index('ix_discovered_domains_parent', 'discovered_domains', ['parent_domain'])

    # 3. DNS Records
    op.create_table(
        'dns_records',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain_id', GUID(), sa.ForeignKey('discovered_domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain_name', sa.String(255), nullable=False),
        sa.Column('record_type', sa.String(10), nullable=False),
        sa.Column('record_value', sa.Text(), nullable=False),
        sa.Column('ttl', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(50), nullable=False, server_default='DNS_RESOLVER'),
        sa.Column('resolution_status', sa.String(50), nullable=False, server_default='RESOLVED'),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_dns_records_org', 'dns_records', ['organization_id'])
    op.create_index('ix_dns_records_domain_id', 'dns_records', ['domain_id'])
    op.create_index('ix_dns_records_domain_name', 'dns_records', ['domain_name'])
    op.create_index('ix_dns_records_type', 'dns_records', ['record_type'])

    # 4. Certificate Evidence
    op.create_table(
        'certificate_evidence',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain_id', GUID(), sa.ForeignKey('discovered_domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('issuer_name', sa.Text(), nullable=True),
        sa.Column('common_name', sa.String(255), nullable=True),
        sa.Column('subject_alt_names', sa.Text(), nullable=True),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=True),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_expired', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_wildcard', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('serial_number', sa.String(128), nullable=True),
        sa.Column('logged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('source', sa.String(50), nullable=False, server_default='CRT_SH'),
        sa.Column('raw_evidence', sa.Text(), nullable=True),
    )
    op.create_index('ix_cert_evidence_org', 'certificate_evidence', ['organization_id'])
    op.create_index('ix_cert_evidence_domain_id', 'certificate_evidence', ['domain_id'])

    # 5. RDAP Records
    op.create_table(
        'rdap_records',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain_id', GUID(), sa.ForeignKey('discovered_domains.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('handle', sa.String(255), nullable=True),
        sa.Column('registrar_name', sa.String(255), nullable=True),
        sa.Column('whois_server', sa.String(255), nullable=True),
        sa.Column('registration_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expiration_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_updated_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('nameservers', sa.Text(), nullable=True),
        sa.Column('status_codes', sa.Text(), nullable=True),
        sa.Column('asn', sa.String(50), nullable=True),
        sa.Column('raw_data', sa.Text(), nullable=True),
    )
    op.create_index('ix_rdap_records_org', 'rdap_records', ['organization_id'])
    op.create_index('ix_rdap_records_domain_id', 'rdap_records', ['domain_id'])

    # 6. Exposure Findings
    op.create_table(
        'exposure_findings',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('job_id', GUID(), sa.ForeignKey('discovery_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('finding_category', sa.String(50), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('confidence', sa.String(20), nullable=False, server_default='HIGH'),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=False),
        sa.Column('discovery_source', sa.String(50), nullable=False, server_default='PASSIVE_RECON'),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('current_status', sa.String(50), nullable=False, server_default='ACTIVE'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_exposure_findings_org', 'exposure_findings', ['organization_id'])
    op.create_index('ix_exposure_findings_asset', 'exposure_findings', ['asset_id'])
    op.create_index('ix_exposure_findings_job', 'exposure_findings', ['job_id'])
    op.create_index('ix_exposure_findings_target', 'exposure_findings', ['target'])
    op.create_index('ix_exposure_findings_category', 'exposure_findings', ['finding_category'])
    op.create_index('ix_exposure_findings_severity', 'exposure_findings', ['severity'])
    op.create_index('ix_exposure_findings_status', 'exposure_findings', ['current_status'])


def downgrade() -> None:
    op.drop_table('exposure_findings')
    op.drop_table('rdap_records')
    op.drop_table('certificate_evidence')
    op.drop_table('dns_records')
    op.drop_table('discovered_domains')
    op.drop_table('discovery_jobs')

