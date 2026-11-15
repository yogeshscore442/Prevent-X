"""Intelligent Virtual Patching, WAF rule engine, Nginx deployment, and enforcement logs

Revision ID: 009_virtual_patching
Revises: 008_zero_trust_resilience
Create Date: 2026-11-14 23:05:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '009_virtual_patching'
down_revision: Union[str, None] = '008_zero_trust_resilience'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Drop placeholder table if exists
    op.execute("DROP TABLE IF EXISTS virtual_patch_rules CASCADE")

    # 1. Create virtual_patch_rules table
    op.create_table(
        'virtual_patch_rules',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='SET NULL'), nullable=True),
        sa.Column('vulnerability_id', GUID(), sa.ForeignKey('vulnerability_records.id', ondelete='SET NULL'), nullable=True),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('cwe_id', sa.String(50), nullable=True),
        sa.Column('rule_name', sa.String(255), nullable=False),
        sa.Column('attack_type', sa.String(50), nullable=False, server_default='SQLI'),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, server_default='HIGH'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('action', sa.String(20), nullable=False, server_default='BLOCK'),
        sa.Column('target_uri_pattern', sa.String(500), nullable=True),
        sa.Column('http_methods', sa.Text(), nullable=True),
        sa.Column('match_conditions', sa.Text(), nullable=True),
        sa.Column('status', sa.String(30), nullable=False, server_default='DRAFT'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_system_rule', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('false_positive_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('enforcement_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('config_snippet', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_virtual_patch_rules_org', 'virtual_patch_rules', ['organization_id'])
    op.create_index('ix_virtual_patch_rules_asset', 'virtual_patch_rules', ['asset_id'])
    op.create_index('ix_virtual_patch_rules_vuln', 'virtual_patch_rules', ['vulnerability_id'])
    op.create_index('ix_virtual_patch_rules_cve', 'virtual_patch_rules', ['cve_id'])
    op.create_index('ix_virtual_patch_rules_status', 'virtual_patch_rules', ['status'])
    op.create_index('ix_virtual_patch_rules_attack_type', 'virtual_patch_rules', ['attack_type'])
    op.create_index('ix_virtual_patch_rules_priority', 'virtual_patch_rules', ['priority'])
    op.create_index('ix_virtual_patch_rules_is_active', 'virtual_patch_rules', ['is_active'])

    # 2. Create virtual_patch_versions table
    op.create_table(
        'virtual_patch_versions',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('rule_id', GUID(), sa.ForeignKey('virtual_patch_rules.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version_number', sa.Integer(), nullable=False),
        sa.Column('rule_name', sa.String(255), nullable=False),
        sa.Column('action', sa.String(20), nullable=False),
        sa.Column('target_uri_pattern', sa.String(500), nullable=True),
        sa.Column('match_conditions', sa.Text(), nullable=True),
        sa.Column('config_snippet', sa.Text(), nullable=True),
        sa.Column('change_summary', sa.Text(), nullable=True),
        sa.Column('created_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_virtual_patch_versions_rule_id', 'virtual_patch_versions', ['rule_id'])
    op.create_index('ix_virtual_patch_versions_ver', 'virtual_patch_versions', ['version_number'])

    # 3. Create virtual_patch_deployments table
    op.create_table(
        'virtual_patch_deployments',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('environment', sa.String(30), nullable=False, server_default='STAGING'),
        sa.Column('status', sa.String(30), nullable=False, server_default='PENDING_APPROVAL'),
        sa.Column('deployed_rules_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('config_hash', sa.String(64), nullable=False),
        sa.Column('nginx_config_path', sa.String(500), nullable=True),
        sa.Column('listen_port', sa.Integer(), nullable=False, server_default='8085'),
        sa.Column('upstream_url', sa.String(255), nullable=False, server_default='http://127.0.0.1:8086'),
        sa.Column('approved_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rollback_target_deployment_id', GUID(), sa.ForeignKey('virtual_patch_deployments.id', ondelete='SET NULL'), nullable=True),
        sa.Column('deployment_log', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_virtual_patch_deployments_org', 'virtual_patch_deployments', ['organization_id'])
    op.create_index('ix_virtual_patch_deployments_status', 'virtual_patch_deployments', ['status'])
    op.create_index('ix_virtual_patch_deployments_env', 'virtual_patch_deployments', ['environment'])

    # 4. Create waf_enforcement_logs table
    op.create_table(
        'waf_enforcement_logs',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('rule_id', GUID(), sa.ForeignKey('virtual_patch_rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('client_ip', sa.String(45), nullable=False),
        sa.Column('http_method', sa.String(10), nullable=False),
        sa.Column('uri', sa.String(1000), nullable=False),
        sa.Column('query_string', sa.Text(), nullable=True),
        sa.Column('headers_snippet', sa.Text(), nullable=True),
        sa.Column('body_snippet', sa.Text(), nullable=True),
        sa.Column('decision', sa.String(20), nullable=False, server_default='BLOCKED'),
        sa.Column('matched_pattern', sa.Text(), nullable=True),
        sa.Column('block_reason', sa.Text(), nullable=False),
        sa.Column('response_status_code', sa.Integer(), nullable=False, server_default='403'),
        sa.Column('is_false_positive_reported', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('false_positive_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_waf_logs_org', 'waf_enforcement_logs', ['organization_id'])
    op.create_index('ix_waf_logs_rule_id', 'waf_enforcement_logs', ['rule_id'])
    op.create_index('ix_waf_logs_client_ip', 'waf_enforcement_logs', ['client_ip'])
    op.create_index('ix_waf_logs_uri', 'waf_enforcement_logs', ['uri'])
    op.create_index('ix_waf_logs_decision', 'waf_enforcement_logs', ['decision'])
    op.create_index('ix_waf_logs_fp', 'waf_enforcement_logs', ['is_false_positive_reported'])
    op.create_index('ix_waf_logs_created_at', 'waf_enforcement_logs', ['created_at'])

    # 5. Create virtual_patch_recommendations table
    op.create_table(
        'virtual_patch_recommendations',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('vulnerability_id', GUID(), sa.ForeignKey('vulnerability_records.id', ondelete='CASCADE'), nullable=False),
        sa.Column('asset_id', GUID(), sa.ForeignKey('managed_assets.id', ondelete='CASCADE'), nullable=False),
        sa.Column('cve_id', sa.String(50), nullable=True),
        sa.Column('cwe_id', sa.String(50), nullable=True),
        sa.Column('attack_type', sa.String(50), nullable=False),
        sa.Column('suggested_rule_name', sa.String(255), nullable=False),
        sa.Column('suggested_pattern', sa.Text(), nullable=False),
        sa.Column('target_uri_pattern', sa.String(500), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='85'),
        sa.Column('status', sa.String(30), nullable=False, server_default='PROPOSED'),
        sa.Column('generated_rule_id', GUID(), sa.ForeignKey('virtual_patch_rules.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_vp_recs_org', 'virtual_patch_recommendations', ['organization_id'])
    op.create_index('ix_vp_recs_vuln', 'virtual_patch_recommendations', ['vulnerability_id'])
    op.create_index('ix_vp_recs_asset', 'virtual_patch_recommendations', ['asset_id'])
    op.create_index('ix_vp_recs_status', 'virtual_patch_recommendations', ['status'])


def downgrade() -> None:
    op.drop_table('virtual_patch_recommendations')
    op.drop_table('waf_enforcement_logs')
    op.drop_table('virtual_patch_deployments')
    op.drop_table('virtual_patch_versions')
    op.drop_table('virtual_patch_rules')

