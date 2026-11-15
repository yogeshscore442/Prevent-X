"""Automated Security Validation, WAF regression, rollback records, and canary policies

Revision ID: 010_security_validation
Revises: 009_virtual_patching
Create Date: 2026-11-14 23:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from backend.app.database.guid import GUID

revision: str = '010_security_validation'
down_revision: Union[str, None] = '009_virtual_patching'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create validation_jobs table
    op.create_table(
        'validation_jobs',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('deployment_id', GUID(), sa.ForeignKey('virtual_patch_deployments.id', ondelete='SET NULL'), nullable=True),
        sa.Column('environment', sa.String(30), nullable=False, server_default='STAGING'),
        sa.Column('target_url', sa.String(255), nullable=False, server_default='http://127.0.0.1:8085'),
        sa.Column('status', sa.String(30), nullable=False, server_default='PENDING'),
        sa.Column('trigger_type', sa.String(30), nullable=False, server_default='MANUAL'),
        sa.Column('canary_percentage', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_tests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('passed_tests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_tests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('blocked_attacks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('allowed_legitimate', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('false_positives_detected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('bypasses_detected', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('pass_rate_percentage', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('active_config_hash', sa.String(64), nullable=True),
        sa.Column('summary_report', sa.Text(), nullable=True),
        sa.Column('initiated_by_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_validation_jobs_org', 'validation_jobs', ['organization_id'])
    op.create_index('ix_validation_jobs_deployment', 'validation_jobs', ['deployment_id'])
    op.create_index('ix_validation_jobs_status', 'validation_jobs', ['status'])
    op.create_index('ix_validation_jobs_trigger', 'validation_jobs', ['trigger_type'])
    op.create_index('ix_validation_jobs_env', 'validation_jobs', ['environment'])

    # 2. Create validation_test_results table
    op.create_table(
        'validation_test_results',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('job_id', GUID(), sa.ForeignKey('validation_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('test_id', sa.String(100), nullable=False),
        sa.Column('test_category', sa.String(50), nullable=False, server_default='SQLI'),
        sa.Column('test_name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('target_endpoint', sa.String(500), nullable=False),
        sa.Column('http_method', sa.String(10), nullable=False, server_default='GET'),
        sa.Column('request_headers_redacted', sa.Text(), nullable=True),
        sa.Column('request_payload_redacted', sa.Text(), nullable=True),
        sa.Column('expected_status_code', sa.Integer(), nullable=False),
        sa.Column('actual_status_code', sa.Integer(), nullable=True),
        sa.Column('expected_decision', sa.String(20), nullable=False, server_default='BLOCKED'),
        sa.Column('actual_decision', sa.String(20), nullable=True),
        sa.Column('result', sa.String(20), nullable=False, server_default='PASSED'),
        sa.Column('latency_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('evidence_snippet', sa.Text(), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='95'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_validation_test_results_job', 'validation_test_results', ['job_id'])
    op.create_index('ix_validation_test_results_org', 'validation_test_results', ['organization_id'])
    op.create_index('ix_validation_test_results_cat', 'validation_test_results', ['test_category'])
    op.create_index('ix_validation_test_results_test_id', 'validation_test_results', ['test_id'])
    op.create_index('ix_validation_test_results_result', 'validation_test_results', ['result'])

    # 3. Create rollback_records table
    op.create_table(
        'rollback_records',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('deployment_id', GUID(), sa.ForeignKey('virtual_patch_deployments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('target_deployment_id', GUID(), sa.ForeignKey('virtual_patch_deployments.id', ondelete='SET NULL'), nullable=True),
        sa.Column('trigger_source', sa.String(50), nullable=False, server_default='MANUAL'),
        sa.Column('rollback_reason', sa.Text(), nullable=False),
        sa.Column('previous_config_hash', sa.String(64), nullable=False),
        sa.Column('restored_config_hash', sa.String(64), nullable=False),
        sa.Column('status', sa.String(30), nullable=False, server_default='INITIATED'),
        sa.Column('is_restoration_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('verification_evidence', sa.Text(), nullable=True),
        sa.Column('operator_user_id', GUID(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('error_details', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_rollback_records_org', 'rollback_records', ['organization_id'])
    op.create_index('ix_rollback_records_dep', 'rollback_records', ['deployment_id'])
    op.create_index('ix_rollback_records_status', 'rollback_records', ['status'])

    # 4. Create canary_policies table
    op.create_table(
        'canary_policies',
        sa.Column('id', GUID(), primary_key=True),
        sa.Column('organization_id', GUID(), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False, server_default='Default SMB Canary Safety Policy'),
        sa.Column('canary_traffic_weight', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('max_failure_rate_percent', sa.Float(), nullable=False, server_default='5.0'),
        sa.Column('max_latency_ms', sa.Float(), nullable=False, server_default='1000.0'),
        sa.Column('max_false_positive_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('auto_rollback_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('auto_promotion_enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_canary_policies_org', 'canary_policies', ['organization_id'])


def downgrade() -> None:
    op.drop_table('canary_policies')
    op.drop_table('rollback_records')
    op.drop_table('validation_test_results')
    op.drop_table('validation_jobs')

