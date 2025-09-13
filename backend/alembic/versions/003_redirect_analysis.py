"""Redirect analysis database migration

Revision ID: 003_redirect_analysis
Revises: 002_enhanced_threat_model
Create Date: 2025-09-11 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '003_redirect_analysis'
down_revision = '002_enhanced_threat_model'  # Previous migration
branch_labels = None
depends_on = None


def upgrade():
    """Create redirect analysis tables"""
    
    # Create redirect_analyses table
    op.create_table(
        'redirect_analyses',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('original_url', sa.String(2048), nullable=False),
        sa.Column('final_destination', sa.String(2048)),
        sa.Column('analysis_timestamp', sa.DateTime, nullable=False),
        sa.Column('total_execution_time_ms', sa.Integer),
        sa.Column('total_hops', sa.Integer, default=0),
        sa.Column('max_hops_reached', sa.Boolean, default=False),
        sa.Column('tls_chain_valid', sa.Boolean, default=True),
        sa.Column('mixed_content_detected', sa.Boolean, default=False),
        sa.Column('chain_reputation_score', sa.Float, default=0.0),
        sa.Column('threat_level', sa.String(20), default='low'),
        sa.Column('cloaking_detected', sa.Boolean, default=False),
        sa.Column('partial_analysis', sa.Boolean, default=False),
        sa.Column('insecure_hops', sa.JSON),
        sa.Column('malicious_hops', sa.JSON),
        sa.Column('risk_factors', sa.JSON),
        sa.Column('recommendations', sa.JSON),
        sa.Column('analysis_errors', sa.JSON),
        sa.Column('screenshot_urls', sa.JSON),
        sa.Column('log_file_paths', sa.JSON),
        sa.Column('threat_result_id', sa.String(36)),
    )
    
    # Create redirect_hops table
    op.create_table(
        'redirect_hops',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('analysis_id', sa.String(36), nullable=False),
        sa.Column('hop_number', sa.Integer, nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('method', sa.String(10), default='GET'),
        sa.Column('status_code', sa.Integer),
        sa.Column('redirect_type', sa.String(50)),
        sa.Column('location_header', sa.String(2048)),
        sa.Column('response_time_ms', sa.Integer),
        sa.Column('content_length', sa.Integer),
        sa.Column('content_type', sa.String(100)),
        sa.Column('server_header', sa.String(200)),
        sa.Column('resolved_hostname', sa.String(255)),
        sa.Column('resolved_ip', sa.String(45)),
        sa.Column('vt_score', sa.Float),
        sa.Column('abuse_score', sa.Float),
        sa.Column('domain_reputation', sa.Float),
        sa.Column('response_headers', sa.JSON),
        sa.Column('dom_changes', sa.JSON),
        sa.Column('javascript_redirects', sa.JSON),
        sa.Column('loaded_resources', sa.JSON),
        sa.Column('error', sa.Text),
        sa.Column('timestamp', sa.DateTime, nullable=False),
        sa.Column('tls_info', sa.JSON),
        sa.ForeignKeyConstraint(['analysis_id'], ['redirect_analyses.id'], ondelete='CASCADE'),
    )
    
    # Create browser_analysis_records table
    op.create_table(
        'browser_analysis_records',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('analysis_id', sa.String(36), nullable=False),
        sa.Column('user_agent_used', sa.String(500), nullable=False),
        sa.Column('browser_type', sa.String(50)),
        sa.Column('final_url', sa.String(2048)),
        sa.Column('page_title', sa.String(500)),
        sa.Column('dom_content_hash', sa.String(64)),
        sa.Column('screenshot_path', sa.String(500)),
        sa.Column('execution_time_ms', sa.Integer),
        sa.Column('console_logs', sa.JSON),
        sa.Column('network_requests', sa.JSON),
        sa.Column('javascript_errors', sa.JSON),
        sa.Column('loaded_scripts', sa.JSON),
        sa.Column('forms_detected', sa.JSON),
        sa.Column('credential_forms_detected', sa.Boolean, default=False),
        sa.Column('suspicious_scripts_count', sa.Integer, default=0),
        sa.Column('external_resources_count', sa.Integer, default=0),
        sa.Column('error', sa.Text),
        sa.Column('timestamp', sa.DateTime, nullable=False),
        sa.ForeignKeyConstraint(['analysis_id'], ['redirect_analyses.id'], ondelete='CASCADE'),
    )
    
    # Create cloaking_analysis_records table
    op.create_table(
        'cloaking_analysis_records',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('analysis_id', sa.String(36), nullable=False),
        sa.Column('is_cloaking_detected', sa.Boolean, default=False),
        sa.Column('confidence', sa.Float, default=0.0),
        sa.Column('user_agent_response_size', sa.Integer),
        sa.Column('bot_response_size', sa.Integer),
        sa.Column('content_similarity', sa.Float),
        sa.Column('final_url_user', sa.String(2048)),
        sa.Column('final_url_bot', sa.String(2048)),
        sa.Column('redirect_count_user', sa.Integer),
        sa.Column('redirect_count_bot', sa.Integer),
        sa.Column('methods_used', sa.JSON),
        sa.Column('cloaking_indicators', sa.JSON),
        sa.Column('suspicious_patterns', sa.JSON),
        sa.Column('title_differences', sa.JSON),
        sa.Column('dom_differences', sa.JSON),
        sa.Column('script_differences', sa.JSON),
        sa.Column('link_differences', sa.JSON),
        sa.Column('timestamp', sa.DateTime, nullable=False),
        sa.ForeignKeyConstraint(['analysis_id'], ['redirect_analyses.id'], ondelete='CASCADE'),
    )
    
    # Create tls_certificates table
    op.create_table(
        'tls_certificates',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('hop_id', sa.String(36), nullable=False),
        sa.Column('subject', sa.String(500)),
        sa.Column('issuer', sa.String(500)),
        sa.Column('not_before', sa.DateTime),
        sa.Column('not_after', sa.DateTime),
        sa.Column('serial_number', sa.String(100)),
        sa.Column('fingerprint_sha256', sa.String(95)),
        sa.Column('validation_status', sa.String(50)),
        sa.Column('hostname_validated', sa.Boolean, default=False),
        sa.Column('chain_trusted', sa.Boolean, default=False),
        sa.Column('san_domains', sa.JSON),
        sa.Column('validation_errors', sa.JSON),
        sa.Column('analyzed_at', sa.DateTime, nullable=False),
        sa.ForeignKeyConstraint(['hop_id'], ['redirect_hops.id'], ondelete='CASCADE'),
    )
    
    # Create indexes
    op.create_index('idx_redirect_analysis_url', 'redirect_analyses', ['original_url'])
    op.create_index('idx_redirect_analysis_timestamp', 'redirect_analyses', ['analysis_timestamp'])
    op.create_index('idx_redirect_analysis_threat_result', 'redirect_analyses', ['threat_result_id'])
    op.create_index('idx_redirect_analysis_url_timestamp', 'redirect_analyses', ['original_url', 'analysis_timestamp'])
    
    op.create_index('idx_redirect_hop_analysis', 'redirect_hops', ['analysis_id'])
    op.create_index('idx_redirect_hop_analysis_hop', 'redirect_hops', ['analysis_id', 'hop_number'])
    op.create_index('idx_hop_vt_score', 'redirect_hops', ['vt_score'])
    op.create_index('idx_hop_abuse_score', 'redirect_hops', ['abuse_score'])
    
    op.create_index('idx_browser_analysis_record', 'browser_analysis_records', ['analysis_id'])
    op.create_index('idx_browser_analysis_agent', 'browser_analysis_records', ['analysis_id', 'user_agent_used'])
    
    op.create_index('idx_cloaking_analysis', 'cloaking_analysis_records', ['analysis_id'])
    op.create_index('idx_cloaking_confidence', 'cloaking_analysis_records', ['confidence'])
    
    op.create_index('idx_analysis_reputation', 'redirect_analyses', ['chain_reputation_score'])
    op.create_index('idx_analysis_threat_level', 'redirect_analyses', ['threat_level'])
    op.create_index('idx_analysis_cloaking', 'redirect_analyses', ['cloaking_detected'])
    
    op.create_index('idx_tls_cert_hop', 'tls_certificates', ['hop_id'])


def downgrade():
    """Drop redirect analysis tables"""
    
    # Drop indexes first
    op.drop_index('idx_tls_cert_hop', 'tls_certificates')
    op.drop_index('idx_analysis_cloaking', 'redirect_analyses')
    op.drop_index('idx_analysis_threat_level', 'redirect_analyses')
    op.drop_index('idx_analysis_reputation', 'redirect_analyses')
    op.drop_index('idx_cloaking_confidence', 'cloaking_analysis_records')
    op.drop_index('idx_cloaking_analysis', 'cloaking_analysis_records')
    op.drop_index('idx_browser_analysis_agent', 'browser_analysis_records')
    op.drop_index('idx_browser_analysis_record', 'browser_analysis_records')
    op.drop_index('idx_hop_abuse_score', 'redirect_hops')
    op.drop_index('idx_hop_vt_score', 'redirect_hops')
    op.drop_index('idx_redirect_hop_analysis_hop', 'redirect_hops')
    op.drop_index('idx_redirect_hop_analysis', 'redirect_hops')
    op.drop_index('idx_redirect_analysis_url_timestamp', 'redirect_analyses')
    op.drop_index('idx_redirect_analysis_threat_result', 'redirect_analyses')
    op.drop_index('idx_redirect_analysis_timestamp', 'redirect_analyses')
    op.drop_index('idx_redirect_analysis_url', 'redirect_analyses')
    
    # Drop tables in reverse order (due to foreign keys)
    op.drop_table('tls_certificates')
    op.drop_table('cloaking_analysis_records')
    op.drop_table('browser_analysis_records')
    op.drop_table('redirect_hops')
    op.drop_table('redirect_analyses')
