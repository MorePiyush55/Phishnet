"""
Alembic migration to create the complete PhishNet database schema
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'create_complete_schema'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    """Create complete PhishNet database schema"""
    
    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('disabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=True),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=False)
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    
    # Create emails table
    op.create_table('emails',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('gmail_msg_id', sa.String(length=255), nullable=False),
        sa.Column('thread_id', sa.String(length=255), nullable=True),
        sa.Column('from_addr', sa.String(length=255), nullable=False),
        sa.Column('to_addr', sa.String(length=255), nullable=False),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('raw_headers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('raw_text', sa.Text(), nullable=True),
        sa.Column('raw_html', sa.Text(), nullable=True),
        sa.Column('sanitized_html', sa.Text(), nullable=True),
        sa.Column('score', sa.Numeric(precision=5, scale=3), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_analyzed', sa.DateTime(timezone=True), nullable=True),
        sa.Column('analysis_version', sa.String(length=50), nullable=True),
        sa.Column('processing_time_ms', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('gmail_msg_id')
    )
    op.create_index(op.f('ix_emails_from_addr'), 'emails', ['from_addr'], unique=False)
    op.create_index(op.f('ix_emails_gmail_msg_id'), 'emails', ['gmail_msg_id'], unique=False)
    op.create_index(op.f('ix_emails_id'), 'emails', ['id'], unique=False)
    op.create_index(op.f('ix_emails_received_at'), 'emails', ['received_at'], unique=False)
    op.create_index(op.f('ix_emails_score'), 'emails', ['score'], unique=False)
    op.create_index(op.f('ix_emails_status'), 'emails', ['status'], unique=False)
    op.create_index(op.f('ix_emails_thread_id'), 'emails', ['thread_id'], unique=False)
    op.create_index(op.f('ix_emails_to_addr'), 'emails', ['to_addr'], unique=False)
    
    # Performance indexes for emails
    op.create_index('idx_emails_status_received', 'emails', ['status', 'received_at'])
    op.create_index('idx_emails_from_received', 'emails', ['from_addr', 'received_at'])
    op.create_index('idx_emails_score_status', 'emails', ['score', 'status'])
    
    # Create refresh_tokens table
    op.create_table('refresh_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False),
        sa.Column('exp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('last_used', sa.DateTime(timezone=True), nullable=True),
        sa.Column('client_info', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash')
    )
    op.create_index(op.f('ix_refresh_tokens_exp'), 'refresh_tokens', ['exp'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_id'), 'refresh_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_revoked'), 'refresh_tokens', ['revoked'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_token_hash'), 'refresh_tokens', ['token_hash'], unique=False)
    op.create_index(op.f('ix_refresh_tokens_user_id'), 'refresh_tokens', ['user_id'], unique=False)
    op.create_index('idx_refresh_tokens_user_exp', 'refresh_tokens', ['user_id', 'exp'])
    op.create_index('idx_refresh_tokens_revoked_exp', 'refresh_tokens', ['revoked', 'exp'])
    
    # Create links table
    op.create_table('links',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('original_url', sa.Text(), nullable=False),
        sa.Column('final_url', sa.Text(), nullable=True),
        sa.Column('chain', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('risk', sa.String(length=50), nullable=False),
        sa.Column('reasons', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('analyzed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('redirect_count', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_links_email_id'), 'links', ['email_id'], unique=False)
    op.create_index(op.f('ix_links_id'), 'links', ['id'], unique=False)
    op.create_index(op.f('ix_links_risk'), 'links', ['risk'], unique=False)
    op.create_index('idx_links_email_risk', 'links', ['email_id', 'risk'])
    op.create_index('idx_links_analyzed_risk', 'links', ['analyzed_at', 'risk'])
    
    # Create email_ai_results table
    op.create_table('email_ai_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('model', sa.String(length=100), nullable=False),
        sa.Column('score', sa.Numeric(precision=5, scale=3), nullable=False),
        sa.Column('labels', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('prompt_version', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('processing_time_ms', sa.Integer(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('api_cost', sa.Numeric(precision=10, scale=6), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_ai_results_email_id'), 'email_ai_results', ['email_id'], unique=False)
    op.create_index(op.f('ix_email_ai_results_id'), 'email_ai_results', ['id'], unique=False)
    op.create_index(op.f('ix_email_ai_results_model'), 'email_ai_results', ['model'], unique=False)
    op.create_index(op.f('ix_email_ai_results_score'), 'email_ai_results', ['score'], unique=False)
    op.create_index('idx_ai_results_email_model', 'email_ai_results', ['email_id', 'model'])
    op.create_index('idx_ai_results_score_created', 'email_ai_results', ['score', 'created_at'])
    
    # Create email_indicators table
    op.create_table('email_indicators',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('indicator', sa.String(length=255), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('reputation', sa.String(length=50), nullable=False),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_updated', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_email_indicators_email_id'), 'email_indicators', ['email_id'], unique=False)
    op.create_index(op.f('ix_email_indicators_id'), 'email_indicators', ['id'], unique=False)
    op.create_index(op.f('ix_email_indicators_indicator'), 'email_indicators', ['indicator'], unique=False)
    op.create_index(op.f('ix_email_indicators_reputation'), 'email_indicators', ['reputation'], unique=False)
    op.create_index(op.f('ix_email_indicators_source'), 'email_indicators', ['source'], unique=False)
    op.create_index(op.f('ix_email_indicators_type'), 'email_indicators', ['type'], unique=False)
    op.create_index('idx_indicators_indicator_type', 'email_indicators', ['indicator', 'type'])
    op.create_index('idx_indicators_reputation_created', 'email_indicators', ['reputation', 'created_at'])
    op.create_index('idx_indicators_source_type', 'email_indicators', ['source', 'type'])
    
    # Create actions table
    op.create_table('actions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email_id', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('result', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['email_id'], ['emails.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_actions_created_by'), 'actions', ['created_by'], unique=False)
    op.create_index(op.f('ix_actions_email_id'), 'actions', ['email_id'], unique=False)
    op.create_index(op.f('ix_actions_id'), 'actions', ['id'], unique=False)
    op.create_index(op.f('ix_actions_type'), 'actions', ['type'], unique=False)
    op.create_index('idx_actions_email_type', 'actions', ['email_id', 'type'])
    op.create_index('idx_actions_created_by_type', 'actions', ['created_by', 'type'])
    op.create_index('idx_actions_created_success', 'actions', ['created_at', 'success'])
    
    # Create audits table
    op.create_table('audits',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('actor_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource', sa.String(length=100), nullable=True),
        sa.Column('details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('request_id', sa.String(length=36), nullable=True),
        sa.Column('ts', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('endpoint', sa.String(length=255), nullable=True),
        sa.Column('method', sa.String(length=10), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audits_action'), 'audits', ['action'], unique=False)
    op.create_index(op.f('ix_audits_actor_id'), 'audits', ['actor_id'], unique=False)
    op.create_index(op.f('ix_audits_id'), 'audits', ['id'], unique=False)
    op.create_index(op.f('ix_audits_request_id'), 'audits', ['request_id'], unique=False)
    op.create_index(op.f('ix_audits_resource'), 'audits', ['resource'], unique=False)
    op.create_index(op.f('ix_audits_ts'), 'audits', ['ts'], unique=False)
    op.create_index('idx_audits_action_ts', 'audits', ['action', 'ts'])
    op.create_index('idx_audits_actor_action', 'audits', ['actor_id', 'action'])
    op.create_index('idx_audits_resource_ts', 'audits', ['resource', 'ts'])
    op.create_index('idx_audits_request_id', 'audits', ['request_id'])

def downgrade():
    """Drop all tables"""
    op.drop_table('audits')
    op.drop_table('actions')
    op.drop_table('email_indicators')
    op.drop_table('email_ai_results')
    op.drop_table('links')
    op.drop_table('refresh_tokens')
    op.drop_table('emails')
    op.drop_table('users')
