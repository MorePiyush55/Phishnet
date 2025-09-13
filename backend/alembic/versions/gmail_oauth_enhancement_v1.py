"""Add Gmail OAuth enhancement fields

Revision ID: gmail_oauth_enhancement_v1
Revises: previous_revision
Create Date: 2025-09-13 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = 'gmail_oauth_enhancement_v1'
down_revision = None  # Update this with the actual last migration
branch_labels = None
depends_on = None


def upgrade():
    """Upgrade database schema for Gmail OAuth enhancements."""
    
    # Add new columns to users table
    op.add_column('users', sa.Column('gmail_connected', sa.Boolean(), default=False))
    op.add_column('users', sa.Column('gmail_email', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('gmail_scopes_granted', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('gmail_connection_date', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('gmail_last_token_refresh', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('gmail_consent_version', sa.String(50), nullable=True))
    op.add_column('users', sa.Column('gmail_status', sa.String(50), default='disconnected'))
    
    # Enhance oauth_tokens table
    op.add_column('oauth_tokens', sa.Column('encrypted_access_token', sa.Text(), nullable=True))
    op.add_column('oauth_tokens', sa.Column('last_used_at', sa.DateTime(), nullable=True))
    op.add_column('oauth_tokens', sa.Column('creation_ip', sa.String(45), nullable=True))
    op.add_column('oauth_tokens', sa.Column('creation_user_agent', sa.String(500), nullable=True))
    op.add_column('oauth_tokens', sa.Column('revocation_reason', sa.String(255), nullable=True))
    op.add_column('oauth_tokens', sa.Column('revoked_at', sa.DateTime(), nullable=True))
    
    # Create oauth_audit_logs table
    op.create_table(
        'oauth_audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), nullable=False, index=True),
        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False, default=sa.func.utcnow()),
        sa.Column('success', sa.Boolean(), default=True),
        sa.Column('error_message', sa.Text(), nullable=True)
    )
    
    # Create indexes for better performance
    op.create_index('idx_oauth_audit_logs_user_id', 'oauth_audit_logs', ['user_id'])
    op.create_index('idx_oauth_audit_logs_event_type', 'oauth_audit_logs', ['event_type'])
    op.create_index('idx_oauth_audit_logs_timestamp', 'oauth_audit_logs', ['timestamp'])
    op.create_index('idx_oauth_tokens_user_provider', 'oauth_tokens', ['user_id', 'provider'])
    op.create_index('idx_users_gmail_connected', 'users', ['gmail_connected'])


def downgrade():
    """Downgrade database schema."""
    
    # Drop indexes
    op.drop_index('idx_users_gmail_connected', 'users')
    op.drop_index('idx_oauth_tokens_user_provider', 'oauth_tokens')
    op.drop_index('idx_oauth_audit_logs_timestamp', 'oauth_audit_logs')
    op.drop_index('idx_oauth_audit_logs_event_type', 'oauth_audit_logs')
    op.drop_index('idx_oauth_audit_logs_user_id', 'oauth_audit_logs')
    
    # Drop oauth_audit_logs table
    op.drop_table('oauth_audit_logs')
    
    # Remove enhanced oauth_tokens columns
    op.drop_column('oauth_tokens', 'revoked_at')
    op.drop_column('oauth_tokens', 'revocation_reason')
    op.drop_column('oauth_tokens', 'creation_user_agent')
    op.drop_column('oauth_tokens', 'creation_ip')
    op.drop_column('oauth_tokens', 'last_used_at')
    op.drop_column('oauth_tokens', 'encrypted_access_token')
    
    # Remove new users columns
    op.drop_column('users', 'gmail_status')
    op.drop_column('users', 'gmail_consent_version')
    op.drop_column('users', 'gmail_last_token_refresh')
    op.drop_column('users', 'gmail_connection_date')
    op.drop_column('users', 'gmail_scopes_granted')
    op.drop_column('users', 'gmail_email')
    op.drop_column('users', 'gmail_connected')
