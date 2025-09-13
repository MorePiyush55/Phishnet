"""Backend OAuth implementation complete migration

Revision ID: backend_oauth_complete
Revises: gmail_watch_fields
Create Date: 2025-01-13 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'backend_oauth_complete'
down_revision = 'gmail_watch_fields'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add all backend OAuth tables and fields."""
    
    # Add new fields to users table
    op.add_column('users', sa.Column('google_sub', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('display_name', sa.String(200), nullable=True))
    op.add_column('users', sa.Column('connected_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('disconnected_at', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('status', sa.String(50), nullable=True, default='disconnected'))
    
    # Create indexes for new user fields
    op.create_index('ix_users_google_sub', 'users', ['google_sub'], unique=True)
    op.create_index('ix_users_status', 'users', ['status'])
    
    # Create oauth_credentials table
    op.create_table('oauth_credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.String(255), nullable=True),
        sa.Column('encrypted_refresh_token', sa.Text(), nullable=False),
        sa.Column('scopes', sa.Text(), nullable=False),
        sa.Column('token_issued_at', sa.DateTime(), nullable=False),
        sa.Column('token_expires_at', sa.DateTime(), nullable=True),
        sa.Column('last_refresh_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_oauth_credentials_user_id', 'oauth_credentials', ['user_id'])
    op.create_index('ix_oauth_credentials_is_active', 'oauth_credentials', ['is_active'])
    
    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('actor', sa.String(100), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, default=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_logs_user_id', 'audit_logs', ['user_id'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_index('ix_audit_logs_success', 'audit_logs', ['success'])
    
    # Create scan_results table
    op.create_table('scan_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('msg_id', sa.String(255), nullable=False),
        sa.Column('thread_id', sa.String(255), nullable=True),
        sa.Column('verdict', sa.String(50), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(), nullable=False),
        sa.Column('scan_duration_ms', sa.Integer(), nullable=True),
        sa.Column('model_version', sa.String(50), nullable=True),
        sa.Column('sender', sa.String(255), nullable=True),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('received_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_results_user_id', 'scan_results', ['user_id'])
    op.create_index('ix_scan_results_msg_id', 'scan_results', ['msg_id'])
    op.create_index('ix_scan_results_verdict', 'scan_results', ['verdict'])
    op.create_index('ix_scan_results_scanned_at', 'scan_results', ['scanned_at'])
    op.create_index('ix_scan_results_score', 'scan_results', ['score'])
    
    # Update default values for existing users
    op.execute("UPDATE users SET status = 'disconnected' WHERE status IS NULL")
    op.execute("UPDATE users SET is_active = true WHERE is_active IS NULL")
    
    # Make status non-nullable after setting defaults
    op.alter_column('users', 'status', nullable=False, server_default='disconnected')


def downgrade() -> None:
    """Remove backend OAuth tables and fields."""
    
    # Drop scan_results table
    op.drop_index('ix_scan_results_score')
    op.drop_index('ix_scan_results_scanned_at')
    op.drop_index('ix_scan_results_verdict')
    op.drop_index('ix_scan_results_msg_id')
    op.drop_index('ix_scan_results_user_id')
    op.drop_table('scan_results')
    
    # Drop audit_logs table
    op.drop_index('ix_audit_logs_success')
    op.drop_index('ix_audit_logs_timestamp')
    op.drop_index('ix_audit_logs_action')
    op.drop_index('ix_audit_logs_user_id')
    op.drop_table('audit_logs')
    
    # Drop oauth_credentials table
    op.drop_index('ix_oauth_credentials_is_active')
    op.drop_index('ix_oauth_credentials_user_id')
    op.drop_table('oauth_credentials')
    
    # Remove user table indexes
    op.drop_index('ix_users_status')
    op.drop_index('ix_users_google_sub')
    
    # Remove user table columns
    op.drop_column('users', 'status')
    op.drop_column('users', 'disconnected_at')
    op.drop_column('users', 'connected_at')
    op.drop_column('users', 'display_name')
    op.drop_column('users', 'google_sub')
