"""Add Gmail watch fields to User model

Revision ID: gmail_watch_fields
Revises: previous_revision  
Create Date: 2025-01-13 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'gmail_watch_fields'
down_revision = None  # Update with actual previous revision
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add Gmail watch and real-time monitoring fields."""
    
    # Add new columns to users table
    op.add_column('users', sa.Column('gmail_watch_history_id', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('gmail_watch_expiration', sa.DateTime(), nullable=True))
    op.add_column('users', sa.Column('gmail_realtime_enabled', sa.Boolean(), nullable=True, default=False))
    
    # Update existing gmail_realtime_enabled to default False for existing users
    op.execute("UPDATE users SET gmail_realtime_enabled = false WHERE gmail_realtime_enabled IS NULL")
    
    # Make gmail_realtime_enabled non-nullable after setting defaults
    op.alter_column('users', 'gmail_realtime_enabled', nullable=False, default=False)


def downgrade() -> None:
    """Remove Gmail watch and real-time monitoring fields."""
    
    op.drop_column('users', 'gmail_realtime_enabled')
    op.drop_column('users', 'gmail_watch_expiration') 
    op.drop_column('users', 'gmail_watch_history_id')
