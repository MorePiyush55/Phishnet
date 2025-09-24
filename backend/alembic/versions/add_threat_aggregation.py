"""Add threat aggregation tables

Revision ID: add_threat_aggregation
Revises: previous_migration
Create Date: 2024-01-15 10:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_threat_aggregation'
down_revision = None  # Replace with actual previous revision
branch_labels = None
depends_on = None


def upgrade():
    # Create threat_analysis_sessions table
    op.create_table('threat_analysis_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_identifier', sa.String(length=500), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_hash', sa.String(length=64), nullable=False),
        sa.Column('session_started', sa.DateTime(timezone=True), nullable=False),
        sa.Column('session_completed', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_processing_time', sa.Float(), nullable=True),
        sa.Column('threshold_profile', sa.String(length=20), nullable=False),
        sa.Column('aggregator_version', sa.String(length=20), nullable=False),
        sa.Column('component_weights', sa.JSON(), nullable=False),
        sa.Column('final_threat_score', sa.Float(), nullable=True),
        sa.Column('threat_level', sa.String(length=20), nullable=True),
        sa.Column('recommended_action', sa.String(length=20), nullable=True),
        sa.Column('deterministic_hash', sa.String(length=32), nullable=True),
        sa.Column('confidence_level', sa.Float(), nullable=True),
        sa.Column('confidence_lower_bound', sa.Float(), nullable=True),
        sa.Column('confidence_upper_bound', sa.Float(), nullable=True),
        sa.Column('reasoning_summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for threat_analysis_sessions
    op.create_index('idx_threat_sessions_target_hash', 'threat_analysis_sessions', ['target_hash'])
    op.create_index('idx_threat_sessions_deterministic_hash', 'threat_analysis_sessions', ['deterministic_hash'])
    op.create_index('idx_threat_sessions_created_at', 'threat_analysis_sessions', ['created_at'])
    op.create_index('idx_threat_sessions_threat_score', 'threat_analysis_sessions', ['final_threat_score'])
    op.create_index(op.f('ix_threat_analysis_sessions_target_identifier'), 'threat_analysis_sessions', ['target_identifier'])

    # Create component_analysis_results table
    op.create_table('component_analysis_results',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('component_type', sa.String(length=50), nullable=False),
        sa.Column('component_version', sa.String(length=20), nullable=False),
        sa.Column('threat_score', sa.Float(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('processing_time', sa.Float(), nullable=False),
        sa.Column('signals', sa.JSON(), nullable=False),
        sa.Column('raw_metadata', sa.JSON(), nullable=True),
        sa.Column('weight_used', sa.Float(), nullable=False),
        sa.Column('score_contribution', sa.Float(), nullable=False),
        sa.Column('analysis_started', sa.DateTime(timezone=True), nullable=False),
        sa.Column('analysis_completed', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['threat_analysis_sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for component_analysis_results
    op.create_index('idx_component_results_session_id', 'component_analysis_results', ['session_id'])
    op.create_index('idx_component_results_component_type', 'component_analysis_results', ['component_type'])
    op.create_index('idx_component_results_threat_score', 'component_analysis_results', ['threat_score'])

    # Create explanation_signals table
    op.create_table('explanation_signals',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('signal_name', sa.String(length=200), nullable=False),
        sa.Column('signal_description', sa.Text(), nullable=False),
        sa.Column('component_type', sa.String(length=50), nullable=False),
        sa.Column('signal_weight', sa.Float(), nullable=False),
        sa.Column('signal_score', sa.Float(), nullable=False),
        sa.Column('contribution_value', sa.Float(), nullable=False),
        sa.Column('rank_order', sa.Integer(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['threat_analysis_sessions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for explanation_signals
    op.create_index('idx_explanation_signals_session_id', 'explanation_signals', ['session_id'])
    op.create_index('idx_explanation_signals_signal_name', 'explanation_signals', ['signal_name'])
    op.create_index('idx_explanation_signals_rank', 'explanation_signals', ['rank_order'])
    op.create_index(op.f('ix_explanation_signals_component_type'), 'explanation_signals', ['component_type'])


def downgrade():
    # Drop tables in reverse order (due to foreign key constraints)
    op.drop_table('explanation_signals')
    op.drop_table('component_analysis_results')
    op.drop_table('threat_analysis_sessions')