"""Consolidate OAuth models

Revision ID: 20250914_consolidate_oauth_models
Revises: <auto>
Create Date: 2025-09-14 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20250914_consolidate_oauth_models'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """No-op migration: model consolidation in `backend/app/models/user.py` merged duplicate
    legacy definitions into a single `OAuthToken`/`OAuthAuditLog` model. The change was code-only
    and did not modify table names or column definitions in a way that requires a schema migration.

    If your database schema differs from the current models, replace this function with the
    required ALTER TABLE / CREATE TABLE operations and set `down_revision` appropriately.
    """
    # Intentionally empty - no schema changes required.
    pass


def downgrade() -> None:
    """No-op downgrade."""
    pass
