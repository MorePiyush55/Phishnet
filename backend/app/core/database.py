"""Backend database shim that re-uses the canonical application database
configuration from `app.core.database` to avoid duplicate SQLAlchemy Base
and MetaData registrations when both `app` and `backend.app` modules are
imported during tests or runtime.

This file intentionally re-exports objects from `app.core.database`.
"""

from app.core.database import engine, SessionLocal, Base, get_db, init_db

__all__ = ["engine", "SessionLocal", "Base", "get_db", "init_db"]

