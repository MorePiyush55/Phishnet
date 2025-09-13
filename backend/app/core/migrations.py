"""
Alembic Database Migrations - Professional schema management
Every DB change via Alembic; no ad-hoc schema tweaks
"""

import os
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.runtime.migration import MigrationContext
from alembic.operations import Operations

logger = logging.getLogger(__name__)

class MigrationManager:
    """
    Professional database migration management using Alembic
    
    Features:
    - Automatic migration generation
    - Schema version tracking
    - Rollback capabilities
    - Migration validation
    - Environment-specific migrations
    - Data migration support
    """
    
    def __init__(self, database_url: str, migrations_dir: str = "alembic"):
        self.database_url = database_url
        self.migrations_dir = Path(migrations_dir)
        self.engine = create_engine(database_url)
        self.alembic_cfg = None
        self._setup_alembic()
    
    def _setup_alembic(self):
        """Setup Alembic configuration"""
        try:
            # Create migrations directory if it doesn't exist
            self.migrations_dir.mkdir(exist_ok=True)
            
            # Create alembic.ini if it doesn't exist
            alembic_ini_path = self.migrations_dir / "alembic.ini"
            if not alembic_ini_path.exists():
                self._create_alembic_ini()
            
            # Setup Alembic config
            self.alembic_cfg = Config(str(alembic_ini_path))
            self.alembic_cfg.set_main_option("sqlalchemy.url", self.database_url)
            
            # Initialize Alembic if needed
            versions_dir = self.migrations_dir / "versions"
            if not versions_dir.exists():
                self._init_alembic()
                
            logger.info("Alembic migration system initialized")
            
        except Exception as e:
            logger.error(f"Failed to setup Alembic: {e}")
            raise
    
    def _create_alembic_ini(self):
        """Create alembic.ini configuration file"""
        alembic_ini_content = """# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = .

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with date and time
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d_%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding `alembic[tz]` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version number format, used by Alembic when generating
# version identifiers. There are two important formats
# available: date-based revisions and sequential integer
# revisions. The default format is: %%(rev)s_%%(slug)s

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = driver://user:pass@localhost/dbname

[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""
        alembic_ini_path = self.migrations_dir / "alembic.ini"
        with open(alembic_ini_path, 'w') as f:
            f.write(alembic_ini_content)
    
    def _init_alembic(self):
        """Initialize Alembic repository"""
        try:
            command.init(self.alembic_cfg, str(self.migrations_dir))
            
            # Create custom env.py
            self._create_env_py()
            
            logger.info("Alembic repository initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Alembic: {e}")
            raise
    
    def _create_env_py(self):
        """Create custom env.py for PhishNet"""
        env_py_content = '''"""PhishNet Alembic Environment Configuration"""

from logging.config import fileConfig
import logging
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context

# Import your models here for autogenerate
from app.models.core.user import User
from app.models.email import Email
from app.models.detection import Detection
from app.models.federated import FederatedLearningSession

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger('alembic.env')

# add your model's MetaData object here
# for 'autogenerate' support
from app.core.database import Base
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    
    # Handle database URL from environment or config
    import os
    database_url = os.getenv('DATABASE_URL') or config.get_main_option("sqlalchemy.url")
    
    configuration = config.get_section(config.config_ini_section)
    configuration['sqlalchemy.url'] = database_url
    
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, 
            target_metadata=target_metadata,
            compare_type=True,  # Detect column type changes
            compare_server_default=True,  # Detect default value changes
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
'''
        
        env_py_path = self.migrations_dir / "env.py"
        with open(env_py_path, 'w') as f:
            f.write(env_py_content)
    
    def generate_migration(self, message: str, autogenerate: bool = True) -> str:
        """
        Generate a new migration
        
        Args:
            message: Migration description
            autogenerate: Whether to auto-detect schema changes
            
        Returns:
            Generated migration revision ID
        """
        try:
            logger.info(f"Generating migration: {message}")
            
            if autogenerate:
                # Auto-generate migration from model changes
                revision = command.revision(
                    self.alembic_cfg,
                    message=message,
                    autogenerate=True
                )
            else:
                # Create empty migration
                revision = command.revision(
                    self.alembic_cfg,
                    message=message
                )
            
            logger.info(f"Generated migration {revision} for: {message}")
            return revision
            
        except Exception as e:
            logger.error(f"Failed to generate migration: {e}")
            raise
    
    def apply_migrations(self, revision: str = "head") -> bool:
        """
        Apply migrations to database
        
        Args:
            revision: Target revision (default: latest)
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Applying migrations to revision: {revision}")
            
            command.upgrade(self.alembic_cfg, revision)
            
            logger.info("Migrations applied successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply migrations: {e}")
            return False
    
    def rollback_migration(self, revision: str) -> bool:
        """
        Rollback to specific revision
        
        Args:
            revision: Target revision to rollback to
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Rolling back to revision: {revision}")
            
            command.downgrade(self.alembic_cfg, revision)
            
            logger.info("Rollback completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback migration: {e}")
            return False
    
    def get_current_revision(self) -> Optional[str]:
        """Get current database revision"""
        try:
            with self.engine.connect() as connection:
                context = MigrationContext.configure(connection)
                return context.get_current_revision()
        except Exception as e:
            logger.error(f"Failed to get current revision: {e}")
            return None
    
    def get_migration_history(self) -> List[Dict[str, Any]]:
        """Get migration history"""
        try:
            script = ScriptDirectory.from_config(self.alembic_cfg)
            revisions = []
            
            for revision in script.walk_revisions():
                revisions.append({
                    'revision': revision.revision,
                    'down_revision': revision.down_revision,
                    'message': revision.doc,
                    'created_at': revision.create_date if hasattr(revision, 'create_date') else None
                })
            
            return revisions
            
        except Exception as e:
            logger.error(f"Failed to get migration history: {e}")
            return []
    
    def validate_migration(self, revision: str) -> bool:
        """Validate a specific migration"""
        try:
            script = ScriptDirectory.from_config(self.alembic_cfg)
            revision_obj = script.get_revision(revision)
            
            if not revision_obj:
                return False
            
            # Check if migration file exists
            migration_file = Path(revision_obj.path)
            if not migration_file.exists():
                return False
            
            # Validate migration syntax
            with open(migration_file, 'r') as f:
                content = f.read()
                # Basic syntax validation
                if 'def upgrade():' not in content or 'def downgrade():' not in content:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Migration validation failed: {e}")
            return False
    
    def create_data_migration(self, message: str, upgrade_sql: str, downgrade_sql: str) -> str:
        """
        Create a data migration with custom SQL
        
        Args:
            message: Migration description
            upgrade_sql: SQL to execute on upgrade
            downgrade_sql: SQL to execute on downgrade
            
        Returns:
            Generated migration revision ID
        """
        try:
            # Generate empty migration
            revision = command.revision(self.alembic_cfg, message=message)
            
            # Get the migration file path
            script = ScriptDirectory.from_config(self.alembic_cfg)
            revision_obj = script.get_revision(revision)
            migration_file = Path(revision_obj.path)
            
            # Create custom migration content
            migration_content = f'''"""PhishNet Data Migration: {message}

Revision ID: {revision}
Revises: {revision_obj.down_revision}
Create Date: {datetime.now().isoformat()}

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '{revision}'
down_revision: Union[str, None] = '{revision_obj.down_revision}'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Data migration upgrade"""
    # Execute custom SQL
    op.execute("""
{upgrade_sql}
    """)


def downgrade() -> None:
    """Data migration downgrade"""
    # Execute custom SQL
    op.execute("""
{downgrade_sql}
    """)
'''
            
            # Write custom migration
            with open(migration_file, 'w') as f:
                f.write(migration_content)
            
            logger.info(f"Created data migration {revision}: {message}")
            return revision
            
        except Exception as e:
            logger.error(f"Failed to create data migration: {e}")
            raise
    
    def backup_database(self, backup_path: Optional[str] = None) -> str:
        """
        Create database backup before migration
        
        Args:
            backup_path: Custom backup file path
            
        Returns:
            Backup file path
        """
        try:
            if not backup_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"backup_phishnet_{timestamp}.sql"
            
            # For SQLite, just copy the file
            if self.database_url.startswith('sqlite'):
                import shutil
                db_path = self.database_url.replace('sqlite:///', '')
                shutil.copy2(db_path, backup_path)
            else:
                # For other databases, use appropriate backup tool
                logger.warning("Backup not implemented for non-SQLite databases")
                return ""
            
            logger.info(f"Database backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Failed to create database backup: {e}")
            return ""
    
    def get_pending_migrations(self) -> List[str]:
        """Get list of pending migrations"""
        try:
            current_rev = self.get_current_revision()
            script = ScriptDirectory.from_config(self.alembic_cfg)
            
            pending = []
            for revision in script.walk_revisions("head", current_rev):
                if revision.revision != current_rev:
                    pending.append(revision.revision)
            
            return pending
            
        except Exception as e:
            logger.error(f"Failed to get pending migrations: {e}")
            return []
    
    def check_migration_status(self) -> Dict[str, Any]:
        """Check overall migration status"""
        try:
            current_rev = self.get_current_revision()
            pending = self.get_pending_migrations()
            history = self.get_migration_history()
            
            return {
                'current_revision': current_rev,
                'pending_migrations': pending,
                'total_migrations': len(history),
                'is_up_to_date': len(pending) == 0,
                'last_migration': history[0] if history else None
            }
            
        except Exception as e:
            logger.error(f"Failed to check migration status: {e}")
            return {
                'current_revision': None,
                'pending_migrations': [],
                'total_migrations': 0,
                'is_up_to_date': False,
                'last_migration': None,
                'error': str(e)
            }

# CLI-style functions for common operations
def create_initial_migration(database_url: str, migrations_dir: str = "alembic"):
    """Create initial migration for PhishNet schema"""
    manager = MigrationManager(database_url, migrations_dir)
    
    # Create initial migration
    revision = manager.generate_migration("Initial PhishNet schema", autogenerate=True)
    print(f"Created initial migration: {revision}")
    
    return revision

def apply_all_migrations(database_url: str, migrations_dir: str = "alembic"):
    """Apply all pending migrations"""
    manager = MigrationManager(database_url, migrations_dir)
    
    # Check status
    status = manager.check_migration_status()
    print(f"Current revision: {status['current_revision']}")
    print(f"Pending migrations: {len(status['pending_migrations'])}")
    
    if status['pending_migrations']:
        # Create backup
        backup_path = manager.backup_database()
        if backup_path:
            print(f"Created backup: {backup_path}")
        
        # Apply migrations
        success = manager.apply_migrations()
        if success:
            print("All migrations applied successfully")
        else:
            print("Migration failed - check logs")
    else:
        print("No pending migrations")

def create_phishnet_data_migration():
    """Create example data migration for PhishNet"""
    database_url = "sqlite:///phishnet_dev.db"
    manager = MigrationManager(database_url)
    
    # Example: Add default admin user
    upgrade_sql = """
    INSERT INTO users (email, password_hash, role, is_active, created_at)
    VALUES ('admin@phishnet.local', 'hashed_password', 'admin', 1, datetime('now'))
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE email = 'admin@phishnet.local');
    """
    
    downgrade_sql = """
    DELETE FROM users WHERE email = 'admin@phishnet.local';
    """
    
    revision = manager.create_data_migration(
        "Add default admin user",
        upgrade_sql,
        downgrade_sql
    )
    
    print(f"Created data migration: {revision}")

# Example usage
def example_migration_workflow():
    """Example of complete migration workflow"""
    database_url = "sqlite:///phishnet_dev.db"
    manager = MigrationManager(database_url)
    
    print("PhishNet Migration Workflow Example")
    print("=" * 40)
    
    # Check current status
    status = manager.check_migration_status()
    print(f"Current status: {status}")
    
    # Generate new migration (if models changed)
    # revision = manager.generate_migration("Add email threading support")
    # print(f"Generated migration: {revision}")
    
    # Apply migrations
    # success = manager.apply_migrations()
    # print(f"Migration applied: {success}")
    
    # Check final status
    final_status = manager.check_migration_status()
    print(f"Final status: {final_status}")

# Example migration workflow can be run from CLI or imported as needed
