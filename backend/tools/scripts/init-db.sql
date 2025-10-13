-- Initialize PhishNet Database
-- This script sets up the initial database structure and permissions

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- For composite indexes

-- Create application user (if not exists from environment)
DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'phishnet_user') THEN
      CREATE ROLE phishnet_user WITH LOGIN PASSWORD 'phishnet_dev_pass';
   END IF;
END
$$;

-- Grant necessary permissions
GRANT CONNECT ON DATABASE phishnet TO phishnet_user;
GRANT USAGE ON SCHEMA public TO phishnet_user;
GRANT CREATE ON SCHEMA public TO phishnet_user;

-- Create indexes for common query patterns (will be managed by Alembic later)
-- This is just for initial setup

COMMENT ON DATABASE phishnet IS 'PhishNet Email Security Analysis Platform';

-- Set database parameters for performance
ALTER DATABASE phishnet SET timezone TO 'UTC';
ALTER DATABASE phishnet SET log_statement TO 'mod';  -- Log modifications in development
