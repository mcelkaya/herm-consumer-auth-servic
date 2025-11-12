-- Database Setup Script for herm-consumer-auth-service
-- This script should be run by a PostgreSQL superuser

-- Create the schema
CREATE SCHEMA IF NOT EXISTS herm_auth;

-- Grant permissions to the application user
GRANT USAGE ON SCHEMA herm_auth TO herm_auth_user;
GRANT CREATE ON SCHEMA herm_auth TO herm_auth_user;
GRANT ALL PRIVILEGES ON SCHEMA herm_auth TO herm_auth_user;

-- Grant permissions on all current and future tables
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA herm_auth TO herm_auth_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA herm_auth TO herm_auth_user;

-- Grant permissions on future tables and sequences
ALTER DEFAULT PRIVILEGES IN SCHEMA herm_auth GRANT ALL PRIVILEGES ON TABLES TO herm_auth_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA herm_auth GRANT ALL PRIVILEGES ON SEQUENCES TO herm_auth_user;

-- Verify schema exists
SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'herm_auth';

