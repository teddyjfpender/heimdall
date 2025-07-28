-- PostgreSQL initialization script for Heimdall
-- This script sets up the basic database structure for local development

-- Create additional databases for testing
CREATE DATABASE heimdall_dev;
CREATE DATABASE heimdall_test_template;

-- Create extension for better performance monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Grant privileges to the heimdall user
GRANT ALL PRIVILEGES ON DATABASE heimdall_test TO heimdall;
GRANT ALL PRIVILEGES ON DATABASE heimdall_dev TO heimdall;
GRANT ALL PRIVILEGES ON DATABASE heimdall_test_template TO heimdall;