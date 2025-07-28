"""
Database utilities for testing.

This module provides utilities for creating, managing, and cleaning up
test databases, ensuring each test run has a clean, isolated environment.
"""

import os
import asyncio
import logging
from typing import Dict, Any, Optional, List
from contextlib import contextmanager, asynccontextmanager
import tempfile
import subprocess
import time

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import redis

from config.settings import settings

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages test database creation and cleanup."""
    
    def __init__(self, base_db_name: str = "heimdall_test"):
        self.base_db_name = base_db_name
        self.admin_connection_params = {
            'host': settings.database.host,
            'port': settings.database.port,
            'user': settings.database.username,
            'password': settings.database.password,
            'database': 'postgres'  # Connect to postgres DB for admin operations
        }
        self.created_databases: List[str] = []
    
    def create_test_database(self, test_name: str = None) -> str:
        """
        Create a new test database with a unique name.
        
        Args:
            test_name: Optional test name for the database
            
        Returns:
            str: Name of the created database
        """
        if test_name is None:
            test_name = f"test_{int(time.time())}_{os.getpid()}"
        
        db_name = f"{self.base_db_name}_{test_name}"
        
        try:
            # Connect to PostgreSQL as admin
            conn = psycopg2.connect(**self.admin_connection_params)
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            with conn.cursor() as cursor:
                # Create database
                cursor.execute(f'CREATE DATABASE "{db_name}"')
                logger.info(f"Created test database: {db_name}")
            
            conn.close()
            
            # Initialize the database schema
            self._initialize_database_schema(db_name)
            
            self.created_databases.append(db_name)
            return db_name
        
        except Exception as e:
            logger.error(f"Failed to create test database {db_name}: {e}")
            raise
    
    def drop_test_database(self, db_name: str) -> None:
        """
        Drop a test database.
        
        Args:
            db_name: Name of the database to drop
        """
        try:
            # Connect to PostgreSQL as admin
            conn = psycopg2.connect(**self.admin_connection_params)
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            with conn.cursor() as cursor:
                # Terminate existing connections to the database
                cursor.execute(f"""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = '{db_name}' AND pid <> pg_backend_pid()
                """)
                
                # Drop database
                cursor.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
                logger.info(f"Dropped test database: {db_name}")
            
            conn.close()
            
            if db_name in self.created_databases:
                self.created_databases.remove(db_name)
        
        except Exception as e:
            logger.error(f"Failed to drop test database {db_name}: {e}")
            # Don't raise - cleanup should be best effort
    
    def cleanup_all_databases(self) -> None:
        """Clean up all created test databases."""
        for db_name in self.created_databases.copy():
            self.drop_test_database(db_name)
    
    def _initialize_database_schema(self, db_name: str) -> None:
        """Initialize database schema for a test database."""
        connection_params = {
            **self.admin_connection_params,
            'database': db_name
        }
        
        try:
            # Read initialization script
            init_script_path = os.path.join(
                os.path.dirname(__file__), 
                '../../docker/postgres/init.sql'
            )
            
            if os.path.exists(init_script_path):
                with open(init_script_path, 'r') as f:
                    init_script = f.read()
                
                # Execute initialization script
                conn = psycopg2.connect(**connection_params)
                conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
                
                with conn.cursor() as cursor:
                    cursor.execute(init_script)
                    logger.info(f"Initialized schema for database: {db_name}")
                
                conn.close()
            else:
                logger.warning(f"Database init script not found: {init_script_path}")
        
        except Exception as e:
            logger.error(f"Failed to initialize schema for {db_name}: {e}")
            raise
    
    def get_connection_url(self, db_name: str) -> str:
        """Get connection URL for a test database."""
        return f"postgresql://{settings.database.username}:{settings.database.password}@{settings.database.host}:{settings.database.port}/{db_name}"


class RedisManager:
    """Manages Redis databases for testing."""
    
    def __init__(self):
        self.redis_host = settings.redis.host
        self.redis_port = settings.redis.port
        self.used_databases: List[int] = []
    
    def get_test_redis_db(self, test_name: str = None) -> int:
        """
        Get a unique Redis database number for testing.
        
        Args:
            test_name: Optional test name
            
        Returns:
            int: Redis database number (0-15)
        """
        # Use hash of test name to get consistent DB number
        if test_name:
            db_num = hash(test_name) % 15 + 1  # Use DB 1-15 for tests
        else:
            # Find next available DB
            for db_num in range(1, 16):
                if db_num not in self.used_databases:
                    break
            else:
                db_num = 1  # Fallback to DB 1
        
        self.used_databases.append(db_num)
        return db_num
    
    def clear_test_redis_db(self, db_num: int) -> None:
        """Clear a Redis test database."""
        try:
            r = redis.Redis(host=self.redis_host, port=self.redis_port, db=db_num)
            r.flushdb()
            logger.info(f"Cleared Redis database: {db_num}")
            
            if db_num in self.used_databases:
                self.used_databases.remove(db_num)
        
        except Exception as e:
            logger.error(f"Failed to clear Redis database {db_num}: {e}")
    
    def cleanup_all_redis_dbs(self) -> None:
        """Clean up all used Redis test databases."""
        for db_num in self.used_databases.copy():
            self.clear_test_redis_db(db_num)
    
    def get_redis_url(self, db_num: int) -> str:
        """Get Redis URL for a test database."""
        return f"redis://{self.redis_host}:{self.redis_port}/{db_num}"


class TestDataManager:
    """Manages test data seeding and cleanup."""
    
    def __init__(self, db_manager: DatabaseManager, redis_manager: RedisManager):
        self.db_manager = db_manager
        self.redis_manager = redis_manager
    
    def seed_test_data(self, db_name: str, data_type: str = "basic") -> None:
        """
        Seed test data into a database.
        
        Args:
            db_name: Database name
            data_type: Type of test data ("basic", "starknet", "multiuser")
        """
        connection_params = {
            'host': settings.database.host,
            'port': settings.database.port,
            'user': settings.database.username,
            'password': settings.database.password,
            'database': db_name
        }
        
        try:
            conn = psycopg2.connect(**connection_params)
            
            with conn.cursor() as cursor:
                if data_type == "basic":
                    self._seed_basic_data(cursor)
                elif data_type == "starknet":
                    self._seed_starknet_data(cursor)
                elif data_type == "multiuser":
                    self._seed_multiuser_data(cursor)
                
                conn.commit()
                logger.info(f"Seeded {data_type} test data in database: {db_name}")
            
            conn.close()
        
        except Exception as e:
            logger.error(f"Failed to seed test data in {db_name}: {e}")
            raise
    
    def _seed_basic_data(self, cursor) -> None:
        """Seed basic test data."""
        # Insert test users
        cursor.execute("""
            INSERT INTO heimdall.user_sessions (user_id, session_token, permissions, expires_at)
            VALUES 
                ('test_user', 'test_session_123', '["test:access"]', NOW() + INTERVAL '1 hour')
            ON CONFLICT (session_token) DO NOTHING
        """)
    
    def _seed_starknet_data(self, cursor) -> None:
        """Seed Starknet-specific test data."""
        # Insert Starknet users
        cursor.execute("""
            INSERT INTO heimdall.user_sessions (user_id, session_token, permissions, expires_at)
            VALUES 
                ('alice', 'starknet_alice_123', '["starknet:sign", "starknet:derive_key"]', NOW() + INTERVAL '1 hour'),
                ('bob', 'starknet_bob_456', '["starknet:sign"]', NOW() + INTERVAL '1 hour')
            ON CONFLICT (session_token) DO NOTHING
        """)
        
        # Insert key derivation history
        cursor.execute("""
            INSERT INTO heimdall.key_derivations (user_id, key_type, derivation_path)
            VALUES 
                ('alice', 'starknet', 'm/44/9004/0/0'),
                ('bob', 'starknet', 'm/44/9004/0/1')
        """)
    
    def _seed_multiuser_data(self, cursor) -> None:
        """Seed multi-user test data."""
        # Insert multiple users with different permissions
        cursor.execute("""
            INSERT INTO heimdall.user_sessions (user_id, session_token, permissions, expires_at)
            VALUES 
                ('alice', 'multiuser_alice_123', '["starknet:sign", "starknet:derive_key"]', NOW() + INTERVAL '1 hour'),
                ('bob', 'multiuser_bob_456', '["starknet:sign"]', NOW() + INTERVAL '1 hour'),
                ('charlie', 'multiuser_charlie_789', '["starknet:sign", "starknet:derive_key", "admin"]', NOW() + INTERVAL '2 hours'),
                ('admin', 'multiuser_admin_000', '["admin", "user:manage"]', NOW() + INTERVAL '8 hours')
            ON CONFLICT (session_token) DO NOTHING
        """)


# Global managers
_db_manager = None
_redis_manager = None
_test_data_manager = None


def get_db_manager() -> DatabaseManager:
    """Get the global database manager."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def get_redis_manager() -> RedisManager:
    """Get the global Redis manager."""
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisManager()
    return _redis_manager


def get_test_data_manager() -> TestDataManager:
    """Get the global test data manager."""
    global _test_data_manager
    if _test_data_manager is None:
        _test_data_manager = TestDataManager(get_db_manager(), get_redis_manager())
    return _test_data_manager


@contextmanager
def isolated_database(test_name: str = None, seed_data: str = None):
    """
    Context manager for isolated test database.
    
    Args:
        test_name: Optional test name
        seed_data: Optional data type to seed ("basic", "starknet", "multiuser")
    
    Usage:
        with isolated_database("my_test", "starknet") as db_name:
            # Use database for testing
            connection_url = get_db_manager().get_connection_url(db_name)
    """
    db_manager = get_db_manager()
    db_name = db_manager.create_test_database(test_name)
    
    try:
        if seed_data:
            test_data_manager = get_test_data_manager()
            test_data_manager.seed_test_data(db_name, seed_data)
        
        yield db_name
    
    finally:
        db_manager.drop_test_database(db_name)


@contextmanager
def isolated_redis(test_name: str = None):
    """
    Context manager for isolated Redis database.
    
    Args:
        test_name: Optional test name
    
    Usage:
        with isolated_redis("my_test") as db_num:
            # Use Redis database for testing
            redis_url = get_redis_manager().get_redis_url(db_num)
    """
    redis_manager = get_redis_manager()
    db_num = redis_manager.get_test_redis_db(test_name)
    
    try:
        yield db_num
    
    finally:
        redis_manager.clear_test_redis_db(db_num)


@contextmanager
def isolated_test_environment(test_name: str = None, seed_data: str = None):
    """
    Context manager for completely isolated test environment (database + Redis).
    
    Args:
        test_name: Optional test name
        seed_data: Optional data type to seed
    
    Usage:
        with isolated_test_environment("my_test", "starknet") as (db_name, redis_db):
            # Use both database and Redis for testing
    """
    with isolated_database(test_name, seed_data) as db_name:
        with isolated_redis(test_name) as redis_db:
            yield db_name, redis_db


def cleanup_all_test_resources():
    """Clean up all test databases and Redis instances."""
    if _db_manager:
        _db_manager.cleanup_all_databases()
    
    if _redis_manager:
        _redis_manager.cleanup_all_redis_dbs()
    
    logger.info("Cleaned up all test resources")