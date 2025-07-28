"""
Test environment configurations for different testing scenarios.

This module provides pre-configured settings for various test environments
to ensure consistent and isolated testing across different scenarios.
"""

import os
import tempfile
from typing import Dict, Any, Optional
from contextlib import contextmanager

from .settings import Settings


class TestEnvironment:
    """Base class for test environment configurations."""
    
    def __init__(self, name: str):
        self.name = name
        self.env_vars: Dict[str, str] = {}
        self.temp_files: list = []
        self.original_env: Dict[str, Optional[str]] = {}
    
    def setup(self) -> None:
        """Set up the test environment."""
        # Backup original environment variables
        for key in self.env_vars:
            self.original_env[key] = os.environ.get(key)
            os.environ[key] = self.env_vars[key]
    
    def teardown(self) -> None:
        """Clean up the test environment."""
        # Restore original environment variables
        for key, original_value in self.original_env.items():
            if original_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_value
        
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except (OSError, FileNotFoundError):
                pass
        
        self.original_env.clear()
        self.temp_files.clear()
    
    def __enter__(self):
        self.setup()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.teardown()


class LocalTestEnvironment(TestEnvironment):
    """Local testing environment with mocked services."""
    
    def __init__(self):
        super().__init__("local")
        self.env_vars = {
            'ENVIRONMENT': 'testing',
            'TEST_MODE': 'true',
            'MOCK_MODE': 'true',
            'DEBUG': 'true',
            'LOG_LEVEL': 'DEBUG',
            
            # Use local services
            'POSTGRES_HOST': 'localhost',
            'POSTGRES_PORT': '5432',
            'POSTGRES_DB': 'heimdall_test',
            'POSTGRES_USER': 'heimdall',
            'POSTGRES_PASSWORD': 'heimdall_password',
            
            'REDIS_URL': 'redis://localhost:6379/1',  # Different DB for testing
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            
            # LocalStack AWS services
            'AWS_ENDPOINT_URL': 'http://localhost:4566',
            'AWS_DEFAULT_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': 'test',
            'AWS_SECRET_ACCESS_KEY': 'test',
            'AWS_SESSION_TOKEN': 'test',
            
            # Mock enclave
            'ENCLAVE_ENDPOINT': 'http://localhost:8001',
            'ENCLAVE_DEBUG_MODE': 'true',
            'REQUIRE_ATTESTATION': 'false',
            
            # Test security settings
            'SECRET_KEY': 'test-secret-key-for-testing-only',
            'MAX_SESSION_DURATION': '3600',
            'ALLOWED_ORIGINS': 'http://localhost:3000,http://localhost:8000',
            
            # Starknet test settings
            'STARKNET_NETWORK': 'goerli',
            'STARKNET_NODE_URL': 'https://starknet-goerli.public.blastapi.io',
            'STARKNET_CHAIN_ID': 'SN_GOERLI',
            'CAIRO_VERSION': '1',
        }


class DockerTestEnvironment(TestEnvironment):
    """Docker-based testing environment."""
    
    def __init__(self):
        super().__init__("docker")
        self.env_vars = {
            'ENVIRONMENT': 'testing',
            'TEST_MODE': 'true',
            'MOCK_MODE': 'true',
            'DEBUG': 'true',
            'LOG_LEVEL': 'DEBUG',
            
            # Docker service hostnames
            'POSTGRES_HOST': 'postgres',
            'POSTGRES_PORT': '5432',
            'POSTGRES_DB': 'heimdall_test',
            'POSTGRES_USER': 'heimdall',
            'POSTGRES_PASSWORD': 'heimdall_password',
            
            'REDIS_URL': 'redis://redis:6379/1',
            'REDIS_HOST': 'redis',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            
            # LocalStack in Docker
            'AWS_ENDPOINT_URL': 'http://localstack:4566',
            'AWS_DEFAULT_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': 'test',
            'AWS_SECRET_ACCESS_KEY': 'test',
            'AWS_SESSION_TOKEN': 'test',
            
            # Mock enclave in Docker
            'ENCLAVE_ENDPOINT': 'http://nitro-enclave-mock:8001',
            'ENCLAVE_DEBUG_MODE': 'true',
            'REQUIRE_ATTESTATION': 'false',
            
            # Test security settings
            'SECRET_KEY': 'test-secret-key-for-testing-only',
            'MAX_SESSION_DURATION': '3600',
            'ALLOWED_ORIGINS': 'http://localhost:3000,http://localhost:8000',
            
            # Starknet test settings
            'STARKNET_NETWORK': 'goerli',
            'STARKNET_NODE_URL': 'https://starknet-goerli.public.blastapi.io',
            'STARKNET_CHAIN_ID': 'SN_GOERLI',
            'CAIRO_VERSION': '1',
        }


class CITestEnvironment(TestEnvironment):
    """CI/CD testing environment (GitHub Actions, etc.)."""
    
    def __init__(self):
        super().__init__("ci")
        self.env_vars = {
            'ENVIRONMENT': 'testing',
            'TEST_MODE': 'true',
            'MOCK_MODE': 'true',
            'DEBUG': 'false',  # Less verbose in CI
            'LOG_LEVEL': 'INFO',
            
            # CI database (usually PostgreSQL service)
            'POSTGRES_HOST': 'localhost',
            'POSTGRES_PORT': '5432',
            'POSTGRES_DB': 'test_db',
            'POSTGRES_USER': 'postgres',
            'POSTGRES_PASSWORD': 'postgres',
            
            # In-memory Redis or service
            'REDIS_URL': 'redis://localhost:6379/1',
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': '1',
            
            # Mocked AWS services
            'AWS_ENDPOINT_URL': '',  # Use moto mocks instead of LocalStack
            'AWS_DEFAULT_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': 'testing',
            'AWS_SECRET_ACCESS_KEY': 'testing',
            'AWS_SESSION_TOKEN': 'testing',
            
            # Mock enclave
            'ENCLAVE_ENDPOINT': 'http://localhost:8001',
            'ENCLAVE_DEBUG_MODE': 'true',
            'REQUIRE_ATTESTATION': 'false',
            
            # Test security settings
            'SECRET_KEY': 'ci-test-secret-key',
            'MAX_SESSION_DURATION': '3600',
            'ALLOWED_ORIGINS': 'http://localhost:3000',
            
            # Starknet test settings
            'STARKNET_NETWORK': 'goerli',
            'STARKNET_NODE_URL': 'https://starknet-goerli.public.blastapi.io',
            'STARKNET_CHAIN_ID': 'SN_GOERLI',
            'CAIRO_VERSION': '1',
        }


class IsolatedTestEnvironment(TestEnvironment):
    """Isolated test environment with temporary databases."""
    
    def __init__(self, test_name: str = "isolated"):
        super().__init__(f"isolated-{test_name}")
        
        # Create temporary database name
        temp_db_name = f"test_{test_name}_{os.getpid()}"
        
        self.env_vars = {
            'ENVIRONMENT': 'testing',
            'TEST_MODE': 'true',
            'MOCK_MODE': 'true',
            'DEBUG': 'true',
            'LOG_LEVEL': 'DEBUG',
            
            # Isolated database
            'POSTGRES_HOST': 'localhost',
            'POSTGRES_PORT': '5432',
            'POSTGRES_DB': temp_db_name,
            'POSTGRES_USER': 'heimdall',
            'POSTGRES_PASSWORD': 'heimdall_password',
            
            # Unique Redis DB
            'REDIS_URL': f'redis://localhost:6379/{hash(test_name) % 15 + 1}',
            'REDIS_HOST': 'localhost',
            'REDIS_PORT': '6379',
            'REDIS_DB': str(hash(test_name) % 15 + 1),
            
            # LocalStack with isolation
            'AWS_ENDPOINT_URL': 'http://localhost:4566',
            'AWS_DEFAULT_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': f'test_{test_name}',
            'AWS_SECRET_ACCESS_KEY': f'test_secret_{test_name}',
            'AWS_SESSION_TOKEN': f'test_token_{test_name}',
            
            # Mock enclave
            'ENCLAVE_ENDPOINT': 'http://localhost:8001',
            'ENCLAVE_DEBUG_MODE': 'true',
            'REQUIRE_ATTESTATION': 'false',
            
            # Test security settings
            'SECRET_KEY': f'test-secret-{test_name}',
            'MAX_SESSION_DURATION': '3600',
            'ALLOWED_ORIGINS': 'http://localhost:3000,http://localhost:8000',
            
            # Starknet test settings
            'STARKNET_NETWORK': 'goerli',
            'STARKNET_NODE_URL': 'https://starknet-goerli.public.blastapi.io',
            'STARKNET_CHAIN_ID': 'SN_GOERLI',
            'CAIRO_VERSION': '1',
        }


# Pre-configured environment instances
LOCAL_TEST = LocalTestEnvironment()
DOCKER_TEST = DockerTestEnvironment()
CI_TEST = CITestEnvironment()


@contextmanager
def test_environment(env_type: str = "local", **kwargs):
    """
    Context manager for setting up test environments.
    
    Args:
        env_type: Type of environment ("local", "docker", "ci", "isolated")
        **kwargs: Additional configuration overrides
    
    Usage:
        with test_environment("local") as env:
            # Run tests with local environment
            assert settings.is_testing
    """
    if env_type == "local":
        env = LocalTestEnvironment()
    elif env_type == "docker":
        env = DockerTestEnvironment()
    elif env_type == "ci":
        env = CITestEnvironment()
    elif env_type == "isolated":
        test_name = kwargs.get("test_name", "default")
        env = IsolatedTestEnvironment(test_name)
    else:
        raise ValueError(f"Unknown environment type: {env_type}")
    
    # Apply any overrides
    env.env_vars.update(kwargs)
    
    with env:
        # Reload settings to pick up new environment
        from .settings import reload_settings
        settings = reload_settings()
        yield settings


def get_test_database_url(test_name: str = "test") -> str:
    """Get a unique database URL for testing."""
    db_name = f"test_{test_name}_{os.getpid()}"
    return f"postgresql://heimdall:heimdall_password@localhost:5432/{db_name}"


def create_test_settings(**overrides) -> Settings:
    """
    Create test settings with optional overrides.
    
    Args:
        **overrides: Configuration overrides
        
    Returns:
        Settings instance configured for testing
    """
    # Temporarily set environment variables
    test_env_vars = {
        'ENVIRONMENT': 'testing',
        'TEST_MODE': 'true',
        'MOCK_MODE': 'true',
        'DEBUG': 'true',
        'LOG_LEVEL': 'DEBUG',
        **overrides
    }
    
    original_env = {}
    for key, value in test_env_vars.items():
        original_env[key] = os.environ.get(key)
        os.environ[key] = str(value)
    
    try:
        from .settings import Settings
        return Settings()
    finally:
        # Restore original environment
        for key, original_value in original_env.items():
            if original_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_value