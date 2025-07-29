"""Configuration settings for Heimdall application.

This module provides centralized configuration management with support for
different environments (development, testing, production) and automatic
loading of environment variables.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Try to load python-dotenv if available
try:
    from dotenv import load_dotenv

    # Load .env file if it exists
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass


@dataclass
class DatabaseConfig:
    """Database configuration settings."""

    host: str = os.getenv("POSTGRES_HOST", "localhost")
    port: int = int(os.getenv("POSTGRES_PORT", "5432"))
    database: str = os.getenv("POSTGRES_DB", "heimdall_test")
    username: str = os.getenv("POSTGRES_USER", "heimdall")
    password: str = os.getenv("POSTGRES_PASSWORD", "heimdall_password")

    @property
    def url(self) -> str:
        """Get the database URL."""
        return (
            f"postgresql://{self.username}:{self.password}@"
            f"{self.host}:{self.port}/{self.database}"
        )


@dataclass
class RedisConfig:
    """Redis configuration settings."""

    url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    host: str = os.getenv("REDIS_HOST", "localhost")
    port: int = int(os.getenv("REDIS_PORT", "6379"))
    db: int = int(os.getenv("REDIS_DB", "0"))


@dataclass
class AWSConfig:
    """AWS configuration settings."""

    endpoint_url: Optional[str] = os.getenv("AWS_ENDPOINT_URL")
    region: str = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    access_key_id: str = os.getenv("AWS_ACCESS_KEY_ID", "test")
    secret_access_key: str = os.getenv("AWS_SECRET_ACCESS_KEY", "test")
    session_token: Optional[str] = os.getenv("AWS_SESSION_TOKEN")

    @property
    def is_localstack(self) -> bool:
        """Check if using LocalStack."""
        return self.endpoint_url is not None and "localhost" in self.endpoint_url


@dataclass
class EnclaveConfig:
    """Nitro Enclave configuration settings."""

    endpoint: str = os.getenv("ENCLAVE_ENDPOINT", "http://localhost:8001")
    cpu_count: int = int(os.getenv("ENCLAVE_CPU_COUNT", "2"))
    memory_mib: int = int(os.getenv("ENCLAVE_MEMORY_MIB", "512"))
    debug_mode: bool = os.getenv("ENCLAVE_DEBUG_MODE", "true").lower() == "true"
    timeout: int = int(os.getenv("NITRO_CLI_TIMEOUT", "30"))


@dataclass
class StarknetConfig:
    """Starknet configuration settings."""

    network: str = os.getenv("STARKNET_NETWORK", "goerli")
    node_url: str = os.getenv(
        "STARKNET_NODE_URL", "https://starknet-goerli.public.blastapi.io"
    )
    chain_id: str = os.getenv("STARKNET_CHAIN_ID", "SN_GOERLI")
    cairo_version: str = os.getenv("CAIRO_VERSION", "1")


@dataclass
class SecurityConfig:
    """Security configuration settings."""

    secret_key: str = os.getenv("SECRET_KEY", "change-me-in-production")
    max_session_duration: int = int(os.getenv("MAX_SESSION_DURATION", "3600"))
    require_attestation: bool = (
        os.getenv("REQUIRE_ATTESTATION", "false").lower() == "true"
    )
    allowed_origins: List[str] = field(
        default_factory=lambda: os.getenv(
            "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000"
        ).split(",")
    )


@dataclass
class TestingConfig:
    """Testing configuration settings."""

    test_mode: bool = os.getenv("TEST_MODE", "false").lower() == "true"
    pytest_workers: str = os.getenv("PYTEST_WORKERS", "auto")
    coverage_threshold: int = int(os.getenv("COVERAGE_THRESHOLD", "80"))
    mock_mode: bool = os.getenv("MOCK_MODE", "false").lower() == "true"


@dataclass
class MonitoringConfig:
    """Monitoring configuration settings."""

    prometheus_url: str = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
    grafana_url: str = os.getenv("GRAFANA_URL", "http://localhost:3000")
    enable_metrics: bool = os.getenv("ENABLE_METRICS", "false").lower() == "true"


class Settings:
    """Main settings class that aggregates all configuration."""

    def __init__(self):
        """Initialize settings with environment variables."""
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.log_level = os.getenv("LOG_LEVEL", "INFO")

        # Configuration sections
        self.database = DatabaseConfig()
        self.redis = RedisConfig()
        self.aws = AWSConfig()
        self.enclave = EnclaveConfig()
        self.starknet = StarknetConfig()
        self.security = SecurityConfig()
        self.testing = TestingConfig()
        self.monitoring = MonitoringConfig()

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.environment == "testing" or self.testing.test_mode

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"

    def get_aws_client_config(self) -> Dict[str, Any]:
        """Get AWS client configuration dictionary."""
        config = {
            "region_name": self.aws.region,
            "aws_access_key_id": self.aws.access_key_id,
            "aws_secret_access_key": self.aws.secret_access_key,
        }

        if self.aws.endpoint_url:
            config["endpoint_url"] = self.aws.endpoint_url

        if self.aws.session_token:
            config["aws_session_token"] = self.aws.session_token

        return config

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # Check required settings in production
        if self.is_production:
            if self.security.secret_key == "change-me-in-production":
                errors.append("SECRET_KEY must be set in production")

            if self.aws.endpoint_url and "localhost" in self.aws.endpoint_url:
                errors.append(
                    "AWS_ENDPOINT_URL should not point to localhost in production"
                )

        # Check database connection settings
        if not self.database.host:
            errors.append("POSTGRES_HOST is required")

        if not self.database.database:
            errors.append("POSTGRES_DB is required")

        # Check Redis settings
        if not self.redis.host and not self.redis.url:
            errors.append("Either REDIS_HOST or REDIS_URL is required")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary (useful for debugging)."""
        return {
            "environment": self.environment,
            "debug": self.debug,
            "log_level": self.log_level,
            "database": {
                "host": self.database.host,
                "port": self.database.port,
                "database": self.database.database,
                "username": self.database.username,
                # Don't include password in dict
            },
            "redis": {
                "host": self.redis.host,
                "port": self.redis.port,
                "db": self.redis.db,
            },
            "aws": {
                "region": self.aws.region,
                "endpoint_url": self.aws.endpoint_url,
                "is_localstack": self.aws.is_localstack,
            },
            "enclave": {
                "endpoint": self.enclave.endpoint,
                "cpu_count": self.enclave.cpu_count,
                "memory_mib": self.enclave.memory_mib,
                "debug_mode": self.enclave.debug_mode,
                "timeout": self.enclave.timeout,
            },
            "starknet": {
                "network": self.starknet.network,
                "node_url": self.starknet.node_url,
                "chain_id": self.starknet.chain_id,
                "cairo_version": self.starknet.cairo_version,
            },
            "security": {
                "max_session_duration": self.security.max_session_duration,
                "require_attestation": self.security.require_attestation,
                "allowed_origins": self.security.allowed_origins,
            },
            "testing": {
                "test_mode": self.testing.test_mode,
                "pytest_workers": self.testing.pytest_workers,
                "coverage_threshold": self.testing.coverage_threshold,
                "mock_mode": self.testing.mock_mode,
            },
            "monitoring": {
                "prometheus_url": self.monitoring.prometheus_url,
                "grafana_url": self.monitoring.grafana_url,
                "enable_metrics": self.monitoring.enable_metrics,
            },
        }


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def reload_settings() -> Settings:
    """Reload settings from environment variables."""
    global settings
    settings = Settings()
    return settings
