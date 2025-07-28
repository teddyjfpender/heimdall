# Heimdall Development Guide

This guide provides comprehensive instructions for setting up and working with the Heimdall local development environment, which eliminates the need for AWS resources during development and testing.

## 🚀 Quick Start

```bash
# 1. Set up development environment
make setup-dev

# 2. Start local services
make local-up

# 3. Run tests to verify setup
make local-test

# 4. View available commands
make help
```

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Development Environment](#development-environment)
- [Local Services](#local-services)  
- [Testing](#testing)
- [Code Quality](#code-quality)
- [Database Management](#database-management)
- [Docker Operations](#docker-operations)
- [CI/CD Pipeline](#cicd-pipeline)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- **Docker & Docker Compose**: Container orchestration
- **Python 3.11+**: Core development language  
- **Node.js 18+**: For AWS CDK operations
- **Git**: Version control

### Dependency Check
```bash
make check-deps
```

## Development Environment

### Environment Configuration

The project uses a layered configuration system:

1. **Base Configuration**: `.env.example` (template)
2. **Local Configuration**: `.env` (your customizations)  
3. **Test Environments**: Managed by `config/test_environments.py`

### Setup Process

```bash
# Complete setup with dependencies and configuration
make setup-dev

# Validate configuration
make validate-env

# Check development environment info
make info
```

### Configuration Files

- **`.env`**: Local environment variables
- **`config/settings.py`**: Centralized configuration management
- **`pyproject.toml`**: Python project configuration and tool settings
- **`.pre-commit-config.yaml`**: Code quality hooks

## Local Services

### Service Architecture

The local environment provides complete AWS service mocking:

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   PostgreSQL    │  │      Redis      │  │   LocalStack    │
│   (Database)    │  │    (Cache)      │  │   (AWS Mock)    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               │
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Nitro Enclave   │  │ Starknet Server │  │   Monitoring    │
│   Mock Server   │  │   (FastAPI)     │  │ (Prometheus)    │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

### Service Management

```bash
# Start all services
make local-up

# Stop all services  
make local-down

# Restart services
make local-restart

# Check service status
make local-status

# View logs from all services
make local-logs

# View logs from specific service
make local-logs-postgres
make local-logs-redis
make local-logs-localstack
```

### Service Access

| Service | URL | Credentials |
|---------|-----|-------------|
| PostgreSQL | `localhost:5432` | `heimdall/heimdall_password` |
| Redis | `localhost:6379` | (no auth) |
| LocalStack AWS | `localhost:4566` | `test/test` |
| Mock Enclave | `localhost:8001` | (no auth) |
| Starknet Server | `localhost:8000` | (no auth) |
| Prometheus | `localhost:9090` | (no auth) |
| Grafana | `localhost:3000` | `admin/admin` |

## Testing

### Test Categories

The project uses comprehensive test categorization:

```bash
# Run all tests in local environment
make local-test

# Run specific test types
make local-test-unit        # Fast unit tests
make local-test-integration # Integration tests  
make local-test-starknet   # Starknet-specific tests

# Run tests with coverage
make local-test-coverage

# Host environment testing (without Docker)
make test                  # All tests
make test-unit            # Unit tests only
make test-integration     # Integration tests only
make test-starknet        # Starknet tests only
make test-crypto         # Cryptographic tests
make test-performance    # Performance tests
```

### Advanced Test Runner

```bash
# Use the enhanced test runner
python scripts/run_tests.py --help

# Examples:
python scripts/run_tests.py --type unit --environment local --verbose
python scripts/run_tests.py --type starknet --parallel 4 --fail-fast  
python scripts/run_tests.py --type integration --environment docker
```

### Test Environment Isolation

```bash
# Tests with isolated databases (recommended for CI)
make test-isolated

# Manual database management
make db-create             # Create test database
make db-seed              # Seed with test data
make db-drop              # Drop test databases
```

### Coverage Reporting

```bash
# Generate comprehensive coverage reports
python scripts/coverage_report.py

# Coverage with custom threshold
python scripts/coverage_report.py --min-coverage 85

# View coverage trends
cat .coverage-history.json
```

## Code Quality

### Automated Quality Checks

```bash
# Format code
make format                # Auto-format with black & isort
make format-check         # Check formatting without changes

# Linting
make lint                 # Run all linting tools
make lint-fix             # Auto-fix what can be fixed
make type-check           # Type checking with mypy

# Security scanning
make security-scan        # Bandit security analysis

# Comprehensive quality check
make quality-check        # All quality tools
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
make pre-commit-install

# Run hooks manually
make pre-commit

# The hooks automatically run:
# - Code formatting (black, isort)
# - Linting (flake8, pylint)  
# - Type checking (mypy)
# - Security scanning (bandit)
# - Custom checks (AWS creds, private keys, etc.)
```

## Database Management

### Database Operations

```bash
# Create isolated test database
make db-create

# Seed test data
make db-seed

# Drop all test databases  
make db-drop

# Clear Redis test databases
make redis-clear
```

### Database Schema

The PostgreSQL database includes:
- **User session management**
- **Key derivation tracking** 
- **Transaction logging**
- **Test data isolation**

### Using Database Utilities

```python
from tests.utils.database import isolated_database, isolated_redis

# Isolated database for testing
with isolated_database("my_test", seed_data="starknet") as db_name:
    # Use database for testing
    connection_url = get_db_manager().get_connection_url(db_name)

# Isolated Redis database
with isolated_redis("my_test") as redis_db:
    # Use Redis database for testing
    redis_url = get_redis_manager().get_redis_url(redis_db)
```

## Docker Operations

### Container Management

```bash
# Build all Docker images
make docker-build

# Build specific image
make docker-build-starknet-server
make docker-build-nitro-enclave-mock

# Run tests in Docker
make docker-test

# Clean up containers and volumes
make docker-clean

# Open shell in container
make docker-shell-postgres
make docker-shell-redis
```

### Development Tools Container

```bash
# Access development tools (includes AWS CLI, CDK, etc.)
make local-shell

# The dev-tools container includes:
# - AWS CLI configured for LocalStack
# - CDK for infrastructure management  
# - All Python development tools
# - Database clients (psql, redis-cli)
```

## CI/CD Pipeline

### GitHub Actions Workflow

The enhanced CI/CD pipeline includes:

- **Change Detection**: Only run relevant jobs
- **Code Quality**: Automated linting, formatting, security scans
- **Multi-Environment Testing**: Local, Docker, CI environments
- **Security Auditing**: Comprehensive security analysis
- **Performance Testing**: Automated performance regression detection
- **Docker Building**: Multi-stage builds with caching
- **Infrastructure Validation**: CDK template validation

### Manual Workflow Triggers

```bash
# Trigger specific test types via GitHub UI:
# - Workflow Dispatch → Test Type → "unit", "integration", "security"
# - Environment → "ci", "docker"
```

### Artifact Collection

The pipeline automatically collects:
- Test results and coverage reports
- Security scan results  
- Performance benchmarks
- Docker image scan results
- CDK synthesis outputs

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service status
make local-status

# Check Docker resources
docker system df
docker system prune  # Clean up if needed

# Restart services
make local-restart
```

#### Test Failures
```bash
# Run tests with verbose output
make local-test-unit -v

# Check test database
make db-drop && make db-create

# Clear Redis cache
make redis-clear

# Reset entire environment
make dev-reset
```

#### Configuration Issues
```bash
# Validate configuration
make validate-env

# Check environment info
make info

# Recreate .env file
rm .env && cp .env.example .env
```

#### Database Connection Issues
```bash
# Check PostgreSQL
docker-compose exec postgres pg_isready -U heimdall -d heimdall_test

# Check Redis
docker-compose exec redis redis-cli ping

# View service logs
make local-logs-postgres
make local-logs-redis
```

### Debug Mode

Enable debug mode for detailed logging:

```bash
# In .env file:
DEBUG=true
LOG_LEVEL=DEBUG

# Restart services
make local-restart
```

### Performance Issues

```bash
# Check resource usage
docker stats

# Clean up unused resources
make clean-all

# Monitor with built-in tools
open http://localhost:9090  # Prometheus
open http://localhost:3000  # Grafana
```

## Advanced Usage

### Custom Test Environments

```python
from config.test_environments import test_environment

# Create custom test environment
with test_environment("isolated", test_name="my_feature") as settings:
    # Custom test logic with isolated resources
    pass
```

### AWS LocalStack Integration

```bash
# Configure AWS CLI for LocalStack
make aws-local

# Set up AWS resources
make aws-setup

# Use AWS CLI with LocalStack
aws --endpoint-url=http://localhost:4566 s3 ls
```

### CDK Operations

```bash
# Synthesize CloudFormation templates
make cdk-synth            # ETH1 application
make cdk-synth-starknet   # Starknet application

# Show differences
make cdk-diff
make cdk-diff-starknet

# Deploy to development (requires real AWS)
make deploy-dev
make deploy-dev-starknet
```

## Development Workflow

### Recommended Daily Workflow

1. **Start Environment**
   ```bash
   make local-up
   ```

2. **Run Tests** (frequently during development)
   ```bash
   make local-test-unit
   ```

3. **Code Quality** (before commits)
   ```bash
   make format
   make lint
   ```

4. **Integration Testing** (before pull requests)
   ```bash
   make local-test-integration
   ```

5. **Cleanup** (end of day)
   ```bash
   make local-down
   ```

### Feature Development Workflow

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Set Up Isolated Environment**
   ```bash
   make test-isolated  # Ensures clean state
   ```

3. **Develop with TDD**
   ```bash
   # Write tests first
   make local-test-unit -x  # Fail fast during development
   ```

4. **Quality Checks**
   ```bash
   make quality-check
   ```

5. **Integration Testing**
   ```bash
   make local-test-integration
   ```

6. **Final Validation**
   ```bash
   make local-test  # Full test suite
   ```

## Contributing

### Code Standards
- **Python**: Follow PEP 8, enforced by black and flake8
- **Type Hints**: Required for public interfaces
- **Documentation**: Docstrings for all public functions/classes
- **Testing**: Minimum 80% coverage for new code

### Pull Request Process
1. Run full test suite: `make local-test`
2. Pass quality checks: `make quality-check`  
3. Update documentation if needed
4. Squash commits for clean history

### Security Guidelines
- Never commit AWS credentials or private keys
- Use environment variables for configuration
- Run security scans: `make security-scan`
- Follow principle of least privilege

---

For additional help or questions, please refer to the project documentation or open an issue on GitHub.