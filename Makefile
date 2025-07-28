# Heimdall - AWS Nitro Enclave Blockchain Wallet - Enhanced Development Makefile

.PHONY: help setup-dev test test-unit test-integration test-e2e lint format security-scan clean install deploy-dev
.PHONY: local-up local-down local-logs local-shell local-test local-mock-server
.PHONY: docker-build docker-test docker-clean db-create db-drop db-migrate db-seed redis-clear
.PHONY: aws-local aws-setup validate-env check-deps

# Configuration - Use modern docker compose or fall back to docker-compose
DOCKER_COMPOSE = $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
DOCKER_COMPOSE_FILE = docker-compose.yml
TEST_DB_NAME = heimdall_test_$(shell date +%s)
LOCAL_MOCK_PORT = 4567

# Default target
help: ## Show this help message
	@echo "Heimdall - Enhanced Development Commands"
	@echo "========================================"  
	@echo ""
	@echo "🚀 QUICK START:"
	@echo "  make local-up      # Start full local environment"
	@echo "  make local-test    # Run tests in local environment"
	@echo "  make local-down    # Stop local environment"
	@echo ""
	@echo "📋 ALL COMMANDS:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

check-deps: ## Check system dependencies
	@echo "Checking system dependencies..."
	@command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed"; exit 1; }
	@docker compose version >/dev/null 2>&1 || docker-compose --version >/dev/null 2>&1 || { echo "❌ Docker Compose is required but not available"; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3 is required but not installed"; exit 1; }
	@echo "✅ All system dependencies are available"

setup-dev: check-deps ## Set up complete development environment
	@echo "🚀 Setting up development environment..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "📝 Created .env file from template"; fi
	pip install --upgrade pip
	pip install -r requirements.txt -r requirements-dev.txt
	pip install python-dotenv  # For environment management
	pre-commit install
	@echo "✅ Development environment ready!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Review and customize .env file"
	@echo "  2. Run 'make local-up' to start services"
	@echo "  3. Run 'make local-test' to verify setup"

install: ## Install production dependencies only
	pip install -r requirements.txt

validate-env: ## Validate environment configuration
	@echo "🔍 Validating environment configuration..."
	@python -c "from config.settings import settings; errors = settings.validate(); print('✅ Configuration valid' if not errors else f'❌ Configuration errors: {errors}'); exit(len(errors))"

# ============================================================================
# LOCAL DEVELOPMENT ENVIRONMENT  
# ============================================================================

local-up: check-deps ## Start essential local development services
	@echo "🚀 Starting essential local development services..."
	@if [ ! -f .env ]; then echo "⚠️  .env file not found. Run 'make setup-dev' first."; exit 1; fi
	@echo "Starting core services (postgres, redis, localstack)..."
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up -d postgres redis localstack
	@echo "⏳ Waiting for core services to be ready..."
	@sleep 15
	@echo "✅ Essential services are ready!"
	@echo ""
	@echo "Services available:"
	@echo "  🗄️  PostgreSQL:     localhost:5432"
	@echo "  📱 Redis:           localhost:6379"  
	@echo "  ☁️  LocalStack AWS:  localhost:4566"
	@echo ""
	@echo "✨ To start additional services:"
	@echo "  make local-up-full    # Start all services including Starknet server"
	@echo "  make local-test       # Run tests with current services"

local-up-full: local-up ## Start full local development environment
	@echo "🚀 Starting additional services..."
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) up -d
	@echo "⏳ Waiting for additional services..."
	@sleep 10
	@echo "✅ Full environment is ready!"
	@echo ""
	@echo "Additional services:"
	@echo "  🔐 Mock Enclave:    localhost:8001"
	@echo "  🌐 Starknet Server: localhost:8000"
	@echo "  📊 Prometheus:      localhost:9090"
	@echo "  📈 Grafana:         localhost:3000 (admin/admin)"

local-down: ## Stop local development environment
	@echo "🛑 Stopping local development environment..."
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) down -v
	@echo "✅ Local environment stopped"

local-restart: ## Restart local development environment
	@make local-down
	@make local-up

local-logs: ## Show logs from all services
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) logs -f

local-logs-%: ## Show logs from specific service (e.g., make local-logs-postgres)
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) logs -f $*

local-shell: ## Open shell in development tools container
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) exec dev-tools bash

local-shell-%: ## Open shell in specific service (e.g., make local-shell-postgres)
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) exec $* bash

local-status: ## Show status of all services
	@echo "📊 Local environment status:"
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) ps

_wait-for-services: ## Internal: Wait for services to be ready
	@echo "⏳ Waiting for PostgreSQL..."
	@timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U heimdall -d heimdall_test; do sleep 1; done' || (echo "❌ PostgreSQL not ready"; exit 1)
	@echo "⏳ Waiting for Redis..."
	@timeout 30 bash -c 'until docker-compose exec -T redis redis-cli ping | grep -q PONG; do sleep 1; done' || (echo "❌ Redis not ready"; exit 1)
	@echo "⏳ Waiting for LocalStack..."
	@timeout 60 bash -c 'until curl -s http://localhost:4566/_localstack/health | grep -q available; do sleep 2; done' || (echo "❌ LocalStack not ready"; exit 1)
	@echo "✅ All services are ready"

# ============================================================================
# TESTING
# ============================================================================

local-test: ## Run tests locally with Docker services available
	@echo "🧪 Running tests locally with Docker services..."
	@if ! $(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) ps postgres | grep -q "Up"; then echo "❌ PostgreSQL not running. Use 'make local-up' first."; exit 1; fi
	@echo "Environment setup: Using local Python with Docker services"
	@export POSTGRES_HOST=localhost POSTGRES_PORT=5432 REDIS_URL=redis://localhost:6379/1 AWS_ENDPOINT_URL=http://localhost:4566 && python run_tests.py
	@echo "✅ Local tests completed"

local-test-unit: ## Run unit tests in local environment
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) run --rm test-runner pytest -m "unit and not (integration or aws or docker)" -v

local-test-integration: ## Run integration tests in local environment  
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) run --rm test-runner pytest -m "integration" -v

local-test-starknet: ## Run Starknet-specific tests in local environment
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) run --rm test-runner pytest -m "starknet" -v

local-test-coverage: ## Run tests with coverage in local environment
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) run --rm test-runner pytest --cov=nitro_wallet --cov=application --cov-report=html:/app/htmlcov --cov-report=term-missing

local-mock-server: ## Start standalone local mock server
	@echo "🚀 Starting local mock server on port $(LOCAL_MOCK_PORT)..."
	@python tests/fixtures/aws_mocks/local_mock_server.py &
	@echo "✅ Mock server started at http://localhost:$(LOCAL_MOCK_PORT)"

test: ## Run all tests (host environment)
	pytest

test-unit: ## Run unit tests only (host environment)
	pytest -m "unit and not (integration or aws or docker)" -v

test-integration: ## Run integration tests only (host environment)
	pytest -m "integration or (unit and aws and not crypto)" -v

test-local-only: ## Run only tests that can run locally (unit tests with basic mocks)
	pytest -m "unit and not integration and not docker" -v

test-starknet: ## Run Starknet-specific tests (host environment)
	pytest -m "starknet" -v

test-crypto: ## Run cryptographic tests (host environment)
	pytest -m "crypto" -v

test-performance: ## Run performance tests (slow tests)
	pytest -m "slow" -v --tb=short

test-e2e: ## Run end-to-end tests
	pytest -m "e2e" -v

test-coverage: ## Run tests with detailed coverage report (host environment)
	pytest --cov=nitro_wallet --cov=application --cov-report=html --cov-report=term-missing --cov-report=xml

test-isolated: ## Run tests with isolated database per test
	@echo "🧪 Running tests with isolated environments..."
	PYTHONPATH=. python -c "from tests.utils.database import cleanup_all_test_resources; cleanup_all_test_resources()"
	pytest --tb=short -v
	PYTHONPATH=. python -c "from tests.utils.database import cleanup_all_test_resources; cleanup_all_test_resources()"

# ============================================================================
# CODE QUALITY
# ============================================================================

format: ## Format code with black and isort
	@echo "🎨 Formatting code..."
	black .
	isort .
	@echo "✅ Code formatted"

format-check: ## Check code formatting without making changes
	@echo "🔍 Checking code formatting..."
	black --check .
	isort --check-only .

lint: ## Run all linting tools
	@echo "🔍 Running linting tools..."
	black --check .
	isort --check-only .
	flake8 .
	pylint nitro_wallet/ application/ config/ --disable=missing-docstring
	mypy nitro_wallet/ config/ --ignore-missing-imports

lint-fix: ## Run linting tools and fix what can be auto-fixed
	@echo "🔧 Auto-fixing linting issues..."
	black .
	isort .
	@echo "✅ Auto-fixable issues resolved"

security-scan: ## Run security scanning with bandit
	@echo "🔒 Running security scan..."
	bandit -r nitro_wallet/ application/ config/ -f json -o bandit-report.json
	bandit -r nitro_wallet/ application/ config/
	@echo "✅ Security scan completed"

type-check: ## Run type checking with mypy
	mypy nitro_wallet/ config/ --ignore-missing-imports

quality-check: lint security-scan type-check ## Run all quality checks

# ============================================================================
# DATABASE AND STORAGE MANAGEMENT
# ============================================================================

db-create: ## Create a new test database
	@echo "🗄️  Creating test database: $(TEST_DB_NAME)"
	PYTHONPATH=. python -c "from tests.utils.database import get_db_manager; db = get_db_manager().create_test_database('$(TEST_DB_NAME)'); print(f'Created: {db}')"

db-drop: ## Drop test databases (use DB_NAME=name for specific)
	@echo "🗑️  Dropping test databases..."
	PYTHONPATH=. python -c "from tests.utils.database import cleanup_all_test_resources; cleanup_all_test_resources()"

db-migrate: ## Run database migrations (if any)
	@echo "📊 Running database migrations..."
	@echo "ℹ️  No migrations configured yet"

db-seed: ## Seed test data into database
	@echo "🌱 Seeding test data..."
	PYTHONPATH=. python -c "from tests.utils.database import get_test_data_manager, get_db_manager; dm = get_db_manager(); tdm = get_test_data_manager(); db = dm.create_test_database('seed_test'); tdm.seed_test_data(db, 'starknet'); print(f'Seeded data in: {db}')"

redis-clear: ## Clear all Redis test databases
	@echo "🧹 Clearing Redis test databases..."
	PYTHONPATH=. python -c "from tests.utils.database import get_redis_manager; get_redis_manager().cleanup_all_redis_dbs()"

# ============================================================================
# DOCKER OPERATIONS
# ============================================================================

docker-build: ## Build all Docker images
	@echo "🐳 Building Docker images..."
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) build
	@echo "✅ Docker images built"

docker-build-%: ## Build specific Docker image (e.g., make docker-build-starknet-server)
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) build $*

docker-test: ## Run tests in Docker environment
	@echo "🐳 Running tests in Docker..."
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) run --rm test-runner
	@echo "✅ Docker tests completed"

docker-clean: ## Clean up Docker containers and volumes
	@echo "🧹 Cleaning up Docker resources..."
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) down -v --remove-orphans
	docker system prune -f
	@echo "✅ Docker cleanup completed"

docker-shell-%: ## Open shell in specific Docker service
	$(DOCKER_COMPOSE) -f $(DOCKER_COMPOSE_FILE) exec $* bash

# ============================================================================
# AWS AND DEPLOYMENT
# ============================================================================

aws-local: ## Set up AWS CLI for LocalStack
	@echo "☁️  Configuring AWS CLI for LocalStack..."
	aws configure set aws_access_key_id test --profile localstack
	aws configure set aws_secret_access_key test --profile localstack
	aws configure set region us-east-1 --profile localstack
	aws configure set endpoint_url http://localhost:4566 --profile localstack
	@echo "✅ AWS LocalStack profile configured"

aws-setup: aws-local ## Set up AWS resources in LocalStack
	@echo "⚙️  Setting up AWS resources in LocalStack..."
	@if ! curl -s http://localhost:4566/_localstack/health >/dev/null; then echo "❌ LocalStack not running. Use 'make local-up' first."; exit 1; fi
	./docker/localstack/init-aws.sh
	@echo "✅ AWS resources set up"

cdk-synth: ## Synthesize CDK templates (default: eth1)
	export CDK_APPLICATION_TYPE=eth1 && cdk synth

cdk-synth-starknet: ## Synthesize CDK templates for Starknet
	export CDK_APPLICATION_TYPE=starknet && cdk synth

cdk-diff: ## Show CDK differences (default: eth1)
	export CDK_APPLICATION_TYPE=eth1 && cdk diff

cdk-diff-starknet: ## Show CDK differences for Starknet
	export CDK_APPLICATION_TYPE=starknet && cdk diff

deploy-dev: ## Deploy to development environment (default: eth1)
	@echo "🚀 Deploying to development environment..."
	export CDK_DEPLOY_REGION=us-east-1 && \
	export CDK_DEPLOY_ACCOUNT=$$(aws sts get-caller-identity --query Account --output text) && \
	export CDK_APPLICATION_TYPE=eth1 && \
	export CDK_PREFIX=dev && \
	./scripts/build_kmstool_enclave_cli.sh && \
	pytest -m "unit and not slow" && \
	cdk deploy devNitroWalletEth --require-approval never

deploy-dev-starknet: ## Deploy Starknet to development environment
	@echo "🚀 Deploying Starknet to development environment..."
	export CDK_DEPLOY_REGION=us-east-1 && \
	export CDK_DEPLOY_ACCOUNT=$$(aws sts get-caller-identity --query Account --output text) && \
	export CDK_APPLICATION_TYPE=starknet && \
	export CDK_PREFIX=dev && \
	./scripts/build_kmstool_enclave_cli.sh && \
	pytest -m "unit and not slow and not ethereum" && \
	cdk deploy devNitroWalletStarknet --require-approval never

# ============================================================================
# DEVELOPMENT UTILITIES
# ============================================================================

generate-test-key: ## Generate test Ethereum private key
	@echo "🔑 Generating test Ethereum private key..."
	@openssl ecparam -name secp256k1 -genkey -noout | openssl ec -text -noout > test_key.tmp
	@echo "Private Key: $$(cat test_key.tmp | grep priv -A 3 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^00//')"
	@echo "Public Key: $$(cat test_key.tmp | grep pub -A 5 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^04//')"
	@rm test_key.tmp

generate-starknet-key: ## Generate test Starknet private key
	@echo "🔑 Generating test Starknet private key..."
	@python -c "from starknet_py.net.account.account import Account; from starknet_py.net.models import StarknetChainId; import secrets; private_key = secrets.randbits(252); print(f'Private Key: {hex(private_key)}'); account = Account.from_key_sync(private_key, '0x0', StarknetChainId.SEPOLIA); print(f'Address: {hex(account.address)}')" 2>/dev/null || echo "Note: Install starknet-py to generate Starknet keys"

validate-config: ## Validate CDK configuration
	@echo "✅ Validating CDK configuration..."
	@python -c "import app; print('✓ CDK app loads successfully')"
	@cdk ls > /dev/null && echo "✓ CDK stacks synthesize successfully"

dev-reset: local-down docker-clean db-drop redis-clear ## Reset entire development environment
	@echo "🔄 Development environment reset complete"

# ============================================================================
# PRE-COMMIT AND CI/CD
# ============================================================================

pre-commit: ## Run pre-commit hooks manually
	pre-commit run --all-files

pre-commit-install: ## Install pre-commit hooks
	pre-commit install

ci-setup: ## Setup for CI environment
	pip install --upgrade pip
	pip install -r requirements.txt -r requirements-dev.txt

ci-test: ## Run tests for CI pipeline
	pytest --junitxml=junit.xml --cov-report=xml

# ============================================================================
# CLEANUP
# ============================================================================

clean: ## Clean up generated files and caches
	@echo "🧹 Cleaning up generated files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf junit.xml
	rm -rf bandit-report.json
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf test-reports/
	@echo "✅ Cleanup completed"

clean-all: clean docker-clean db-drop redis-clear ## Clean everything including Docker and databases
	@echo "✅ Complete cleanup finished"

# ============================================================================
# DOCUMENTATION AND INFO
# ============================================================================

docs: ## Generate documentation (placeholder)
	@echo "📚 Documentation generation not yet implemented"

info: ## Show development environment information
	@echo "📋 Heimdall Development Environment Information"
	@echo "=============================================="
	@echo "Python Version: $$(python --version)"
	@echo "Docker Version: $$(docker --version)"
	@echo "Docker Compose Version: $$(docker-compose --version)"
	@echo ""
	@echo "Configuration:"
	@make validate-env 2>/dev/null || echo "⚠️  Run 'make setup-dev' to configure environment"
	@echo ""
	@echo "Services Status:"
	@if docker-compose ps 2>/dev/null | grep -q "Up"; then \
		echo "✅ Some services are running"; \
		make local-status; \
	else \
		echo "❌ No services running - use 'make local-up' to start"; \
	fi

# Test information and planning
test-list-unit: ## List unit tests that can run locally
	pytest -m "unit and not (integration or aws or docker)" --collect-only -q

test-list-integration: ## List integration tests requiring infrastructure
	pytest -m "integration or (unit and aws and not crypto)" --collect-only -q

test-list-local: ## List all tests that can run locally (unit + basic crypto)
	pytest -m "unit and not integration and not docker" --collect-only -q

test-e2e: ## Run end-to-end tests only
	pytest -m e2e -v

test-aws: ## Run AWS service tests (mocked)
	pytest -m aws -v

test-crypto: ## Run cryptographic tests
	pytest -m crypto -v

test-ethereum: ## Run Ethereum-specific tests
	pytest -m ethereum -v

test-starknet: ## Run Starknet-specific tests  
	python validate_starknet_migration.py

test-blockchain: ## Run all blockchain tests (Ethereum and Starknet)
	pytest -m blockchain -v

test-coverage: ## Run tests with detailed coverage report
	pytest --cov-report=html --cov-report=term-missing

# CDK Operations
cdk-synth: ## Synthesize CDK templates (default: eth1)
	export CDK_APPLICATION_TYPE=eth1 && cdk synth

cdk-synth-starknet: ## Synthesize CDK templates for Starknet
	export CDK_APPLICATION_TYPE=starknet && cdk synth

cdk-diff: ## Show CDK differences (default: eth1)
	export CDK_APPLICATION_TYPE=eth1 && cdk diff

cdk-diff-starknet: ## Show CDK differences for Starknet
	export CDK_APPLICATION_TYPE=starknet && cdk diff

deploy-dev: ## Deploy to development environment (default: eth1)
	@echo "Deploying to development environment..."
	export CDK_DEPLOY_REGION=us-east-1 && \
	export CDK_DEPLOY_ACCOUNT=$$(aws sts get-caller-identity --query Account --output text) && \
	export CDK_APPLICATION_TYPE=eth1 && \
	export CDK_PREFIX=dev && \
	./scripts/build_kmstool_enclave_cli.sh && \
	pytest -m "unit and not slow" && \
	cdk deploy devNitroWalletEth --require-approval never

deploy-dev-starknet: ## Deploy Starknet to development environment
	@echo "Deploying Starknet to development environment..."
	export CDK_DEPLOY_REGION=us-east-1 && \
	export CDK_DEPLOY_ACCOUNT=$$(aws sts get-caller-identity --query Account --output text) && \
	export CDK_APPLICATION_TYPE=starknet && \
	export CDK_PREFIX=dev && \
	./scripts/build_kmstool_enclave_cli.sh && \
	pytest -m "unit and not slow and not ethereum" && \
	cdk deploy devNitroWalletStarknet --require-approval never

# Docker Operations
docker-build-eth1-server: ## Build Ethereum server Docker image
	docker build -t nitro-eth1-server ./application/eth1/server/

docker-build-eth1-enclave: ## Build Ethereum enclave Docker image  
	docker build -t nitro-eth1-enclave ./application/eth1/enclave/

docker-build-starknet-server: ## Build Starknet server Docker image
	docker build -t nitro-starknet-server ./application/starknet/server/

docker-build-starknet-enclave: ## Build Starknet enclave Docker image
	docker build -t nitro-starknet-enclave ./application/starknet/enclave/

docker-test: ## Run tests in Docker container
	docker run --rm -v $$(pwd):/workspace -w /workspace python:3.11 make test

# Cleanup
clean: ## Clean up generated files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf coverage.xml
	rm -rf junit.xml
	rm -rf bandit-report.json
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

# Git Hooks
pre-commit: ## Run pre-commit hooks manually
	pre-commit run --all-files

# Development Utilities
generate-test-key: ## Generate test Ethereum private key
	@echo "Generating test Ethereum private key..."
	@openssl ecparam -name secp256k1 -genkey -noout | openssl ec -text -noout > test_key.tmp
	@echo "Private Key: $$(cat test_key.tmp | grep priv -A 3 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^00//')"
	@echo "Public Key: $$(cat test_key.tmp | grep pub -A 5 | tail -n +2 | tr -d '\n[:space:]:' | sed 's/^04//')"
	@rm test_key.tmp

generate-starknet-key: ## Generate test Starknet private key
	@echo "Generating test Starknet private key..."
	@python -c "from starknet_py.net.account.account import Account; from starknet_py.net.models import StarknetChainId; import secrets; private_key = secrets.randbits(252); print(f'Private Key: {hex(private_key)}'); account = Account.from_key_sync(private_key, '0x0', StarknetChainId.SEPOLIA); print(f'Address: {hex(account.address)}')" 2>/dev/null || echo "Note: Install starknet-py to generate Starknet keys"

validate-config: ## Validate CDK configuration
	@echo "Validating CDK configuration..."
	@python -c "import app; print('✓ CDK app loads successfully')"
	@cdk ls > /dev/null && echo "✓ CDK stacks synthesize successfully"

# Documentation
docs: ## Generate documentation (placeholder)
	@echo "Documentation generation not yet implemented"

# CI/CD helpers
ci-setup: ## Setup for CI environment
	pip install --upgrade pip
	pip install -r requirements.txt -r requirements-dev.txt

ci-test: ## Run tests for CI pipeline
	pytest --junitxml=junit.xml --cov-report=xml