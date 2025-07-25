# AWS Nitro Enclave Blockchain Wallet - Development Makefile

.PHONY: help setup-dev test test-unit test-integration test-e2e lint format security-scan clean install deploy-dev

# Default target
help: ## Show this help message
	@echo "AWS Nitro Enclave Blockchain Wallet - Development Commands"
	@echo "=========================================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development Environment Setup
setup-dev: ## Set up development environment
	@echo "Setting up development environment..."
	pip install --upgrade pip
	pip install -r requirements.txt -r requirements-dev.txt
	pre-commit install
	@echo "Development environment ready!"

install: ## Install production dependencies
	pip install -r requirements.txt

# Code Quality
format: ## Format code with black and isort
	black .
	isort .

lint: ## Run all linting tools
	black --check .
	isort --check-only .
	flake8 .
	pylint nitro_wallet/ application/ --disable=missing-docstring
	mypy nitro_wallet/ --ignore-missing-imports

security-scan: ## Run security scanning with bandit
	bandit -r nitro_wallet/ application/ -f json -o bandit-report.json
	bandit -r nitro_wallet/ application/

# Testing
test: ## Run all tests
	pytest

test-unit: ## Run unit tests only (tests that can run locally with mocks)
	pytest -m "unit and not (integration or aws or docker)" -v

test-integration: ## Run integration tests only (tests requiring real AWS infrastructure)
	pytest -m "integration or (unit and aws and not crypto)" -v

test-local: ## Run only tests that can run locally (unit tests with basic mocks)
	pytest -m "unit and not integration and not docker" -v

test-aws-integration: ## Run tests requiring AWS infrastructure deployment
	pytest -m "integration or aws" -v

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