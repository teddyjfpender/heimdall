# AWS Service Mocks for Local Testing

This directory contains comprehensive AWS service mocks designed for local testing without AWS dependencies. The mocks provide realistic behavior patterns for KMS, Secrets Manager, and Nitro Enclave services.

## Overview

The AWS service mocks are designed to:
- **Eliminate AWS dependencies** in tests while maintaining realistic behavior
- **Simulate error conditions** for robust error handling testing  
- **Provide consistent test environments** across different development setups
- **Enable performance testing** with controllable latency patterns
- **Support complex integration scenarios** between multiple AWS services

## Architecture

```
aws_mocks/
├── __init__.py                    # Main exports and public API
├── kms_mock.py                   # AWS KMS service mock
├── secrets_manager_mock.py       # AWS Secrets Manager service mock  
├── nitro_enclave_mock.py         # AWS Nitro Enclave service mock
├── test_environment.py           # Test environment orchestration
├── test_fixtures.py              # Pytest fixtures and utilities
├── integration_helpers.py        # Integration with existing codebase
├── example_usage.py              # Comprehensive usage examples
└── README.md                     # This documentation
```

## Quick Start

### Basic Usage

```python
from tests.fixtures.aws_mocks import quick_aws_test_setup

# Set up mocks for specific services
setup = quick_aws_test_setup(["kms", "secrets_manager"])
kms = setup["kms"]
secrets = setup["secrets_manager"]

# Use like real AWS services
key = kms.create_key(description="Test key")
key_id = key["KeyMetadata"]["KeyId"]

encrypted = kms.encrypt(key_id, b"Hello, World!")
decrypted = kms.decrypt(encrypted["CiphertextBlob"])
assert decrypted["Plaintext"] == b"Hello, World!"
```

### Context Manager Usage

```python
from tests.fixtures.aws_mocks import aws_test_environment

with aws_test_environment() as env:
    kms = env.get_kms_service()
    secrets = env.get_secrets_manager_service()
    enclave = env.get_nitro_enclave_service()
    
    # All services are automatically configured and integrated
    # Environment variables and patches are handled automatically
```

### Pytest Integration

```python
import pytest
from tests.fixtures.aws_mocks.test_fixtures import (
    aws_mock_fixtures,
    starknet_basic_scenario
)

def test_with_aws_mocks(aws_mock_fixtures):
    kms = aws_mock_fixtures.get_kms_service()
    # Test your code here

def test_starknet_scenario(starknet_basic_scenario):
    # Pre-configured Starknet testing environment
    fixtures = starknet_basic_scenario
    # Your Starknet tests here
```

## Service Details

### KMS Mock (`MockKMSService`)

Comprehensive AWS KMS simulation with:

**Core Operations:**
- `create_key()` - Create symmetric/asymmetric keys
- `encrypt()` / `decrypt()` - Data encryption with encryption contexts
- `generate_data_key()` - Generate data encryption keys
- `generate_random()` - Cryptographically secure random bytes

**Key Management:**
- `describe_key()` - Get key metadata
- `list_keys()` - List available keys  
- `enable_key()` / `disable_key()` - Key lifecycle management
- `create_alias()` / `list_aliases()` - Key alias management

**Advanced Features:**
- Realistic PCR-based encryption/decryption
- Support for encryption contexts
- Error simulation (access denied, disabled keys, etc.)
- Configurable latency patterns

### Secrets Manager Mock (`MockSecretsManagerService`)

Full-featured AWS Secrets Manager simulation:

**Secret Operations:**
- `create_secret()` - Create secrets with JSON/binary/string data
- `get_secret_value()` - Retrieve secret values with version support
- `put_secret_value()` - Update secrets with automatic versioning
- `delete_secret()` / `restore_secret()` - Secret lifecycle management

**Version Management:**
- Automatic version staging (AWSCURRENT, AWSPENDING)
- Version-specific retrieval
- Version stage management

**Advanced Features:**
- Multi-region replication simulation
- Resource policy validation
- Batch operations
- Password generation
- Tag management

### Nitro Enclave Mock (`MockNitroEnclaveService`)

Realistic AWS Nitro Enclave simulation:

**Enclave Lifecycle:**
- `create_enclave()` - Create and configure enclaves
- `describe_enclave()` - Get enclave status and configuration
- `terminate_enclave()` - Clean enclave shutdown

**Attestation:**
- `generate_attestation_document()` - Create CBOR attestation documents
- `verify_attestation_document()` - Validate attestation documents
- PCR measurement simulation

**Communication:**
- VSOCK connection simulation
- `create_vsock_connection()` - Mock VSOCK sockets
- Bidirectional communication support

**Integration:**
- `simulate_kmstool_call()` - Mock kmstool_enclave_cli behavior
- Environment validation
- Performance metrics simulation

## Integration Patterns

### Starknet Integration

The mocks provide specific support for Starknet blockchain wallet functionality:

```python
from tests.fixtures.aws_mocks import create_integrated_test_scenario

# Pre-configured Starknet multi-user environment
env = create_integrated_test_scenario("starknet_multiuser")

with env:
    # Encrypted master seed automatically configured
    # User sessions created for testing
    # KMS keys set up for each user
    # Enclave environment ready
    pass
```

### Application Code Integration

The `StarknetIntegrationHelper` automatically patches application modules:

```python
from tests.fixtures.aws_mocks import StarknetIntegrationHelper

helper = StarknetIntegrationHelper(env_manager)
helper.patch_aws_multiuser_integration()  # Patch AWS integration
helper.patch_subprocess_kmstool()         # Patch kmstool calls
helper.start_patches()

# Your application code now uses mocks transparently
```

### Universal boto3 Patching

For comprehensive boto3 integration:

```python
from tests.fixtures.aws_mocks import UniversalAWSMockPatcher

with UniversalAWSMockPatcher(env_manager):
    # All boto3.client() calls automatically use mocks
    import boto3
    
    kms_client = boto3.client('kms')  # Returns mock client
    secrets_client = boto3.client('secretsmanager')  # Returns mock client
```

## Test Scenarios

### Scenario Builder

Create complex test scenarios programmatically:

```python
from tests.fixtures.aws_mocks import TestScenarioBuilder

builder = TestScenarioBuilder(env_manager)
scenario = (builder
    .with_encrypted_master_seed()
    .with_user_sessions(["alice", "bob", "charlie"])
    .with_enclave_attestation()
    .build())

# Scenario contains all configured resources
master_seed = scenario["master_seed"]
users = scenario["users"]
attestation = scenario["attestation"]
```

### Pre-built Scenarios

Common scenarios are available out-of-the-box:

```python
# Basic Starknet wallet functionality
env = create_integrated_test_scenario("starknet_basic")

# Multi-user Starknet environment  
env = create_integrated_test_scenario("starknet_multiuser")

# Enclave attestation testing
env = create_integrated_test_scenario("enclave_attestation")

# KMS + Secrets Manager integration
env = create_integrated_test_scenario("kms_secrets_integration")
```

## Error Simulation

All services support comprehensive error simulation:

```python
# Simulate access denied errors
kms.simulate_error("access_denied", key_id)
secrets.simulate_error("access_denied", secret_name)

# Simulate service issues
kms.simulate_error("throttling")
secrets.simulate_error("service_unavailable")

# Simulate enclave problems
enclave.simulate_error("enclave_crashed", enclave_id)
enclave.simulate_error("attestation_failure")
```

## Performance Testing

Mocks include realistic latency simulation:

```python
# Enable realistic AWS latency patterns
kms.simulate_realistic_latency("encrypt")  # ~50ms
secrets.simulate_realistic_latency("get_secret_value")  # ~60ms

# Disable for fast testing
os.environ["__DEV_MODE__"] = "test"  # Disables latency simulation
```

## Configuration

### Environment Variables

The mocks respect standard AWS environment variables:

```bash
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
NITRO_CLI_TIMEOUT=30
ENCLAVE_CPU_COUNT=2
ENCLAVE_MEMORY_MIB=512
__DEV_MODE__=test  # Disables latency simulation
```

### Custom Configuration

```python
# Custom region
env = TestEnvironmentManager(region="eu-west-1")

# Custom service setup
setup = quick_aws_test_setup(["kms"])  # Only KMS
```

## Best Practices

### 1. Use Context Managers

Always use context managers for automatic cleanup:

```python
with aws_test_environment() as env:
    # Your tests here
    pass
# Automatic cleanup happens here
```

### 2. Leverage Fixtures

Use pytest fixtures for consistent test setup:

```python
@pytest.fixture
def my_test_env(aws_mock_fixtures):
    # Custom setup
    return aws_mock_fixtures.create_test_user_session("test-user")

def test_something(my_test_env):
    # Test with pre-configured environment
    pass
```

### 3. Test Error Conditions

Always test error scenarios:

```python
def test_kms_access_denied(kms_service):
    key = kms_service.create_key()
    key_id = key["KeyMetadata"]["KeyId"]
    
    # Simulate access denied
    kms_service.simulate_error("access_denied", key_id)
    
    with pytest.raises(AccessDeniedError):
        kms_service.encrypt(key_id, b"test data")
```

### 4. Validate Realistic Behavior

Use assertion helpers for realistic validation:

```python
from tests.fixtures.aws_mocks import assert_aws_arn_format, assert_starknet_key_format

# Validate AWS resource formats
assert_aws_arn_format(key_arn, "kms")
assert_starknet_key_format(derived_key)
```

### 5. Performance Testing

Test with realistic loads:

```python
def test_batch_operations(aws_mock_fixtures):
    perf_data = aws_mock_fixtures.create_performance_test_data(100)  # 100 users
    
    # Test your batch processing logic
    for user in perf_data["users"]:
        # Process user operations
        pass
```

## Troubleshooting

### Import Errors

If you encounter import errors, ensure the application modules are in the Python path:

```python
from tests.fixtures.aws_mocks import patch_application_imports
patch_application_imports()  # Adds application paths to sys.path
```

### Mock Not Working

Verify patches are applied correctly:

```python
# Check if patches are active
with aws_test_environment() as env:
    validation = env.validate_service_integration()
    assert validation["valid"] is True
```

### Performance Issues

For faster tests, disable latency simulation:

```python
import os
os.environ["__DEV_MODE__"] = "test"
```

## Advanced Usage

### Custom Service Extensions

Extend mocks with custom behavior:

```python
class CustomKMSMock(MockKMSService):
    def custom_operation(self):
        # Your custom logic
        pass

# Use in test environment
env = TestEnvironmentManager(auto_setup=False)
env.services["kms"] = CustomKMSMock()
```

### Integration with Real AWS

For hybrid testing (some real, some mock):

```python
def create_hybrid_environment():
    env = TestEnvironmentManager(auto_setup=False)
    
    # Use real KMS, mock others
    env.services["kms"] = boto3.client('kms')
    env.services["secrets_manager"] = create_secrets_manager_mock()
    
    return env
```

## Examples

See `example_usage.py` for comprehensive examples including:
- Basic service operations
- Integrated scenarios  
- Error simulation
- Performance testing
- Starknet-specific workflows
- Pytest fixture usage

## Contributing

When extending the mocks:

1. **Maintain realistic behavior** - match AWS service responses
2. **Add comprehensive error simulation** - cover common AWS errors
3. **Include performance patterns** - realistic latency and throughput
4. **Provide good examples** - document usage patterns
5. **Test thoroughly** - ensure mocks work with actual application code

## Version Compatibility

- **Python**: 3.8+
- **boto3**: All versions (mocked, not imported)
- **pytest**: 6.0+
- **cryptography**: 3.0+ (for realistic encryption)

The mocks are designed to be AWS SDK version agnostic since they mock the service behavior rather than the SDK itself.