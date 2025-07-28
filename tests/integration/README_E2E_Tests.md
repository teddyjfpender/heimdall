# Starknet End-to-End Transaction Signing Tests

This directory contains comprehensive end-to-end tests that validate the complete flow from user request to signed Starknet transaction in the Heimdall system.

## Overview

The E2E test suite covers:

1. **Complete Transaction Flow Testing** - User key derivation → Transaction creation → Signing → Verification
2. **Various Starknet Transaction Types** - Invoke, deploy, declare, and batch transactions
3. **Multi-user Concurrent Transaction Signing** - Concurrent access by multiple users
4. **Starknet Integration Testing** - Integration with starknet-py for transaction creation
5. **Security and Error Scenarios** - Invalid authentication, malformed data, network failures
6. **Performance and Scale Testing** - High-volume signing, concurrent users, resource utilization

## Test Files

### Core E2E Tests
- `test_starknet_e2e_transaction_signing.py` - Main E2E transaction signing tests
- `test_starknet_security_error_scenarios.py` - Security and error scenario tests
- `test_starknet_performance_scale.py` - Performance and scalability tests
- `test_starknet_py_integration.py` - Starknet-py library integration tests

### Test Infrastructure
- `test_starknet_e2e_runner.py` - Comprehensive test runner and reporting
- `pytest_e2e.ini` - Pytest configuration for E2E tests
- `README_E2E_Tests.md` - This documentation file

## Running the Tests

### Complete Test Suite

Run the entire E2E test suite with comprehensive reporting:

```bash
# Run all E2E tests with detailed reporting
python tests/integration/test_starknet_e2e_runner.py -v

# Save results to custom report file
python tests/integration/test_starknet_e2e_runner.py -v -r my_report.json
```

### Individual Test Categories

Run specific test categories using pytest markers:

```bash
# Basic transaction flow tests
pytest tests/integration/test_starknet_e2e_transaction_signing.py::TestStarknetTransactionFlowE2E -v

# Multi-user concurrent tests
pytest tests/integration/test_starknet_e2e_transaction_signing.py::TestMultiUserConcurrentSigning -v

# Security and error scenarios
pytest tests/integration/test_starknet_security_error_scenarios.py -v

# Performance tests
pytest tests/integration/test_starknet_performance_scale.py -v

# Starknet-py integration
pytest tests/integration/test_starknet_py_integration.py -v
```

### Test Filtering

Use pytest markers to run specific test types:

```bash
# Run only E2E tests
pytest -m "starknet and integration and e2e" tests/integration/

# Run only performance tests
pytest -m "performance" tests/integration/

# Run only security tests
pytest -m "security" tests/integration/

# Exclude slow tests
pytest -m "not slow" tests/integration/
```

## Test Structure

### TestStarknetTransactionFlowE2E
Complete transaction flow validation:
- Single-user invoke transaction flow
- Multi-user transaction flow with key derivation
- Account information request flow

### TestStarknetTransactionTypes
Various transaction type testing:
- Invoke transaction signing
- Declare transaction signing
- Deploy account transaction signing
- Batch transaction signing

### TestMultiUserConcurrentSigning
Concurrent user access testing:
- Concurrent signing by multiple users
- Same user with different key indices
- High concurrency stress testing

### TestStarknetNetworkIntegration
Network integration testing:
- Testnet transaction signing
- Mainnet transaction signing
- Account abstraction patterns
- Gas estimation and fee handling

### Security Test Classes
Comprehensive security validation:
- Authentication and authorization failures
- AWS service access errors
- Transaction validation errors
- Network failure scenarios
- Memory cleanup validation

### Performance Test Classes
Scalability and performance validation:
- Transaction throughput testing
- Maximum concurrent user limits
- Memory usage monitoring
- Resource utilization analysis

## Test Data and Fixtures

The tests use AWS mock fixtures from `tests/fixtures/aws_mocks/` to simulate:
- KMS key management and decryption
- Secrets Manager secret storage
- Nitro Enclave attestation
- Multi-user session management

### Key Test Scenarios

1. **Happy Path Scenarios**
   - Valid users signing valid transactions
   - Multi-user concurrent access
   - Different transaction types

2. **Error Scenarios**
   - Invalid authentication
   - Malformed transaction data
   - Network failures
   - AWS service errors

3. **Performance Scenarios**
   - High-volume transaction signing
   - Concurrent user stress testing
   - Resource utilization monitoring

4. **Security Scenarios**
   - Authorization bypass attempts
   - Invalid key access
   - Memory security validation

## Performance Benchmarks

The test suite validates these performance requirements:

### Throughput
- Sequential: > 50 transactions/second
- Concurrent: > 20 transactions/second
- Batch processing: > 10% improvement over individual

### Response Times
- Average: < 100ms per transaction
- 95th percentile: < 200ms
- 99th percentile: < 500ms

### Scalability
- Support > 50 concurrent users
- Memory growth < 100MB under sustained load
- Success rate > 95% under maximum load

### Resource Utilization
- CPU usage < 90% under heavy load
- Memory efficiency with proper cleanup
- Connection pooling efficiency > 80%

## Error Handling Validation

The tests validate proper handling of:

### Authentication Errors
- Invalid user credentials
- Expired sessions
- Insufficient permissions
- Invalid key indices

### AWS Integration Errors
- KMS access denied
- KMS key disabled
- Secrets Manager access denied
- Enclave attestation failures

### Transaction Validation Errors
- Malformed transaction parameters
- Invalid contract addresses
- Invalid fee values
- Oversized payloads

### Network Errors
- RPC endpoint failures
- Request timeouts
- Connection failures
- Retry logic exhaustion

## Test Configuration

### Pytest Configuration
The `pytest_e2e.ini` file configures:
- Test discovery patterns
- Marker definitions
- Output formatting
- Logging configuration
- Timeout settings

### Environment Variables
Set these environment variables for testing:
```bash
export STARKNET_NETWORK=testnet
export AWS_REGION=us-east-1
export LOG_LEVEL=INFO
```

### Mock Configuration
AWS services are mocked using the fixtures in `tests/fixtures/aws_mocks/`:
- KMS encryption/decryption
- Secrets Manager secret storage
- Nitro Enclave attestation
- Performance simulation

## Continuous Integration

### GitHub Actions Integration
Add to `.github/workflows/e2e-tests.yml`:
```yaml
name: Starknet E2E Tests
on: [push, pull_request]
jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install -r requirements-dev.txt
      - name: Run E2E tests
        run: |
          python tests/integration/test_starknet_e2e_runner.py -v
```

### Test Reporting
The test runner generates comprehensive JSON reports containing:
- Execution summary
- Performance metrics
- Suite-by-suite results
- Error details
- Recommendations

## Troubleshooting

### Common Issues

1. **Import Errors**
   - Ensure starknet-py is installed: `pip install starknet-py`
   - Check Python path includes application directory

2. **Timeout Errors**
   - Increase timeout in pytest configuration
   - Check system performance under load

3. **Mock Failures**
   - Verify AWS mock fixtures are properly initialized
   - Check fixture dependencies

4. **Performance Test Failures**
   - Ensure system has sufficient resources
   - Adjust performance thresholds for your environment

### Debug Mode
Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
pytest --log-cli-level=DEBUG tests/integration/
```

### Test Isolation
Run tests in isolation to debug issues:
```bash
pytest --forked tests/integration/test_specific_test.py::TestClass::test_method
```

## Contributing

When adding new E2E tests:

1. Follow the existing naming conventions
2. Use appropriate pytest markers
3. Include both positive and negative test cases
4. Add performance assertions where relevant
5. Update documentation for new test scenarios
6. Ensure proper cleanup in fixtures

### Test Categories

Add tests to these categories:
- `@pytest.mark.e2e` - Core end-to-end tests
- `@pytest.mark.performance` - Performance tests
- `@pytest.mark.security` - Security tests
- `@pytest.mark.slow` - Tests taking > 5 seconds

### Performance Test Guidelines

For performance tests:
- Use realistic test data volumes
- Include both warm-up and measurement phases
- Assert on multiple metrics (throughput, latency, resources)
- Provide clear performance requirements
- Include recommendations for failures

This comprehensive E2E test suite ensures that the Starknet transaction signing system is thoroughly validated before production deployment.