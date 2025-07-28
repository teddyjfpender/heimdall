# Heimdall Cryptographic Test Suite

This directory contains a comprehensive test suite for all cryptographic operations in the Heimdall project, following Test-Driven Development (TDD) principles and industry best practices.

## Overview

The test suite provides complete coverage of:

- **HKDF Implementation** - RFC 5869 compliant key derivation
- **Starknet Key Derivation** - User-specific private key generation
- **Starknet Cryptography** - Curve validation and field operations
- **Security Properties** - Constant-time operations and timing attack resistance
- **AWS Integration** - KMS decryption and secure master seed handling
- **Performance & Edge Cases** - Stress testing and boundary condition validation

## Test Structure

### Core Test Files

1. **`test_hkdf_implementation.py`** - HKDF Extract/Expand with RFC 5869 compliance
2. **`test_key_derivation.py`** - User private key derivation with edge cases
3. **`test_starknet_crypto.py`** - Starknet-specific cryptographic operations
4. **`test_security_properties.py`** - Constant-time ops and timing attack resistance
5. **`test_aws_integration.py`** - AWS KMS integration and master seed handling
6. **`test_performance_edge_cases.py`** - Performance tests and edge cases

### Test Categories

#### 1. HKDF Implementation Testing (`test_hkdf_implementation.py`)

**Purpose**: Validate HKDF compliance with RFC 5869 and cryptographic correctness.

**Key Test Areas**:
- RFC 5869 test vector validation
- Extract and Expand function correctness
- Maximum output length handling
- Edge cases (empty inputs, large inputs)
- Performance characteristics
- Security properties (pseudorandomness, avalanche effect)

**Example Tests**:
```python
def test_hkdf_extract_rfc5869_vectors(self, rfc5869_test_vectors):
    """Test HKDF-Extract against RFC 5869 test vectors."""
    
def test_hkdf_expand_max_length(self):
    """Test HKDF-Expand with maximum allowed length."""
    
def test_hkdf_avalanche_effect(self):
    """Test that small input changes cause large output changes."""
```

#### 2. Key Derivation Testing (`test_key_derivation.py`)

**Purpose**: Validate the `derive_user_private_key` function and related operations.

**Key Test Areas**:
- Deterministic key generation
- User isolation and uniqueness
- Key index independence
- Fallback mechanism reliability
- Performance scaling
- Statistical properties

**Example Tests**:
```python
def test_derive_user_private_key_deterministic(self):
    """Test that key derivation is deterministic."""
    
def test_derive_user_private_key_fallback_mechanism(self):
    """Test that fallback mechanism always produces valid keys."""
    
def test_key_derivation_performance_scaling(self):
    """Test how performance scales with number of operations."""
```

#### 3. Starknet Cryptography Testing (`test_starknet_crypto.py`)

**Purpose**: Validate Starknet-specific cryptographic operations and curve compliance.

**Key Test Areas**:
- STARK curve constant validation
- Private key validation (range checks)
- Account address derivation
- Field element operations
- Integration with key derivation

**Example Tests**:
```python
def test_validate_starknet_private_key_boundary_values(self):
    """Test validation at boundary values."""
    
def test_derive_account_address_statistical_distribution(self):
    """Test that derived addresses have good statistical distribution."""
    
def test_stark_order_value(self):
    """Test that STARK_ORDER has the correct value."""
```

#### 4. Security Properties Testing (`test_security_properties.py`)

**Purpose**: Validate security properties and resistance to timing attacks.

**Key Test Areas**:
- Constant-time comparisons
- Timing attack resistance
- Memory cleanup
- Cryptographic independence
- Entropy validation

**Example Tests**:
```python
def test_constant_time_compare_timing_consistency(self):
    """Test that constant-time comparison has consistent timing."""
    
def test_validate_user_key_timing_consistency(self):
    """Test that user key validation has consistent timing."""
    
def test_user_key_independence(self):
    """Test that user keys are cryptographically independent."""
```

#### 5. AWS Integration Testing (`test_aws_integration.py`)

**Purpose**: Validate AWS KMS integration and secure master seed handling.

**Key Test Areas**:
- KMS decryption functionality
- Master seed loading and cleanup
- User session validation
- Transaction processing
- Performance monitoring

**Example Tests**:
```python
def test_kms_decrypt_master_seed_success(self):
    """Test successful KMS decryption."""
    
def test_load_master_seed_failure_cleanup(self):
    """Test that failures during seed loading trigger cleanup."""
    
def test_validate_user_ownership_success(self):
    """Test successful user ownership validation."""
```

#### 6. Performance & Edge Cases (`test_performance_edge_cases.py`)

**Purpose**: Stress testing, performance benchmarks, and edge case validation.

**Key Test Areas**:
- Performance benchmarking
- Memory usage patterns
- Concurrent access testing
- Edge case handling
- System limits validation

**Example Tests**:
```python
def test_hkdf_performance_baseline(self):
    """Establish performance baseline for HKDF operations."""
    
def test_concurrent_key_derivation(self):
    """Test key derivation under concurrent access."""
    
def test_memory_pressure_handling(self):
    """Test behavior under memory pressure."""
```

## Running Tests

### Quick Start

```bash
# Run all crypto tests
python -m pytest tests/unit/crypto/ -v

# Run fast tests only (excludes slow performance tests)
python -m pytest tests/unit/crypto/ -v -m "not slow"

# Run with coverage
python -m pytest tests/unit/crypto/ --cov=application.starknet.enclave --cov-report=html
```

### Using the Test Runner

The comprehensive test runner provides advanced options:

```bash
# Run all tests with coverage
python tests/unit/crypto/run_crypto_tests.py --test-type all --coverage --verbose

# Run only security tests
python tests/unit/crypto/run_crypto_tests.py --test-type security --verbose

# Run performance tests
python tests/unit/crypto/run_crypto_tests.py --test-type performance

# Run specific test file
python tests/unit/crypto/run_crypto_tests.py --specific-test tests/unit/crypto/test_hkdf_implementation.py

# Run with parallel execution
python tests/unit/crypto/run_crypto_tests.py --parallel 4 --coverage
```

### Test Categories

- `--test-type all` - Run all tests
- `--test-type unit` - Run unit tests (no slow tests)
- `--test-type fast` - Run fast tests only
- `--test-type slow` - Run slow/performance tests only
- `--test-type security` - Run security-focused tests
- `--test-type performance` - Run performance tests

## Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.crypto` - Cryptographic operation tests
- `@pytest.mark.slow` - Long-running tests (performance, stress)
- `@pytest.mark.unit` - Unit tests
- `@pytest.mark.integration` - Integration tests

## Performance Expectations

### Baseline Performance Requirements

Based on the test suite, the system should meet these performance criteria:

- **HKDF Operations**: < 1ms per operation
- **Key Derivation**: > 50 keys/second
- **Multiple Key Derivation**: > 20 keys/second per user
- **Memory Growth**: < 50MB for 1000 key operations
- **Concurrent Performance**: Maintain >50% of single-thread performance

### Timing Attack Resistance

The test suite validates constant-time properties:

- Key validation timing variance < 5x between valid/invalid keys
- Username comparison timing consistency
- Memory access pattern consistency

## Security Test Coverage

### Cryptographic Properties Tested

1. **Key Uniqueness**: All derived keys must be unique
2. **Deterministic Behavior**: Same inputs always produce same outputs
3. **Statistical Randomness**: Keys pass basic entropy tests
4. **Curve Compliance**: All keys valid for Starknet curve
5. **Independence**: User keys cryptographically independent

### Timing Attack Tests

1. **Constant-Time Comparisons**: Byte and integer comparisons
2. **Key Validation**: User key validation timing consistency
3. **Username Comparison**: Secure username comparison
4. **Concurrent Timing**: Timing consistency under load

### Memory Security

1. **Cleanup Testing**: Sensitive data properly zeroed
2. **Memory Leaks**: No persistent sensitive data in memory
3. **Isolation**: Different managers don't interfere

## Edge Cases Covered

### Input Validation

- Empty inputs, maximum length inputs
- Invalid usernames, invalid key indices
- Malformed master seeds, invalid credentials

### Boundary Conditions

- Maximum HKDF output length (8160 bytes)
- STARK curve order boundaries
- Very large key indices (up to 2^24)
- Maximum username length (255 characters)

### Error Conditions

- KMS decryption failures
- Invalid session data
- Master seed loading errors
- Subprocess failures

## Test Data and Fixtures

### Deterministic Testing

Tests use deterministic seeds for reproducibility:

```python
@pytest.fixture
def test_master_seed(self):
    return create_test_master_seed(deterministic=True)
```

### RFC Test Vectors

HKDF tests include official RFC 5869 test vectors for compliance validation.

### Mock Objects

AWS integration tests use comprehensive mocking:

- KMS service calls
- Subprocess operations
- File system operations
- Environment variables

## Continuous Integration

### Test Execution Strategy

1. **Pull Request Tests**: Fast tests only (`not slow`)
2. **Nightly Tests**: Full test suite including performance
3. **Release Tests**: Full suite with coverage requirements

### Coverage Requirements

- **Minimum Coverage**: 90% line coverage
- **Critical Paths**: 100% coverage for key derivation
- **Security Functions**: 100% coverage for constant-time operations

### Performance Regression Detection

- Baseline performance measurements
- Alert on >20% performance degradation
- Memory usage growth monitoring

## Troubleshooting

### Common Issues

1. **Missing Dependencies**: Install `pip install psutil` for memory tests
2. **Slow Test Timeout**: Increase timeout or run with `-m "not slow"`
3. **Coverage Issues**: Ensure `pytest-cov` is installed

### Debug Mode

Run tests with additional debugging:

```bash
python -m pytest tests/unit/crypto/ -v -s --tb=long
```

### Performance Issues

If tests are slow, run performance profiling:

```bash
python -m pytest tests/unit/crypto/test_performance_edge_cases.py --profile
```

## Contributing

### Adding New Tests

1. Follow existing test structure and naming conventions
2. Include both positive and negative test cases
3. Add appropriate pytest markers
4. Update this README if adding new test categories

### Test Quality Guidelines

1. **Isolation**: Each test should be independent
2. **Deterministic**: Tests should produce consistent results
3. **Clear Intent**: Test names should clearly describe what's being tested
4. **Performance**: Avoid unnecessary delays in fast tests
5. **Security**: Include timing attack resistance tests for sensitive operations

### Code Coverage

Aim for comprehensive coverage:

- Branch coverage for conditional logic
- Edge case coverage for boundary conditions
- Error path coverage for exception handling
- Integration coverage for component interactions

---

## Security Considerations

This test suite validates critical security properties of the cryptographic system. Key security aspects tested include:

- **Cryptographic Correctness**: RFC compliance and proper implementation
- **Timing Attack Resistance**: Constant-time operations validation
- **Key Isolation**: Proper user and key independence
- **Memory Security**: Secure cleanup and no data leaks
- **Input Validation**: Robust handling of edge cases and invalid inputs

The comprehensive nature of these tests provides confidence in the security and reliability of the Heimdall cryptographic implementation.