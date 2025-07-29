"""Basic Starknet integration tests without external dependencies.

This module contains simplified integration tests for Starknet functionality
that don't require complex dependency resolution.
"""

import pytest
import sys
import os

from tests.fixtures.starknet_factories import (
    StarknetPrivateKeyFactory,
    validate_stark_private_key,
    validate_stark_field_element,
    STARK_PRIME,
    STARK_ORDER
)


@pytest.mark.starknet
@pytest.mark.integration
class TestStarknetBasicFunctionality:
    """Basic integration tests for Starknet functionality."""
    
    def test_starknet_constants(self):
        """Test that Starknet constants are correctly defined."""
        # STARK_PRIME should be 2^251 + 17 * 2^192 + 1
        expected_prime = 2**251 + 17 * 2**192 + 1
        assert STARK_PRIME == expected_prime
        
        # STARK_ORDER should be a large prime
        assert STARK_ORDER > 0
        assert STARK_ORDER < STARK_PRIME
    
    def test_private_key_generation(self):
        """Test Starknet private key generation."""
        # Generate multiple keys to test consistency
        keys = [StarknetPrivateKeyFactory() for _ in range(10)]
        
        for key in keys:
            # Key should be hex string
            assert isinstance(key, str)
            assert key.startswith('0x')
            
            # Key should be valid
            assert validate_stark_private_key(key)
            
            # Convert to int and check range
            key_int = int(key, 16)
            assert 0 < key_int < STARK_ORDER
    
    def test_field_element_validation(self):
        """Test STARK field element validation."""
        # Valid field elements
        valid_elements = [
            "0x1",
            "0x123",
            "0x" + "f" * 60,  # Large but valid
            1000,
            STARK_PRIME - 1
        ]
        
        for element in valid_elements:
            assert validate_stark_field_element(element), f"Valid element {element} failed validation"
        
        # Invalid field elements
        invalid_elements = [
            STARK_PRIME,  # Equal to prime
            STARK_PRIME + 1,  # Greater than prime
            -1,  # Negative
            "invalid",  # Non-numeric string
            None  # None value
        ]
        
        for element in invalid_elements:
            assert not validate_stark_field_element(element), f"Invalid element {element} passed validation"
    
    def test_starknet_server_import(self):
        """Test that Starknet server can be imported."""
        try:
            import server
            assert hasattr(server, 'kms_call')
            assert hasattr(server, 'StarkCurveSigner')
            print("✓ Starknet server imports successfully")
        except ImportError as e:
            pytest.fail(f"Failed to import Starknet server: {e}")
    
    def test_key_operations_isolation(self):
        """Test that key operations work in isolation."""
        # Generate a key
        key = StarknetPrivateKeyFactory()
        
        # Validate it
        assert validate_stark_private_key(key)
        
        # Convert formats
        key_int = int(key, 16)
        key_hex = hex(key_int)
        
        # Should still be valid
        assert validate_stark_private_key(key_hex)
        
        # Range checks
        assert 0 < key_int < STARK_ORDER


@pytest.mark.starknet
@pytest.mark.integration
class TestStarknetSecurityFeatures:
    """Test security features of Starknet implementation."""
    
    def test_key_uniqueness(self):
        """Test that generated keys are unique."""
        keys = set()
        num_keys = 100
        
        for _ in range(num_keys):
            key = StarknetPrivateKeyFactory()
            keys.add(key)
        
        # All keys should be unique
        assert len(keys) == num_keys
    
    def test_key_entropy(self):
        """Test that generated keys have sufficient entropy."""
        key = StarknetPrivateKeyFactory()
        key_bytes = bytes.fromhex(key[2:])  # Remove 0x prefix
        
        # Should have reasonable byte diversity
        unique_bytes = len(set(key_bytes))
        assert unique_bytes > 16, f"Key entropy too low: {unique_bytes} unique bytes"
    
    def test_boundary_conditions(self):
        """Test boundary conditions for STARK curve."""
        # Test edge cases for field element validation
        boundary_tests = [
            (0, False),  # Zero should be invalid
            (1, True),   # One should be valid
            (STARK_PRIME - 1, True),  # Max valid value
            (STARK_PRIME, False),     # Prime itself should be invalid
        ]
        
        for value, expected_valid in boundary_tests:
            actual_valid = validate_stark_field_element(value)
            assert actual_valid == expected_valid, f"Boundary test failed for {value}: expected {expected_valid}, got {actual_valid}"


@pytest.mark.starknet
@pytest.mark.integration
class TestStarknetMigrationReadiness:
    """Test readiness of Starknet migration components."""
    
    def test_directory_structure(self):
        """Test that required Starknet directories exist."""
        base_path = os.path.join(os.path.dirname(__file__), '../../application/starknet')
        
        required_dirs = [
            'enclave',
            'lambda', 
            'server',
            'user_data'
        ]
        
        for dir_name in required_dirs:
            dir_path = os.path.join(base_path, dir_name)
            assert os.path.exists(dir_path), f"Required directory {dir_name} does not exist"
    
    def test_required_files(self):
        """Test that required Starknet files exist."""
        base_path = os.path.join(os.path.dirname(__file__), '../../application/starknet')
        
        required_files = [
            'enclave/server.py',
            'enclave/requirements.txt',
            'enclave/Dockerfile',
            'lambda/lambda_function.py',
            'server/app.py',
            'server/requirements.txt',
            'user_data/user_data.sh'
        ]
        
        for file_name in required_files:
            file_path = os.path.join(base_path, file_name)
            assert os.path.exists(file_path), f"Required file {file_name} does not exist"
    
    def test_starknet_requirements(self):
        """Test that Starknet requirements are properly specified."""
        req_path = os.path.join(
            os.path.dirname(__file__), 
            '../../application/starknet/enclave/requirements.txt'
        )
        
        with open(req_path, 'r') as f:
            requirements = f.read()
        
        # Should contain starknet-py
        assert 'starknet-py' in requirements
        assert 'boto3' in requirements
    
    def test_migration_completeness(self):
        """Test that migration appears complete."""
        # Check that both Ethereum and Starknet applications exist
        eth_path = os.path.join(os.path.dirname(__file__), '../../application/eth1')
        starknet_path = os.path.join(os.path.dirname(__file__), '../../application/starknet')
        
        assert os.path.exists(eth_path), "Ethereum application should still exist"
        assert os.path.exists(starknet_path), "Starknet application should exist"
        
        # Both should have similar structure
        for app_path in [eth_path, starknet_path]:
            assert os.path.exists(os.path.join(app_path, 'enclave'))
            assert os.path.exists(os.path.join(app_path, 'lambda'))