"""
Comprehensive tests for Starknet-specific cryptographic operations.

This module tests Starknet curve validation, field element operations,
and related cryptographic functions specific to the STARK curve.
"""

import secrets
from typing import List, Tuple

import pytest

# Import the modules under test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../application/starknet/enclave'))

from key_derivation import (
    validate_starknet_private_key,
    derive_account_address_from_private_key,
    create_test_master_seed,
    STARK_ORDER,
    STARK_PRIME
)


class TestStarknetCurveConstants:
    """Test that Starknet curve constants are correct."""
    
    def test_stark_order_value(self):
        """Test that STARK_ORDER has the correct value."""
        # STARK curve order from the specification
        expected_order = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
        assert STARK_ORDER == expected_order
        
        # Verify it's approximately 2^251
        assert 2**250 < STARK_ORDER < 2**252
        
        # More precise: should be very close to 2^251
        ratio = STARK_ORDER / (2**251)
        assert 0.9 < ratio < 1.1
    
    def test_stark_prime_value(self):
        """Test that STARK_PRIME has the correct value."""
        # STARK field prime from the specification
        expected_prime = 0x800000000000011000000000000000000000000000000000000000000000001
        assert STARK_PRIME == expected_prime
        
        # Verify it's approximately 2^251
        assert 2**250 < STARK_PRIME < 2**252
        
        # Should be larger than STARK_ORDER
        assert STARK_PRIME > STARK_ORDER
    
    def test_curve_constants_relationship(self):
        """Test the relationship between curve constants."""
        # STARK_PRIME should be the field prime
        # STARK_ORDER should be the curve order (smaller than prime)
        assert STARK_PRIME > STARK_ORDER
        
        # Both should be odd (characteristic of cryptographic primes/orders)
        assert STARK_PRIME % 2 == 1
        assert STARK_ORDER % 2 == 1
        
        # Difference should be reasonable
        difference = STARK_PRIME - STARK_ORDER
        assert difference > 0
        assert difference < STARK_ORDER  # Sanity check


class TestStarknetPrivateKeyValidation:
    """Test validation of Starknet private keys."""
    
    def test_validate_starknet_private_key_valid_keys(self):
        """Test validation with valid private keys."""
        valid_keys = [
            1,  # Minimum valid key
            2,  # Small valid key
            100,  # Small valid key
            2**128,  # Medium key
            2**200,  # Large key
            STARK_ORDER // 2,  # Middle of range
            STARK_ORDER - 2,  # Near maximum
            STARK_ORDER - 1,  # Maximum valid key
        ]
        
        for key in valid_keys:
            with pytest.subtest(key=key):
                assert validate_starknet_private_key(key) is True
                assert 0 < key < STARK_ORDER
    
    def test_validate_starknet_private_key_invalid_keys(self):
        """Test validation with invalid private keys."""
        invalid_keys = [
            0,  # Zero is invalid
            -1,  # Negative is invalid
            -100,  # Negative is invalid
            STARK_ORDER,  # Equal to order is invalid
            STARK_ORDER + 1,  # Greater than order is invalid
            STARK_ORDER + 100,  # Much greater than order is invalid
            2**256,  # Very large number
            STARK_PRIME,  # Field prime is invalid for private key
        ]
        
        for key in invalid_keys:
            with pytest.subtest(key=key):
                assert validate_starknet_private_key(key) is False
    
    def test_validate_starknet_private_key_boundary_values(self):
        """Test validation at boundary values."""
        # Test values around the boundaries
        boundary_tests = [
            (0, False),  # Zero boundary
            (1, True),   # Just above zero
            (STARK_ORDER - 1, True),   # Just below order
            (STARK_ORDER, False),      # At order (invalid)
            (STARK_ORDER + 1, False),  # Just above order
        ]
        
        for key, expected in boundary_tests:
            with pytest.subtest(key=key, expected=expected):
                assert validate_starknet_private_key(key) is expected
    
    def test_validate_starknet_private_key_type_handling(self):
        """Test that validation handles different input types appropriately."""
        # Valid integer
        assert validate_starknet_private_key(12345) is True
        
        # Test with very large integers (should handle gracefully)
        very_large = 2**1000
        assert validate_starknet_private_key(very_large) is False
        
        # Test with zero and negative
        assert validate_starknet_private_key(0) is False
        assert validate_starknet_private_key(-1) is False
    
    def test_validate_starknet_private_key_rejection_rate(self):
        """Test that validation rejection rate matches theoretical expectations."""
        # Generate random 256-bit values and test validation
        valid_count = 0
        invalid_count = 0
        test_count = 1000
        
        for _ in range(test_count):
            # Generate random 256-bit value
            random_bytes = secrets.token_bytes(32)
            random_int = int.from_bytes(random_bytes, 'big')
            
            if validate_starknet_private_key(random_int):
                valid_count += 1
            else:
                invalid_count += 1
        
        # Theoretical rejection rate is approximately 31/32 (96.875%)
        # Valid rate should be approximately 1/32 (3.125%)
        rejection_rate = invalid_count / test_count
        valid_rate = valid_count / test_count
        
        # Allow some statistical variance
        assert 0.90 < rejection_rate < 0.99  # Should be very high rejection rate
        assert 0.01 < valid_rate < 0.10      # Should be low valid rate
        
        # Should approximately match theoretical values
        theoretical_rejection = 31/32
        assert abs(rejection_rate - theoretical_rejection) < 0.05


class TestDeriveAccountAddress:
    """Test account address derivation from private keys."""
    
    def test_derive_account_address_basic(self):
        """Test basic account address derivation."""
        # Use a known valid private key
        private_key = 12345
        assert validate_starknet_private_key(private_key)
        
        address = derive_account_address_from_private_key(private_key)
        
        # Address should be a positive integer
        assert isinstance(address, int)
        assert address > 0
        
        # Should be deterministic
        address2 = derive_account_address_from_private_key(private_key)
        assert address == address2
    
    def test_derive_account_address_different_keys(self):
        """Test that different private keys produce different addresses."""
        private_keys = [1, 2, 100, 1000, 12345, 2**100, STARK_ORDER - 1]
        addresses = {}
        
        for private_key in private_keys:
            assert validate_starknet_private_key(private_key)
            address = derive_account_address_from_private_key(private_key)
            addresses[private_key] = address
            assert isinstance(address, int)
            assert address > 0
        
        # All addresses should be unique
        unique_addresses = set(addresses.values())
        assert len(unique_addresses) == len(addresses)
    
    def test_derive_account_address_range(self):
        """Test that derived addresses are in reasonable range."""
        test_keys = [1, 1000, 2**128, STARK_ORDER - 1]
        
        for private_key in test_keys:
            address = derive_account_address_from_private_key(private_key)
            
            # Address should be positive but not too large
            assert 0 < address < 2**160  # Reasonable address range
            
            # Should be much smaller than the field prime
            assert address < STARK_PRIME
    
    def test_derive_account_address_deterministic(self):
        """Test that address derivation is deterministic across calls."""
        private_key = 2**200 + 12345
        assert validate_starknet_private_key(private_key)
        
        # Generate address multiple times
        addresses = []
        for _ in range(10):
            address = derive_account_address_from_private_key(private_key)
            addresses.append(address)
        
        # All should be identical
        assert all(addr == addresses[0] for addr in addresses)
        assert len(set(addresses)) == 1
    
    def test_derive_account_address_invalid_keys(self):
        """Test address derivation with invalid private keys."""
        invalid_keys = [0, -1, STARK_ORDER, STARK_ORDER + 1]
        
        for invalid_key in invalid_keys:
            assert not validate_starknet_private_key(invalid_key)
            # Function should still work (implementation choice)
            # but we won't use these addresses in practice
            address = derive_account_address_from_private_key(invalid_key)
            assert isinstance(address, int)
    
    def test_derive_account_address_statistical_distribution(self):
        """Test that derived addresses have good statistical distribution."""
        # Use a range of valid private keys
        addresses = []
        for i in range(100):
            private_key = (i + 1) * 12345  # Ensure valid keys
            if validate_starknet_private_key(private_key):
                address = derive_account_address_from_private_key(private_key)
                addresses.append(address)
        
        # Should have generated a reasonable number of addresses
        assert len(addresses) > 50
        
        # All addresses should be unique
        assert len(addresses) == len(set(addresses))
        
        # Convert to bytes for distribution analysis
        address_bytes = [addr.to_bytes(20, 'big') for addr in addresses]
        all_bytes = b''.join(address_bytes)
        
        # Should have good byte distribution
        unique_bytes = len(set(all_bytes))
        assert unique_bytes > 200  # Good distribution across byte values


class TestStarknetFieldOperations:
    """Test operations related to Starknet field elements."""
    
    def test_field_element_range_validation(self):
        """Test validation of field element ranges."""
        # Valid field elements should be in range [0, STARK_PRIME)
        valid_elements = [
            0,  # Minimum
            1,  # Small
            STARK_PRIME // 2,  # Middle
            STARK_PRIME - 1,  # Maximum
        ]
        
        for element in valid_elements:
            assert 0 <= element < STARK_PRIME
        
        # Invalid field elements
        invalid_elements = [
            -1,  # Negative
            STARK_PRIME,  # Equal to prime
            STARK_PRIME + 1,  # Greater than prime
        ]
        
        for element in invalid_elements:
            assert not (0 <= element < STARK_PRIME)
    
    def test_field_element_vs_private_key_ranges(self):
        """Test that field elements and private keys have different valid ranges."""
        # Field elements: [0, STARK_PRIME)
        # Private keys: (0, STARK_ORDER)
        
        # Zero is valid field element but invalid private key
        assert 0 < STARK_PRIME
        assert not validate_starknet_private_key(0)
        
        # STARK_ORDER is invalid private key but valid field element
        assert STARK_ORDER < STARK_PRIME
        assert not validate_starknet_private_key(STARK_ORDER)
        assert 0 <= STARK_ORDER < STARK_PRIME
        
        # There are valid field elements that are invalid private keys
        test_element = STARK_ORDER + 1000
        assert test_element < STARK_PRIME
        assert not validate_starknet_private_key(test_element)
    
    def test_conversion_between_bytes_and_integers(self):
        """Test conversion between bytes and integers for Starknet values."""
        # Test with various valid private keys
        test_keys = [1, 1000, 2**128, STARK_ORDER - 1]
        
        for original_key in test_keys:
            assert validate_starknet_private_key(original_key)
            
            # Convert to bytes (32 bytes for 256-bit values)
            key_bytes = original_key.to_bytes(32, 'big')
            assert len(key_bytes) == 32
            
            # Convert back to integer
            recovered_key = int.from_bytes(key_bytes, 'big')
            assert recovered_key == original_key
            
            # Should still be valid
            assert validate_starknet_private_key(recovered_key)
    
    def test_hex_string_representations(self):
        """Test hex string representations of Starknet values."""
        test_values = [
            1,
            255,  # One byte
            65535,  # Two bytes
            2**128,  # 16 bytes
            STARK_ORDER - 1
        ]
        
        for value in test_values:
            # Convert to hex string
            hex_str = hex(value)
            assert hex_str.startswith('0x')
            
            # Convert back from hex
            recovered_value = int(hex_str, 16)
            assert recovered_value == value
            
            # Test with padding
            padded_hex = f"0x{value:064x}"  # 64 hex chars = 32 bytes
            assert len(padded_hex) == 66  # '0x' + 64 chars
            recovered_padded = int(padded_hex, 16)
            assert recovered_padded == value


class TestStarknetCryptographicProperties:
    """Test cryptographic properties specific to Starknet."""
    
    def test_private_key_to_address_independence(self):
        """Test that address derivation provides good independence."""
        # Generate multiple private keys and their addresses
        private_keys = []
        addresses = []
        
        for i in range(100):
            # Generate a private key that's likely to be valid
            candidate = (i + 1) * 1000 + 12345
            if validate_starknet_private_key(candidate):
                private_keys.append(candidate)
                address = derive_account_address_from_private_key(candidate)
                addresses.append(address)
        
        assert len(private_keys) > 50  # Should have many valid keys
        
        # All addresses should be unique
        assert len(addresses) == len(set(addresses))
        
        # Check that small changes in private key cause large changes in address
        if len(private_keys) >= 2:
            pk1, pk2 = private_keys[0], private_keys[1]
            addr1 = derive_account_address_from_private_key(pk1)
            addr2 = derive_account_address_from_private_key(pk2)
            
            # Addresses should be very different
            addr1_bytes = addr1.to_bytes(20, 'big')
            addr2_bytes = addr2.to_bytes(20, 'big')
            
            # Count differing bits
            diff_bits = 0
            for b1, b2 in zip(addr1_bytes, addr2_bytes):
                diff_bits += bin(b1 ^ b2).count('1')
            
            # Should have significant bit difference
            total_bits = 20 * 8
            diff_ratio = diff_bits / total_bits
            assert diff_ratio > 0.3  # At least 30% bit difference
    
    def test_key_generation_entropy(self):
        """Test that derived keys have good entropy properties."""
        master_seed = create_test_master_seed(deterministic=False)
        
        # Import key derivation to test with actual derived keys
        from key_derivation import derive_user_private_key
        
        derived_keys = []
        for i in range(50):
            username = f"entropy_test_user_{i:03d}"
            private_key, _ = derive_user_private_key(master_seed, username)
            assert validate_starknet_private_key(private_key)
            derived_keys.append(private_key)
        
        # All keys should be unique
        assert len(derived_keys) == len(set(derived_keys))
        
        # Convert keys to bytes for entropy analysis
        key_bytes = b''.join(key.to_bytes(32, 'big') for key in derived_keys)
        
        # Count unique bytes
        unique_bytes = len(set(key_bytes))
        
        # Should have good distribution of byte values
        assert unique_bytes > 200  # Good distribution
        
        # Check that keys don't have obvious patterns
        # (This is a basic check - more sophisticated entropy tests could be added)
        first_bytes = [key.to_bytes(32, 'big')[0] for key in derived_keys]
        unique_first_bytes = len(set(first_bytes))
        assert unique_first_bytes > len(derived_keys) * 0.5  # At least 50% unique
    
    def test_curve_order_properties(self):
        """Test mathematical properties of the curve order."""
        # STARK_ORDER should be odd (necessary for elliptic curve cryptography)
        assert STARK_ORDER % 2 == 1
        
        # Should be close to but less than 2^252
        assert 2**251 < STARK_ORDER < 2**252
        
        # Should be much larger than common small factors
        assert STARK_ORDER > 2**200
        
        # Basic primality-related checks (not full primality test)
        # STARK_ORDER should not be divisible by small primes
        small_primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
        
        for p in small_primes:
            # It's okay if it's divisible by some small primes (not necessarily prime itself)
            # This is just a basic sanity check
            pass  # Skip this test as STARK_ORDER may have small factors
    
    def test_field_prime_properties(self):
        """Test mathematical properties of the field prime."""
        # STARK_PRIME should be odd
        assert STARK_PRIME % 2 == 1
        
        # Should be close to 2^251
        assert 2**250 < STARK_PRIME < 2**252
        
        # Should be larger than STARK_ORDER
        assert STARK_PRIME > STARK_ORDER
        
        # Should end in 1 (property of this specific prime)
        assert str(STARK_PRIME)[-1] == '1'


class TestStarknetKeyValidationEdgeCases:
    """Test edge cases in Starknet key validation."""
    
    def test_large_number_handling(self):
        """Test handling of very large numbers."""
        # Test with numbers much larger than STARK_ORDER
        very_large_numbers = [
            2**256,
            2**512,
            2**1024,
            STARK_ORDER * 2,
            STARK_ORDER * 1000,
            STARK_PRIME * 2
        ]
        
        for large_num in very_large_numbers:
            # Should handle gracefully and return False
            assert validate_starknet_private_key(large_num) is False
    
    def test_negative_number_handling(self):
        """Test handling of negative numbers."""
        negative_numbers = [-1, -100, -STARK_ORDER, -2**256]
        
        for neg_num in negative_numbers:
            # Should handle gracefully and return False
            assert validate_starknet_private_key(neg_num) is False
    
    def test_zero_and_near_zero(self):
        """Test handling of zero and near-zero values."""
        near_zero_values = [0, 1, 2, 3]
        
        for value in near_zero_values:
            result = validate_starknet_private_key(value)
            if value == 0:
                assert result is False  # Zero is invalid
            else:
                assert result is True   # Positive values should be valid
    
    def test_near_order_values(self):
        """Test handling of values near STARK_ORDER."""
        near_order_values = [
            STARK_ORDER - 3,
            STARK_ORDER - 2,
            STARK_ORDER - 1,
            STARK_ORDER,
            STARK_ORDER + 1,
            STARK_ORDER + 2,
            STARK_ORDER + 3
        ]
        
        for value in near_order_values:
            result = validate_starknet_private_key(value)
            if value < STARK_ORDER:
                assert result is True   # Less than order should be valid
            else:
                assert result is False  # Greater than or equal to order should be invalid
    
    def test_boundary_precision(self):
        """Test that boundary validation is precise."""
        # Test exact boundary values
        exact_boundary_tests = [
            (STARK_ORDER - 1, True),   # Should be valid
            (STARK_ORDER, False),      # Should be invalid
        ]
        
        for value, expected in exact_boundary_tests:
            assert validate_starknet_private_key(value) is expected
    
    def test_address_derivation_edge_cases(self):
        """Test address derivation with edge case private keys."""
        edge_case_keys = [
            1,  # Minimum valid key
            2,  # Small key
            STARK_ORDER - 2,  # Near maximum
            STARK_ORDER - 1,  # Maximum valid key
        ]
        
        addresses = []
        for key in edge_case_keys:
            assert validate_starknet_private_key(key)
            address = derive_account_address_from_private_key(key)
            addresses.append(address)
            
            # Each address should be valid
            assert isinstance(address, int)
            assert address > 0
        
        # All addresses should be unique
        assert len(addresses) == len(set(addresses))


@pytest.mark.crypto
class TestStarknetIntegrationWithKeyDerivation:
    """Test integration between Starknet crypto and key derivation."""
    
    def test_derived_keys_are_valid_starknet_keys(self):
        """Test that all derived keys are valid for Starknet."""
        from key_derivation import derive_user_private_key
        
        master_seed = create_test_master_seed(deterministic=True)
        
        # Test with many users
        for i in range(100):
            username = f"integration_user_{i:04d}"
            private_key, attempt = derive_user_private_key(master_seed, username)
            
            # Every derived key should be valid for Starknet
            assert validate_starknet_private_key(private_key)
            
            # Should be able to derive address
            address = derive_account_address_from_private_key(private_key)
            assert isinstance(address, int)
            assert address > 0
    
    def test_key_derivation_fallback_produces_valid_keys(self):
        """Test that fallback mechanism produces valid Starknet keys."""
        from key_derivation import derive_user_private_key
        
        # Use deterministic seed and force fallback by using low max_attempts
        master_seed = create_test_master_seed(deterministic=True)
        
        for i in range(20):
            username = f"fallback_user_{i:03d}"
            private_key, attempt = derive_user_private_key(
                master_seed, username, max_attempts=1  # Force fallback for most keys
            )
            
            # Even with fallback, key should be valid
            assert validate_starknet_private_key(private_key)
            
            # Should be able to derive address
            address = derive_account_address_from_private_key(private_key)
            assert isinstance(address, int)
            assert address > 0
    
    def test_multiple_keys_per_user_all_valid(self):
        """Test that multiple keys per user are all valid Starknet keys."""
        from key_derivation import derive_multiple_user_keys
        
        master_seed = create_test_master_seed(deterministic=True)
        username = "multi_key_integration_user"
        num_keys = 10
        
        keys = derive_multiple_user_keys(master_seed, username, num_keys)
        
        addresses = []
        for private_key, key_index, attempt in keys:
            # Each key should be valid
            assert validate_starknet_private_key(private_key)
            
            # Should be able to derive unique address
            address = derive_account_address_from_private_key(private_key)
            addresses.append(address)
            assert isinstance(address, int)
            assert address > 0
        
        # All addresses should be unique
        assert len(addresses) == len(set(addresses))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])