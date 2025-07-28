"""
Comprehensive tests for HKDF implementation following RFC 5869.

This module tests the HKDF (HMAC-based Key Derivation Function) implementation
for compliance with RFC 5869, including test vectors and edge cases.
"""

import hashlib
import hmac
import secrets
from typing import List, Tuple

import pytest

# Import the modules under test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../application/starknet/enclave'))

from key_derivation import (
    hkdf,
    hkdf_extract,
    hkdf_expand,
    STARK_ORDER,
    STARK_PRIME
)


class TestHKDFRFC5869Compliance:
    """Test HKDF implementation against RFC 5869 test vectors."""
    
    @pytest.fixture
    def rfc5869_test_vectors(self):
        """RFC 5869 official test vectors for HKDF-SHA256."""
        return [
            {
                # Test Case 1: Basic test case with SHA-256
                "name": "RFC5869_Test_Case_1",
                "ikm": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                "salt": bytes.fromhex("000102030405060708090a0b0c"),
                "info": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
                "length": 42,
                "expected_prk": bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
                "expected_okm": bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
            },
            {
                # Test Case 2: Test with longer inputs
                "name": "RFC5869_Test_Case_2", 
                "ikm": bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
                "salt": bytes.fromhex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab"),
                "info": bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                "length": 82,
                "expected_prk": bytes.fromhex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
                "expected_okm": bytes.fromhex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
            },
            {
                # Test Case 3: Test with zero-length salt
                "name": "RFC5869_Test_Case_3",
                "ikm": bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                "salt": b"",
                "info": b"",
                "length": 42,
                "expected_prk": bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
                "expected_okm": bytes.fromhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
            }
        ]
    
    def test_hkdf_extract_rfc5869_vectors(self, rfc5869_test_vectors):
        """Test HKDF-Extract against RFC 5869 test vectors."""
        for vector in rfc5869_test_vectors:
            with pytest.subtest(vector["name"]):
                prk = hkdf_extract(vector["salt"], vector["ikm"])
                assert prk == vector["expected_prk"], (
                    f"HKDF-Extract failed for {vector['name']}\n"
                    f"Expected: {vector['expected_prk'].hex()}\n"
                    f"Got:      {prk.hex()}"
                )
    
    def test_hkdf_expand_rfc5869_vectors(self, rfc5869_test_vectors):
        """Test HKDF-Expand against RFC 5869 test vectors."""
        for vector in rfc5869_test_vectors:
            with pytest.subtest(vector["name"]):
                prk = vector["expected_prk"]  # Use expected PRK
                okm = hkdf_expand(prk, vector["info"], vector["length"])
                assert okm == vector["expected_okm"], (
                    f"HKDF-Expand failed for {vector['name']}\n"
                    f"Expected: {vector['expected_okm'].hex()}\n"
                    f"Got:      {okm.hex()}"
                )
    
    def test_complete_hkdf_rfc5869_vectors(self, rfc5869_test_vectors):
        """Test complete HKDF (Extract + Expand) against RFC 5869 test vectors."""
        for vector in rfc5869_test_vectors:
            with pytest.subtest(vector["name"]):
                okm = hkdf(
                    vector["ikm"], 
                    vector["salt"], 
                    vector["info"], 
                    vector["length"]
                )
                assert okm == vector["expected_okm"], (
                    f"Complete HKDF failed for {vector['name']}\n"
                    f"Expected: {vector['expected_okm'].hex()}\n"
                    f"Got:      {okm.hex()}"
                )


class TestHKDFExtractFunction:
    """Test HKDF-Extract function thoroughly."""
    
    def test_hkdf_extract_basic_functionality(self):
        """Test basic HKDF-Extract functionality."""
        salt = b"salt_value"
        ikm = b"input_keying_material"
        
        prk = hkdf_extract(salt, ikm)
        
        # Should return 32 bytes (SHA256 output)
        assert len(prk) == 32
        assert isinstance(prk, bytes)
        
        # Should be deterministic
        prk2 = hkdf_extract(salt, ikm)
        assert prk == prk2
    
    def test_hkdf_extract_empty_salt(self):
        """Test HKDF-Extract with empty salt (should use default)."""
        ikm = b"input_keying_material"
        
        # Empty salt should use default (32 zero bytes)
        prk_empty = hkdf_extract(b"", ikm)
        prk_default = hkdf_extract(b"\x00" * 32, ikm)
        
        assert prk_empty == prk_default
        assert len(prk_empty) == 32
    
    def test_hkdf_extract_various_salt_lengths(self):
        """Test HKDF-Extract with various salt lengths."""
        ikm = b"input_keying_material"
        
        salt_lengths = [0, 1, 16, 32, 48, 64, 128]
        results = {}
        
        for length in salt_lengths:
            salt = b"S" * length if length > 0 else b""
            prk = hkdf_extract(salt, ikm)
            results[length] = prk
            
            # All should produce 32-byte output
            assert len(prk) == 32
        
        # Different salt lengths should produce different outputs (except 0 == 32 zeros)
        unique_results = set(results.values())
        assert len(unique_results) >= len(salt_lengths) - 1
    
    def test_hkdf_extract_various_ikm_lengths(self):
        """Test HKDF-Extract with various IKM lengths."""
        salt = b"test_salt"
        
        ikm_lengths = [1, 16, 32, 64, 128, 256, 512]
        results = {}
        
        for length in ikm_lengths:
            ikm = b"I" * length
            prk = hkdf_extract(salt, ikm)
            results[length] = prk
            
            # All should produce 32-byte output
            assert len(prk) == 32
        
        # Different IKM lengths should produce different outputs
        unique_results = set(results.values())
        assert len(unique_results) == len(ikm_lengths)
    
    def test_hkdf_extract_edge_cases(self):
        """Test HKDF-Extract edge cases."""
        # Minimum inputs
        prk_min = hkdf_extract(b"", b"\x01")
        assert len(prk_min) == 32
        
        # Maximum reasonable inputs
        large_salt = secrets.token_bytes(1024)
        large_ikm = secrets.token_bytes(1024)
        prk_large = hkdf_extract(large_salt, large_ikm)
        assert len(prk_large) == 32
        
        # All-zero inputs
        prk_zeros = hkdf_extract(b"\x00" * 32, b"\x00" * 32)
        assert len(prk_zeros) == 32
        
        # All-ones inputs
        prk_ones = hkdf_extract(b"\xFF" * 32, b"\xFF" * 32)
        assert len(prk_ones) == 32
        
        # These should all be different
        assert prk_min != prk_large != prk_zeros != prk_ones


class TestHKDFExpandFunction:
    """Test HKDF-Expand function thoroughly."""
    
    @pytest.fixture
    def test_prk(self):
        """Generate a test PRK for expand tests."""
        return hkdf_extract(b"test_salt", b"test_ikm")
    
    def test_hkdf_expand_basic_functionality(self, test_prk):
        """Test basic HKDF-Expand functionality."""
        info = b"test_info"
        length = 32
        
        okm = hkdf_expand(test_prk, info, length)
        
        assert len(okm) == length
        assert isinstance(okm, bytes)
        
        # Should be deterministic
        okm2 = hkdf_expand(test_prk, info, length)
        assert okm == okm2
    
    def test_hkdf_expand_various_lengths(self, test_prk):
        """Test HKDF-Expand with various output lengths."""
        info = b"test_info"
        
        lengths = [1, 16, 32, 48, 64, 128, 255, 256, 512, 1024]
        results = {}
        
        for length in lengths:
            okm = hkdf_expand(test_prk, info, length)
            results[length] = okm
            
            assert len(okm) == length
        
        # Longer outputs should contain shorter outputs as prefix
        assert results[16] == results[32][:16]
        assert results[32] == results[64][:32]
        assert results[64] == results[128][:64]
    
    def test_hkdf_expand_maximum_length(self, test_prk):
        """Test HKDF-Expand with maximum allowed length."""
        max_length = 255 * 32  # 8160 bytes
        
        okm = hkdf_expand(test_prk, b"", max_length)
        assert len(okm) == max_length
        
        # Should fail for length > max
        with pytest.raises(ValueError, match="Cannot expand to more than"):
            hkdf_expand(test_prk, b"", max_length + 1)
    
    def test_hkdf_expand_zero_length(self, test_prk):
        """Test HKDF-Expand with zero length."""
        okm = hkdf_expand(test_prk, b"test", 0)
        assert okm == b""
        assert len(okm) == 0
    
    def test_hkdf_expand_different_info(self, test_prk):
        """Test HKDF-Expand with different info parameters."""
        length = 32
        
        info_values = [
            b"",
            b"a",
            b"test_info",
            b"different_info",
            b"very_long_info_parameter_that_is_quite_lengthy",
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
            b"\xFF" * 32
        ]
        
        results = {}
        for info in info_values:
            okm = hkdf_expand(test_prk, info, length)
            results[info] = okm
            assert len(okm) == length
        
        # Different info should produce different outputs
        unique_results = set(results.values())
        assert len(unique_results) == len(info_values)
    
    def test_hkdf_expand_invalid_inputs(self, test_prk):
        """Test HKDF-Expand with invalid inputs."""
        # Invalid length (too large)
        with pytest.raises(ValueError):
            hkdf_expand(test_prk, b"", 255 * 32 + 1)
        
        # Invalid PRK (wrong size)
        with pytest.raises(Exception):
            hkdf_expand(b"short_prk", b"", 32)
    
    def test_hkdf_expand_block_boundary_behavior(self, test_prk):
        """Test HKDF-Expand behavior at block boundaries."""
        # SHA256 has 32-byte blocks
        info = b"block_test"
        
        # Test outputs at block boundaries
        for length in [31, 32, 33, 63, 64, 65, 95, 96, 97]:
            okm = hkdf_expand(test_prk, info, length)
            assert len(okm) == length
            
            # Verify consistency across boundaries
            if length > 32:
                okm_prev = hkdf_expand(test_prk, info, 32)
                assert okm[:32] == okm_prev


class TestHKDFCompleteFunction:
    """Test complete HKDF function (Extract + Expand)."""
    
    def test_hkdf_complete_basic(self):
        """Test complete HKDF functionality."""
        ikm = b"input_keying_material"
        salt = b"salt_value"
        info = b"application_info"
        length = 32
        
        okm = hkdf(ikm, salt, info, length)
        
        assert len(okm) == length
        assert isinstance(okm, bytes)
        
        # Should be deterministic
        okm2 = hkdf(ikm, salt, info, length)
        assert okm == okm2
    
    def test_hkdf_complete_equivalence(self):
        """Test that complete HKDF equals separate Extract+Expand."""
        ikm = b"input_keying_material"
        salt = b"salt_value"
        info = b"application_info"
        length = 64
        
        # Complete HKDF
        okm_complete = hkdf(ikm, salt, info, length)
        
        # Separate Extract + Expand
        prk = hkdf_extract(salt, ikm)
        okm_separate = hkdf_expand(prk, info, length)
        
        assert okm_complete == okm_separate
    
    def test_hkdf_complete_default_parameters(self):
        """Test HKDF with default parameters."""
        ikm = b"input_keying_material"
        
        # Default salt (empty), info (empty), length (32)
        okm1 = hkdf(ikm)
        okm2 = hkdf(ikm, b"", b"", 32)
        
        assert okm1 == okm2
        assert len(okm1) == 32
    
    def test_hkdf_complete_parameter_sensitivity(self):
        """Test that HKDF is sensitive to all parameters."""
        base_ikm = b"input_keying_material"
        base_salt = b"salt_value"
        base_info = b"application_info"
        base_length = 32
        
        # Base case
        okm_base = hkdf(base_ikm, base_salt, base_info, base_length)
        
        # Change each parameter
        okm_ikm = hkdf(base_ikm + b"x", base_salt, base_info, base_length)
        okm_salt = hkdf(base_ikm, base_salt + b"x", base_info, base_length)
        okm_info = hkdf(base_ikm, base_salt, base_info + b"x", base_length)
        okm_length = hkdf(base_ikm, base_salt, base_info, base_length + 1)
        
        # All should be different
        results = [okm_base, okm_ikm, okm_salt, okm_info, okm_length[:base_length]]
        unique_results = set(results)
        assert len(unique_results) == len(results)


class TestHKDFSecurityProperties:
    """Test security properties of HKDF implementation."""
    
    def test_hkdf_pseudorandomness(self):
        """Test that HKDF outputs appear pseudorandom."""
        ikm = b"test_input_keying_material"
        salt = b"test_salt"
        info = b"test_info"
        
        # Generate multiple outputs
        outputs = []
        for i in range(100):
            test_info = info + str(i).encode()
            okm = hkdf(ikm, salt, test_info, 32)
            outputs.append(okm)
        
        # Check for uniqueness (should be very high)
        unique_outputs = set(outputs)
        assert len(unique_outputs) == len(outputs)
        
        # Basic entropy check: count unique bytes across all outputs
        all_bytes = b''.join(outputs)
        unique_bytes = len(set(all_bytes))
        assert unique_bytes > 200  # Should see good byte distribution
    
    def test_hkdf_avalanche_effect(self):
        """Test that small input changes cause large output changes."""
        base_ikm = b"test_input_keying_material"
        salt = b"test_salt"
        info = b"test_info"
        
        okm_base = hkdf(base_ikm, salt, info, 32)
        
        # Change one bit in IKM
        modified_ikm = bytearray(base_ikm)
        modified_ikm[0] ^= 0x01  # Flip one bit
        okm_modified = hkdf(bytes(modified_ikm), salt, info, 32)
        
        # Count differing bits
        diff_bits = 0
        for b1, b2 in zip(okm_base, okm_modified):
            diff_bits += bin(b1 ^ b2).count('1')
        
        # Should have approximately 50% bit difference (avalanche effect)
        total_bits = 32 * 8
        diff_ratio = diff_bits / total_bits
        assert 0.3 < diff_ratio < 0.7  # Allow some variance
    
    def test_hkdf_key_independence(self):
        """Test that keys derived with different info are independent."""
        ikm = b"master_key_material"
        salt = b"common_salt"
        
        # Derive multiple keys with different info
        keys = {}
        for i in range(20):
            info = f"key_purpose_{i}".encode()
            key = hkdf(ikm, salt, info, 32)
            keys[i] = key
        
        # All keys should be unique
        unique_keys = set(keys.values())
        assert len(unique_keys) == len(keys)
        
        # No key should be predictable from others
        # (This is a basic check - full analysis would require more sophisticated tests)
        key_bytes = list(keys.values())
        for i, key in enumerate(key_bytes):
            for j, other_key in enumerate(key_bytes):
                if i != j:
                    # Keys should not have obvious relationships
                    xor_result = bytes(a ^ b for a, b in zip(key, other_key))
                    # XOR should not be all zeros or all ones
                    assert xor_result != b'\x00' * 32
                    assert xor_result != b'\xFF' * 32
    
    def test_hkdf_deterministic_behavior(self):
        """Test that HKDF is deterministic across multiple calls."""
        ikm = b"test_input"
        salt = b"test_salt"
        info = b"test_info"
        length = 64
        
        # Generate same key multiple times
        keys = []
        for _ in range(10):
            key = hkdf(ikm, salt, info, length)
            keys.append(key)
        
        # All should be identical
        assert all(key == keys[0] for key in keys)
        assert len(set(keys)) == 1


class TestHKDFPerformanceAndLimits:
    """Test HKDF performance characteristics and limits."""
    
    def test_hkdf_performance_scaling(self):
        """Test that HKDF performance scales reasonably with output length."""
        ikm = b"performance_test_input"
        salt = b"perf_salt"
        info = b"perf_info"
        
        import time
        
        lengths = [32, 64, 128, 256, 512, 1024]
        times = {}
        
        for length in lengths:
            start_time = time.perf_counter()
            for _ in range(100):  # Average over multiple runs
                hkdf(ikm, salt, info, length)
            end_time = time.perf_counter()
            times[length] = (end_time - start_time) / 100
        
        # Performance should scale roughly linearly with output length
        # (Allow for some overhead and variation)
        ratio_32_1024 = times[1024] / times[32]
        assert ratio_32_1024 < 50  # Should not be more than 50x slower for 32x more output
    
    def test_hkdf_memory_efficiency(self):
        """Test that HKDF doesn't use excessive memory."""
        ikm = b"memory_test_input"
        salt = b"mem_salt"
        info = b"mem_info"
        
        # Generate large output without using excessive memory
        large_output = hkdf(ikm, salt, info, 4096)  # 4KB output
        assert len(large_output) == 4096
        
        # Should be able to generate very large outputs
        very_large_output = hkdf(ikm, salt, info, 255 * 32)  # Maximum allowed
        assert len(very_large_output) == 255 * 32
    
    def test_hkdf_input_size_limits(self):
        """Test HKDF with various input sizes."""
        # Very small inputs
        small_okm = hkdf(b"a", b"b", b"c", 1)
        assert len(small_okm) == 1
        
        # Large inputs
        large_ikm = secrets.token_bytes(10000)  # 10KB IKM
        large_salt = secrets.token_bytes(1000)  # 1KB salt
        large_info = secrets.token_bytes(1000)  # 1KB info
        
        large_okm = hkdf(large_ikm, large_salt, large_info, 256)
        assert len(large_okm) == 256
    
    @pytest.mark.slow
    def test_hkdf_stress_test(self):
        """Stress test HKDF with many derivations."""
        base_ikm = b"stress_test_input"
        salt = b"stress_salt"
        
        # Generate many keys quickly
        keys = set()
        for i in range(1000):
            info = f"stress_key_{i}".encode()
            key = hkdf(base_ikm, salt, info, 32)
            keys.add(key)
        
        # All keys should be unique
        assert len(keys) == 1000
        
        # No obvious patterns in the keys
        key_list = list(keys)
        first_bytes = [key[0] for key in key_list]
        unique_first_bytes = len(set(first_bytes))
        assert unique_first_bytes > 100  # Should have good distribution


@pytest.mark.crypto
class TestHKDFStarknetSpecific:
    """Test HKDF usage specific to Starknet key derivation."""
    
    def test_hkdf_starknet_key_material_length(self):
        """Test that HKDF generates proper length material for Starknet keys."""
        ikm = b"starknet_master_seed"
        salt = b"starknet_salt"
        info = b"starknet_private_key_v1"
        
        # Starknet private keys need 32 bytes (256 bits)
        key_material = hkdf(ikm, salt, info, 32)
        assert len(key_material) == 32
        
        # Convert to integer for Starknet validation
        key_int = int.from_bytes(key_material, 'big')
        assert 0 <= key_int < 2**256
    
    def test_hkdf_starknet_user_isolation(self):
        """Test that HKDF provides proper user isolation for Starknet."""
        master_seed = secrets.token_bytes(32)
        
        # Different users should get different keys
        user_keys = {}
        for user_id in range(10):
            username = f"user_{user_id}"
            salt = hashlib.sha256(f"starknet_user_{username}_0".encode()).digest()
            info = b"starknet_private_key_v1_attempt_0"
            
            key_material = hkdf(master_seed, salt, info, 32)
            user_keys[user_id] = key_material
        
        # All keys should be unique
        unique_keys = set(user_keys.values())
        assert len(unique_keys) == len(user_keys)
    
    def test_hkdf_starknet_key_index_isolation(self):
        """Test that different key indices produce different keys."""
        master_seed = secrets.token_bytes(32)
        username = "test_user"
        
        # Different key indices should produce different keys
        key_indices = {}
        for key_index in range(10):
            salt = hashlib.sha256(f"starknet_user_{username}_{key_index}".encode()).digest()
            info = b"starknet_private_key_v1_attempt_0"
            
            key_material = hkdf(master_seed, salt, info, 32)
            key_indices[key_index] = key_material
        
        # All keys should be unique
        unique_keys = set(key_indices.values())
        assert len(unique_keys) == len(key_indices)
    
    def test_hkdf_starknet_attempt_determinism(self):
        """Test that HKDF attempts are deterministic but different."""
        master_seed = secrets.token_bytes(32)
        username = "test_user"
        key_index = 0
        
        salt = hashlib.sha256(f"starknet_user_{username}_{key_index}".encode()).digest()
        
        # Different attempts should produce different outputs
        attempts = {}
        for attempt in range(10):
            info = f"starknet_private_key_v1_attempt_{attempt}".encode()
            key_material = hkdf(master_seed, salt, info, 32)
            attempts[attempt] = key_material
        
        # All attempts should be unique
        unique_attempts = set(attempts.values())
        assert len(unique_attempts) == len(attempts)
        
        # But each attempt should be deterministic
        for attempt in range(10):
            info = f"starknet_private_key_v1_attempt_{attempt}".encode()
            key_material2 = hkdf(master_seed, salt, info, 32)
            assert key_material2 == attempts[attempt]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])