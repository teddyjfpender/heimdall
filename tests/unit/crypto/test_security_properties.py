"""
Comprehensive tests for security properties and timing attack resistance.

This module tests constant-time operations, timing attack resistance,
and other security properties of the cryptographic implementation.
"""

import hashlib
import secrets
import statistics
import time
from typing import List, Tuple
from unittest.mock import patch

import pytest

# Import the modules under test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../application/starknet/enclave'))

from key_derivation import (
    constant_time_compare,
    constant_time_int_compare,
    secure_compare_usernames,
    secure_zero_memory,
    StarknetMultiUserKeyManager,
    create_test_master_seed,
    STARK_ORDER
)


class TestConstantTimeComparisons:
    """Test constant-time comparison functions."""
    
    def test_constant_time_compare_basic(self):
        """Test basic constant-time byte comparison."""
        # Equal byte sequences
        data1 = b"hello_world_test_data"
        data2 = b"hello_world_test_data"
        assert constant_time_compare(data1, data2) is True
        
        # Different byte sequences
        data3 = b"hello_world_test_data"
        data4 = b"hello_world_test_diff"
        assert constant_time_compare(data3, data4) is False
        
        # Empty sequences
        assert constant_time_compare(b"", b"") is True
        assert constant_time_compare(b"", b"x") is False
    
    def test_constant_time_compare_different_lengths(self):
        """Test constant-time comparison with different lengths."""
        short_data = b"short"
        long_data = b"this_is_much_longer_data"
        
        # Different lengths should return False
        assert constant_time_compare(short_data, long_data) is False
        assert constant_time_compare(long_data, short_data) is False
        
        # Same length, different content
        data1 = b"same_length_data"
        data2 = b"same_length_diff"
        assert len(data1) == len(data2)
        assert constant_time_compare(data1, data2) is False
    
    def test_constant_time_compare_timing_consistency(self):
        """Test that constant-time comparison has consistent timing."""
        # Create test data
        data_length = 32
        base_data = secrets.token_bytes(data_length)
        
        # Create variations: identical, one bit different, all different
        identical_data = base_data
        one_bit_diff = bytearray(base_data)
        one_bit_diff[0] ^= 0x01  # Flip one bit
        one_bit_diff = bytes(one_bit_diff)
        
        all_different = bytes(~b & 0xFF for b in base_data)
        
        test_cases = [
            (base_data, identical_data, True),
            (base_data, one_bit_diff, False),
            (base_data, all_different, False)
        ]
        
        # Measure timing for each case
        times = {}
        iterations = 1000
        
        for i, (data1, data2, expected_result) in enumerate(test_cases):
            case_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                result = constant_time_compare(data1, data2)
                end_time = time.perf_counter()
                
                assert result == expected_result
                case_times.append(end_time - start_time)
            
            times[i] = case_times
        
        # Calculate statistics
        mean_times = [statistics.mean(times[i]) for i in range(3)]
        std_times = [statistics.stdev(times[i]) for i in range(3)]
        
        # Times should be similar across all cases (constant-time property)
        max_mean = max(mean_times)
        min_mean = min(mean_times)
        
        # Allow some variance but not too much
        timing_ratio = max_mean / min_mean if min_mean > 0 else float('inf')
        assert timing_ratio < 2.0, f"Timing ratio too high: {timing_ratio}"
    
    def test_constant_time_int_compare_basic(self):
        """Test basic constant-time integer comparison."""
        # Equal integers
        assert constant_time_int_compare(12345, 12345) is True
        assert constant_time_int_compare(0, 0) is True
        assert constant_time_int_compare(STARK_ORDER - 1, STARK_ORDER - 1) is True
        
        # Different integers
        assert constant_time_int_compare(12345, 12346) is False
        assert constant_time_int_compare(0, 1) is False
        assert constant_time_int_compare(STARK_ORDER - 1, STARK_ORDER - 2) is False
    
    def test_constant_time_int_compare_large_numbers(self):
        """Test constant-time integer comparison with large numbers."""
        # Large valid Starknet private keys
        large1 = 2**200 + 12345
        large2 = 2**200 + 12345
        large3 = 2**200 + 12346
        
        assert constant_time_int_compare(large1, large2) is True
        assert constant_time_int_compare(large1, large3) is False
        
        # Very large numbers (beyond 32 bytes)
        very_large1 = 2**300
        very_large2 = 2**300
        very_large3 = 2**300 + 1
        
        assert constant_time_int_compare(very_large1, very_large2) is True
        assert constant_time_int_compare(very_large1, very_large3) is False
    
    def test_constant_time_int_compare_edge_cases(self):
        """Test constant-time integer comparison edge cases."""
        # Negative numbers
        assert constant_time_int_compare(-1, -1) is False  # Should handle gracefully
        assert constant_time_int_compare(-1, 1) is False
        
        # Zero with positive
        assert constant_time_int_compare(0, 0) is True
        assert constant_time_int_compare(0, 1) is False
        
        # Numbers that would overflow byte conversion
        huge_num = 2**1000
        assert constant_time_int_compare(huge_num, huge_num) is False  # Too large for 32 bytes
    
    def test_constant_time_int_compare_timing_consistency(self):
        """Test timing consistency of integer comparison."""
        # Test with integers that differ in different ways
        base_int = 2**128 + 12345
        
        test_cases = [
            (base_int, base_int),  # Identical
            (base_int, base_int + 1),  # One bit different (low bits)
            (base_int, base_int + 2**64),  # Different high bits
            (base_int, base_int ^ (2**127)),  # MSB different
        ]
        
        times = []
        iterations = 500
        
        for case_a, case_b in test_cases:
            case_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                constant_time_int_compare(case_a, case_b)
                end_time = time.perf_counter()
                case_times.append(end_time - start_time)
            times.append(statistics.mean(case_times))
        
        # Timing should be consistent across cases
        max_time = max(times)
        min_time = min(times)
        timing_ratio = max_time / min_time if min_time > 0 else float('inf')
        
        # Allow some variance but should be reasonably consistent
        assert timing_ratio < 3.0, f"Integer comparison timing ratio too high: {timing_ratio}"


class TestSecureUsernameComparison:
    """Test secure username comparison functionality."""
    
    def test_secure_compare_usernames_basic(self):
        """Test basic secure username comparison."""
        # Identical usernames
        assert secure_compare_usernames("alice", "alice") is True
        assert secure_compare_usernames("bob123", "bob123") is True
        assert secure_compare_usernames("", "") is True
        
        # Different usernames
        assert secure_compare_usernames("alice", "alice2") is False
        assert secure_compare_usernames("bob", "Bob") is False  # Case sensitive
        assert secure_compare_usernames("alice", "bob") is False
    
    def test_secure_compare_usernames_case_sensitivity(self):
        """Test that username comparison is case-sensitive."""
        test_cases = [
            ("User", "user", False),
            ("USER", "user", False),
            ("Alice", "alice", False),
            ("Test123", "test123", False),
        ]
        
        for user1, user2, expected in test_cases:
            assert secure_compare_usernames(user1, user2) == expected
    
    def test_secure_compare_usernames_unicode_handling(self):
        """Test username comparison with unicode characters."""
        # Unicode usernames
        unicode_cases = [
            ("café", "café", True),
            ("café", "cafe", False),  # Different characters
            ("user🔑", "user🔑", True),
            ("user🔑", "user🗝️", False),
        ]
        
        for user1, user2, expected in unicode_cases:
            assert secure_compare_usernames(user1, user2) == expected
    
    def test_secure_compare_usernames_timing_consistency(self):
        """Test that username comparison has consistent timing."""
        base_username = "timing_test_user_12345"
        
        # Create test cases with different types of differences
        test_cases = [
            (base_username, base_username),  # Identical
            (base_username, base_username + "x"),  # One char added
            (base_username, base_username[:-1]),  # One char removed
            (base_username, base_username.replace("1", "2")),  # One char changed
            (base_username, "completely_different_username"),  # Completely different
        ]
        
        times = []
        iterations = 1000
        
        for user1, user2 in test_cases:
            case_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                secure_compare_usernames(user1, user2)
                end_time = time.perf_counter()
                case_times.append(end_time - start_time)
            times.append(statistics.mean(case_times))
        
        # Calculate timing consistency
        max_time = max(times)
        min_time = min(times)
        timing_ratio = max_time / min_time if min_time > 0 else float('inf')
        
        # Should have consistent timing (uses secrets.compare_digest internally)
        assert timing_ratio < 3.0, f"Username comparison timing ratio too high: {timing_ratio}"


class TestSecureMemoryOperations:
    """Test secure memory handling operations."""
    
    def test_secure_zero_memory_bytes(self):
        """Test secure memory zeroing with bytes."""
        # Create test data
        test_data = b"sensitive_data_to_be_zeroed"
        
        # Note: bytes are immutable in Python, so this mainly tests the function doesn't crash
        secure_zero_memory(test_data)
        
        # The original bytes object should be unchanged (immutable)
        assert test_data == b"sensitive_data_to_be_zeroed"
    
    def test_secure_zero_memory_bytearray(self):
        """Test secure memory zeroing with bytearray."""
        # Create mutable test data
        test_data = bytearray(b"sensitive_data_to_be_zeroed")
        original_length = len(test_data)
        
        # Zero the memory
        secure_zero_memory(test_data)
        
        # Data should be zeroed
        assert len(test_data) == original_length
        assert all(byte == 0 for byte in test_data)
        assert test_data == bytearray(b"\x00" * original_length)
    
    def test_secure_zero_memory_different_sizes(self):
        """Test secure memory zeroing with different data sizes."""
        sizes = [1, 16, 32, 64, 128, 256, 1024]
        
        for size in sizes:
            # Create test data
            test_data = bytearray(b"x" * size)
            
            # Verify initial state
            assert len(test_data) == size
            assert all(byte == ord('x') for byte in test_data)
            
            # Zero the memory
            secure_zero_memory(test_data)
            
            # Verify zeroed state
            assert len(test_data) == size
            assert all(byte == 0 for byte in test_data)
    
    def test_secure_zero_memory_empty_data(self):
        """Test secure memory zeroing with empty data."""
        # Empty bytes
        empty_bytes = b""
        secure_zero_memory(empty_bytes)  # Should not crash
        
        # Empty bytearray
        empty_bytearray = bytearray()
        secure_zero_memory(empty_bytearray)
        assert len(empty_bytearray) == 0


class TestKeyManagerTimingAttackResistance:
    """Test timing attack resistance in key manager operations."""
    
    @pytest.fixture
    def key_manager(self):
        """Create a key manager for testing."""
        master_seed = create_test_master_seed(deterministic=True)
        return StarknetMultiUserKeyManager(master_seed)
    
    def test_validate_user_key_timing_consistency(self, key_manager):
        """Test that user key validation has consistent timing."""
        username = "timing_test_user"
        
        # Derive a valid key for the user
        valid_key, _ = key_manager.derive_user_key(username)
        
        # Create invalid keys
        invalid_keys = [
            valid_key + 1,  # Close to valid key
            valid_key * 2,  # Different magnitude
            12345,  # Random valid Starknet key (but not for this user)
            STARK_ORDER - 1,  # Maximum valid key
        ]
        
        # Measure timing for valid key validation
        valid_times = []
        iterations = 100
        
        for _ in range(iterations):
            start_time = time.perf_counter()
            result = key_manager.validate_user_key(username, valid_key)
            end_time = time.perf_counter()
            
            assert result is True
            valid_times.append(end_time - start_time)
        
        # Measure timing for invalid key validations
        invalid_times_by_key = {}
        
        for invalid_key in invalid_keys:
            key_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                result = key_manager.validate_user_key(username, invalid_key)
                end_time = time.perf_counter()
                
                assert result is False
                key_times.append(end_time - start_time)
            
            invalid_times_by_key[invalid_key] = key_times
        
        # Calculate timing statistics
        valid_mean = statistics.mean(valid_times)
        invalid_means = [statistics.mean(times) for times in invalid_times_by_key.values()]
        
        all_means = [valid_mean] + invalid_means
        max_mean = max(all_means)
        min_mean = min(all_means)
        
        # Timing should be consistent (constant-time property)
        timing_ratio = max_mean / min_mean if min_mean > 0 else float('inf')
        
        # Allow reasonable variance but should not be dramatically different
        assert timing_ratio < 5.0, f"Key validation timing ratio too high: {timing_ratio}"
    
    def test_validate_user_key_different_usernames_timing(self, key_manager):
        """Test timing consistency across different usernames."""
        # Create several users with valid keys
        users_and_keys = []
        for i in range(5):
            username = f"timing_user_{i}"
            valid_key, _ = key_manager.derive_user_key(username)
            users_and_keys.append((username, valid_key))
        
        # Test cross-validation timing (wrong user for each key)
        cross_validation_times = []
        iterations = 50
        
        for _ in range(iterations):
            for i, (username, _) in enumerate(users_and_keys):
                # Use a different user's key
                other_user_key = users_and_keys[(i + 1) % len(users_and_keys)][1]
                
                start_time = time.perf_counter()
                result = key_manager.validate_user_key(username, other_user_key)
                end_time = time.perf_counter()
                
                assert result is False
                cross_validation_times.append(end_time - start_time)
        
        # All cross-validations should have similar timing
        if len(cross_validation_times) > 1:
            mean_time = statistics.mean(cross_validation_times)
            max_time = max(cross_validation_times)
            min_time = min(cross_validation_times)
            
            # Should have reasonable consistency
            timing_range_ratio = max_time / min_time if min_time > 0 else float('inf')
            assert timing_range_ratio < 10.0, "Cross-validation timing too inconsistent"
    
    def test_key_validation_error_path_timing(self, key_manager):
        """Test that error paths have consistent timing."""
        username = "error_timing_user"
        
        # Test various error conditions
        error_cases = [
            (None, "invalid_username"),  # Invalid username type
            ("", 12345),  # Empty username
            ("x" * 256, 12345),  # Username too long
            (username, -1),  # Invalid key (negative)
            (username, 0),  # Invalid key (zero)
            (username, STARK_ORDER),  # Invalid key (too large)
        ]
        
        error_times = []
        iterations = 50
        
        for error_username, error_key in error_cases:
            case_times = []
            for _ in range(iterations):
                start_time = time.perf_counter()
                try:
                    result = key_manager.validate_user_key(error_username, error_key)
                    # Should return False for invalid inputs
                    assert result is False
                except (TypeError, ValueError):
                    # Some cases might raise exceptions, which is also fine
                    pass
                end_time = time.perf_counter()
                case_times.append(end_time - start_time)
            
            if case_times:
                error_times.extend(case_times)
        
        # Error case timing should be reasonably consistent
        if len(error_times) > 1:
            mean_time = statistics.mean(error_times)
            max_time = max(error_times)
            min_time = min(error_times)
            
            timing_ratio = max_time / min_time if min_time > 0 else float('inf')
            assert timing_ratio < 10.0, "Error path timing too inconsistent"


class TestCryptographicIndependence:
    """Test cryptographic independence between users and operations."""
    
    def test_user_key_independence(self):
        """Test that user keys are cryptographically independent."""
        master_seed = create_test_master_seed(deterministic=True)
        key_manager = StarknetMultiUserKeyManager(master_seed)
        
        # Generate keys for multiple users
        users = [f"independence_user_{i:03d}" for i in range(20)]
        user_keys = {}
        
        for username in users:
            private_key, _ = key_manager.derive_user_key(username)
            user_keys[username] = private_key
        
        # All keys should be unique
        all_keys = list(user_keys.values())
        assert len(all_keys) == len(set(all_keys))
        
        # Test cross-validation (no user should validate another's key)
        for username, user_key in user_keys.items():
            # Should validate for correct user
            assert key_manager.validate_user_key(username, user_key) is True
            
            # Should not validate for other users
            for other_username in users:
                if other_username != username:
                    assert key_manager.validate_user_key(other_username, user_key) is False
    
    def test_key_index_independence(self):
        """Test that different key indices produce independent keys."""
        master_seed = create_test_master_seed(deterministic=True)
        key_manager = StarknetMultiUserKeyManager(master_seed)
        
        username = "multi_index_user"
        num_indices = 10
        
        # Generate keys for different indices
        keys_by_index = {}
        for key_index in range(num_indices):
            private_key, _ = key_manager.derive_user_key(username, key_index)
            keys_by_index[key_index] = private_key
        
        # All keys should be unique
        all_keys = list(keys_by_index.values())
        assert len(all_keys) == len(set(all_keys))
        
        # Test that keys have good cryptographic properties
        # Convert to bytes for analysis
        key_bytes = [key.to_bytes(32, 'big') for key in all_keys]
        
        # Should have good bit distribution
        all_bytes = b''.join(key_bytes)
        unique_bytes = len(set(all_bytes))
        assert unique_bytes > 100  # Good distribution
        
        # No obvious patterns between consecutive keys
        for i in range(len(all_keys) - 1):
            key1 = all_keys[i]
            key2 = all_keys[i + 1]
            
            # XOR should not be predictable
            xor_result = key1 ^ key2
            assert xor_result != 0  # Never identical
            assert xor_result != key1  # Not trivial relationship
            assert xor_result != key2  # Not trivial relationship
    
    def test_master_seed_independence(self):
        """Test that different master seeds create independent key spaces."""
        username = "seed_independence_user"
        
        # Create multiple master seeds
        seeds = [secrets.token_bytes(32) for _ in range(5)]
        key_managers = [StarknetMultiUserKeyManager(seed) for seed in seeds]
        
        # Derive keys for same user with different seeds
        keys_by_seed = []
        for manager in key_managers:
            private_key, _ = manager.derive_user_key(username)
            keys_by_seed.append(private_key)
        
        # All keys should be unique (different seeds -> different keys)
        assert len(keys_by_seed) == len(set(keys_by_seed))
        
        # Test that cross-validation fails (key from one seed shouldn't validate with another)
        for i, manager_i in enumerate(key_managers):
            key_i = keys_by_seed[i]
            
            # Should validate with correct manager
            assert manager_i.validate_user_key(username, key_i) is True
            
            # Should not validate with other managers
            for j, manager_j in enumerate(key_managers):
                if i != j:
                    assert manager_j.validate_user_key(username, key_i) is False


class TestEntropyAndRandomnessProperties:
    """Test entropy and randomness properties of cryptographic operations."""
    
    def test_derived_key_entropy(self):
        """Test that derived keys have good entropy properties."""
        master_seed = create_test_master_seed(deterministic=False)  # Random seed
        key_manager = StarknetMultiUserKeyManager(master_seed)
        
        # Generate many keys
        keys = []
        for i in range(200):
            username = f"entropy_user_{i:04d}"
            private_key, _ = key_manager.derive_user_key(username)
            keys.append(private_key)
        
        # All keys should be unique
        assert len(keys) == len(set(keys))
        
        # Convert to bytes for entropy analysis
        key_bytes = b''.join(key.to_bytes(32, 'big') for key in keys)
        
        # Count byte frequency
        byte_counts = [0] * 256
        for byte in key_bytes:
            byte_counts[byte] += 1
        
        # Should have reasonably uniform distribution
        total_bytes = len(key_bytes)
        expected_count = total_bytes / 256
        
        # Chi-square test approximation (simplified)
        chi_square = sum((count - expected_count) ** 2 / expected_count for count in byte_counts)
        degrees_freedom = 255
        
        # Should not be too far from expected (this is a rough test)
        assert chi_square < degrees_freedom * 2  # Allow reasonable variance
    
    def test_hkdf_randomness_properties(self):
        """Test randomness properties of HKDF outputs."""
        from key_derivation import hkdf
        
        master_seed = secrets.token_bytes(32)
        base_salt = b"randomness_test_salt"
        
        # Generate many HKDF outputs with different info
        outputs = []
        for i in range(100):
            info = f"randomness_test_info_{i:04d}".encode()
            output = hkdf(master_seed, base_salt, info, 32)
            outputs.append(output)
        
        # All outputs should be unique
        assert len(outputs) == len(set(outputs))
        
        # Test bit distribution
        all_bits = []
        for output in outputs:
            for byte in output:
                for bit_pos in range(8):
                    bit = (byte >> bit_pos) & 1
                    all_bits.append(bit)
        
        # Approximately 50% of bits should be 1
        ones_count = sum(all_bits)
        total_bits = len(all_bits)
        ones_ratio = ones_count / total_bits
        
        # Should be close to 0.5 (allow reasonable variance)
        assert 0.4 < ones_ratio < 0.6
    
    def test_address_derivation_randomness(self):
        """Test randomness properties of address derivation."""
        from key_derivation import derive_account_address_from_private_key
        
        # Generate addresses from sequential private keys
        addresses = []
        base_key = 12345
        
        for i in range(100):
            private_key = base_key + i * 1000  # Ensure valid keys
            if private_key < STARK_ORDER:
                address = derive_account_address_from_private_key(private_key)
                addresses.append(address)
        
        # All addresses should be unique
        assert len(addresses) == len(set(addresses))
        
        # Addresses should not follow obvious patterns
        # Test that consecutive addresses are not consecutive
        address_diffs = []
        for i in range(len(addresses) - 1):
            diff = abs(addresses[i + 1] - addresses[i])
            address_diffs.append(diff)
        
        # Differences should be large and varied
        min_diff = min(address_diffs)
        max_diff = max(address_diffs)
        
        assert min_diff > 1000  # Addresses should not be consecutive
        assert max_diff / min_diff > 10  # Should have varied differences


@pytest.mark.slow
class TestTimingAttackResistanceStress:
    """Stress tests for timing attack resistance (marked as slow)."""
    
    def test_large_scale_timing_consistency(self):
        """Test timing consistency at scale."""
        master_seed = create_test_master_seed(deterministic=True)
        key_manager = StarknetMultiUserKeyManager(master_seed)
        
        # Create many users with keys
        num_users = 100
        users_and_keys = []
        
        for i in range(num_users):
            username = f"scale_timing_user_{i:04d}"
            valid_key, _ = key_manager.derive_user_key(username)
            users_and_keys.append((username, valid_key))
        
        # Test timing for valid validations
        valid_times = []
        for username, valid_key in users_and_keys[:20]:  # Test subset for speed
            start_time = time.perf_counter()
            result = key_manager.validate_user_key(username, valid_key)
            end_time = time.perf_counter()
            
            assert result is True
            valid_times.append(end_time - start_time)
        
        # Test timing for invalid validations (cross-user)
        invalid_times = []
        for i, (username, _) in enumerate(users_and_keys[:20]):
            # Use different user's key
            other_key = users_and_keys[(i + 10) % num_users][1]
            
            start_time = time.perf_counter()
            result = key_manager.validate_user_key(username, other_key)
            end_time = time.perf_counter()
            
            assert result is False
            invalid_times.append(end_time - start_time)
        
        # Calculate timing statistics
        valid_mean = statistics.mean(valid_times)
        invalid_mean = statistics.mean(invalid_times)
        
        # Should have similar timing
        timing_ratio = max(valid_mean, invalid_mean) / min(valid_mean, invalid_mean)
        assert timing_ratio < 3.0, f"Large-scale timing ratio too high: {timing_ratio}"
    
    def test_concurrent_timing_attack_resistance(self):
        """Test timing attack resistance under concurrent load."""
        import threading
        import queue
        
        master_seed = create_test_master_seed(deterministic=True)
        key_manager = StarknetMultiUserKeyManager(master_seed)
        
        # Setup test data
        username = "concurrent_timing_user"
        valid_key, _ = key_manager.derive_user_key(username)
        invalid_key = valid_key + 1
        
        results_queue = queue.Queue()
        
        def timing_test_worker(worker_id: int, test_key: int, expected_result: bool):
            """Worker function for concurrent timing tests."""
            times = []
            for _ in range(50):
                start_time = time.perf_counter()
                result = key_manager.validate_user_key(username, test_key)
                end_time = time.perf_counter()
                
                assert result == expected_result
                times.append(end_time - start_time)
            
            results_queue.put((worker_id, statistics.mean(times)))
        
        # Start concurrent workers
        threads = []
        
        # Mix of valid and invalid key validations
        for i in range(10):
            test_key = valid_key if i % 2 == 0 else invalid_key
            expected = i % 2 == 0
            
            thread = threading.Thread(
                target=timing_test_worker,
                args=(i, test_key, expected)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Collect results
        worker_times = []
        while not results_queue.empty():
            worker_id, avg_time = results_queue.get()
            worker_times.append(avg_time)
        
        # Timing should be consistent across concurrent workers
        if len(worker_times) > 1:
            max_time = max(worker_times)
            min_time = min(worker_times)
            timing_ratio = max_time / min_time if min_time > 0 else float('inf')
            
            assert timing_ratio < 5.0, f"Concurrent timing ratio too high: {timing_ratio}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])