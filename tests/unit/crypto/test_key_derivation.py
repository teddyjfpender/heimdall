"""
Comprehensive tests for user private key derivation system.

This module tests the derive_user_private_key function and related functionality
for correctness, performance, and security properties.
"""

import hashlib
import secrets
import time
from typing import Dict, List, Set, Tuple
from unittest.mock import patch

import pytest

# Import the modules under test
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../application/starknet/enclave'))

from key_derivation import (
    derive_user_private_key,
    derive_multiple_user_keys,
    validate_starknet_private_key,
    validate_username,
    create_test_master_seed,
    calculate_key_derivation_probabilities,
    StarknetKeyDerivationError,
    InvalidUserNameError,
    KeyValidationError,
    STARK_ORDER,
    STARK_PRIME
)


class TestDeriveUserPrivateKey:
    """Test the core derive_user_private_key function."""
    
    @pytest.fixture
    def test_master_seed(self):
        """Provide a deterministic test master seed."""
        return create_test_master_seed(deterministic=True)
    
    @pytest.fixture
    def random_master_seed(self):
        """Provide a random master seed for non-deterministic tests."""
        return secrets.token_bytes(32)
    
    def test_derive_user_private_key_basic(self, test_master_seed):
        """Test basic key derivation functionality."""
        username = "test_user"
        
        private_key, attempt = derive_user_private_key(test_master_seed, username)
        
        # Should return valid Starknet private key
        assert isinstance(private_key, int)
        assert isinstance(attempt, int)
        assert validate_starknet_private_key(private_key)
        assert 0 <= attempt < 1000  # Within expected range
    
    def test_derive_user_private_key_deterministic(self, test_master_seed):
        """Test that key derivation is deterministic."""
        username = "deterministic_user"
        
        # Generate same key multiple times
        results = []
        for _ in range(10):
            private_key, attempt = derive_user_private_key(test_master_seed, username)
            results.append((private_key, attempt))
        
        # All results should be identical
        assert all(result == results[0] for result in results)
        assert len(set(results)) == 1
    
    def test_derive_user_private_key_different_users(self, test_master_seed):
        """Test that different users get different keys."""
        usernames = [f"user_{i:03d}" for i in range(20)]
        user_keys = {}
        
        for username in usernames:
            private_key, attempt = derive_user_private_key(test_master_seed, username)
            user_keys[username] = (private_key, attempt)
            assert validate_starknet_private_key(private_key)
        
        # All private keys should be unique
        private_keys = [key for key, _ in user_keys.values()]
        assert len(private_keys) == len(set(private_keys))
    
    def test_derive_user_private_key_different_key_indices(self, test_master_seed):
        """Test that different key indices produce different keys."""
        username = "multi_key_user"
        keys_by_index = {}
        
        for key_index in range(10):
            private_key, attempt = derive_user_private_key(
                test_master_seed, username, key_index
            )
            keys_by_index[key_index] = (private_key, attempt)
            assert validate_starknet_private_key(private_key)
        
        # All keys should be unique across indices
        all_keys = [key for key, _ in keys_by_index.values()]
        assert len(all_keys) == len(set(all_keys))
    
    def test_derive_user_private_key_invalid_master_seed(self):
        """Test key derivation with invalid master seeds."""
        username = "test_user"
        
        invalid_seeds = [
            None,
            b"",
            b"too_short",
            b"a" * 31,  # 31 bytes
            b"a" * 33,  # 33 bytes
            "not_bytes",
            123
        ]
        
        for invalid_seed in invalid_seeds:
            with pytest.raises((ValueError, TypeError)):
                derive_user_private_key(invalid_seed, username)
    
    def test_derive_user_private_key_invalid_usernames(self, test_master_seed):
        """Test key derivation with invalid usernames."""
        invalid_usernames = [
            "",  # Empty
            None,  # None
            123,  # Not string
            "a" * 256,  # Too long
            "user with spaces",  # Invalid characters
            "user@domain.com",  # Invalid characters
        ]
        
        for invalid_username in invalid_usernames:
            with pytest.raises((InvalidUserNameError, TypeError)):
                derive_user_private_key(test_master_seed, invalid_username)
    
    def test_derive_user_private_key_invalid_key_index(self, test_master_seed):
        """Test key derivation with invalid key indices."""
        username = "test_user"
        
        invalid_indices = [-1, -10, "not_int", None, 1.5]
        
        for invalid_index in invalid_indices:
            with pytest.raises((ValueError, TypeError)):
                derive_user_private_key(test_master_seed, username, invalid_index)
    
    def test_derive_user_private_key_max_attempts(self, test_master_seed):
        """Test custom max_attempts parameter."""
        username = "test_user"
        
        # Test with different max_attempts values
        for max_attempts in [10, 100, 500, 1000]:
            private_key, attempt = derive_user_private_key(
                test_master_seed, username, max_attempts=max_attempts
            )
            assert validate_starknet_private_key(private_key)
            assert attempt <= max_attempts
    
    def test_derive_user_private_key_fallback_mechanism(self):
        """Test that fallback mechanism always produces valid keys."""
        # Create a seed that's likely to require fallback for some users
        test_seed = secrets.token_bytes(32)
        
        # Test many users to increase chance of hitting fallback
        for i in range(100):
            username = f"fallback_user_{i:03d}"
            private_key, attempt = derive_user_private_key(
                test_seed, username, max_attempts=10  # Low attempts to force fallback
            )
            
            # Should always produce valid key, even with fallback
            assert validate_starknet_private_key(private_key)
            assert attempt <= 10  # Should not exceed max_attempts
    
    def test_derive_user_private_key_attempt_statistics(self, random_master_seed):
        """Test that attempt statistics align with theoretical expectations."""
        attempt_counts = []
        
        # Generate keys for many users to get statistical data
        for i in range(200):
            username = f"stats_user_{i:04d}"
            _, attempt = derive_user_private_key(random_master_seed, username)
            attempt_counts.append(attempt)
        
        # Calculate statistics
        avg_attempts = sum(attempt_counts) / len(attempt_counts)
        fallback_count = sum(1 for a in attempt_counts if a == 1000)
        
        # Expected attempts based on STARK curve properties
        expected_avg = 32  # Approximately 1 / (1/32) where 1/32 is success probability
        
        # Allow reasonable variance but check it's in expected range
        assert 10 < avg_attempts < 100  # Should be reasonable
        assert fallback_count < len(attempt_counts) * 0.1  # Less than 10% fallback


class TestDeriveMultipleUserKeys:
    """Test the derive_multiple_user_keys function."""
    
    @pytest.fixture
    def test_master_seed(self):
        """Provide a deterministic test master seed."""
        return create_test_master_seed(deterministic=True)
    
    def test_derive_multiple_user_keys_basic(self, test_master_seed):
        """Test basic multiple key derivation."""
        username = "multi_key_user"
        num_keys = 5
        
        keys = derive_multiple_user_keys(test_master_seed, username, num_keys)
        
        assert len(keys) == num_keys
        assert all(len(key_tuple) == 3 for key_tuple in keys)
        
        for i, (private_key, key_index, attempt) in enumerate(keys):
            assert isinstance(private_key, int)
            assert isinstance(key_index, int)
            assert isinstance(attempt, int)
            assert validate_starknet_private_key(private_key)
            assert key_index == i  # Should be sequential
    
    def test_derive_multiple_user_keys_starting_index(self, test_master_seed):
        """Test multiple key derivation with custom starting index."""
        username = "indexed_user"
        num_keys = 3
        starting_index = 10
        
        keys = derive_multiple_user_keys(
            test_master_seed, username, num_keys, starting_index
        )
        
        assert len(keys) == num_keys
        
        for i, (private_key, key_index, attempt) in enumerate(keys):
            assert validate_starknet_private_key(private_key)
            assert key_index == starting_index + i
    
    def test_derive_multiple_user_keys_uniqueness(self, test_master_seed):
        """Test that multiple keys for same user are unique."""
        username = "unique_keys_user"
        num_keys = 20
        
        keys = derive_multiple_user_keys(test_master_seed, username, num_keys)
        
        # All private keys should be unique
        private_keys = [key for key, _, _ in keys]
        assert len(private_keys) == len(set(private_keys))
        
        # Key indices should be sequential and unique
        key_indices = [index for _, index, _ in keys]
        assert key_indices == list(range(num_keys))
    
    def test_derive_multiple_user_keys_consistency(self, test_master_seed):
        """Test that multiple key derivation is consistent with single derivation."""
        username = "consistency_user"
        num_keys = 5
        
        # Derive multiple keys at once
        multi_keys = derive_multiple_user_keys(test_master_seed, username, num_keys)
        
        # Derive same keys individually
        single_keys = []
        for i in range(num_keys):
            private_key, attempt = derive_user_private_key(
                test_master_seed, username, i
            )
            single_keys.append((private_key, i, attempt))
        
        # Results should be identical
        assert multi_keys == single_keys
    
    def test_derive_multiple_user_keys_invalid_inputs(self, test_master_seed):
        """Test multiple key derivation with invalid inputs."""
        username = "test_user"
        
        # Invalid num_keys
        with pytest.raises(ValueError):
            derive_multiple_user_keys(test_master_seed, username, 0)
        
        with pytest.raises(ValueError):
            derive_multiple_user_keys(test_master_seed, username, -1)
        
        with pytest.raises(ValueError):
            derive_multiple_user_keys(test_master_seed, username, 1001)  # Too many
        
        # Invalid starting_index
        with pytest.raises(ValueError):
            derive_multiple_user_keys(test_master_seed, username, 5, -1)
    
    def test_derive_multiple_user_keys_performance(self, test_master_seed):
        """Test performance of multiple key derivation."""
        username = "perf_user"
        num_keys = 100
        
        start_time = time.perf_counter()
        keys = derive_multiple_user_keys(test_master_seed, username, num_keys)
        end_time = time.perf_counter()
        
        duration = end_time - start_time
        keys_per_second = num_keys / duration
        
        # Should be reasonably fast
        assert keys_per_second > 10  # At least 10 keys per second
        assert all(validate_starknet_private_key(key) for key, _, _ in keys)


class TestKeyDerivationSecurity:
    """Test security properties of key derivation."""
    
    @pytest.fixture
    def test_master_seed(self):
        """Provide a deterministic test master seed."""
        return create_test_master_seed(deterministic=True)
    
    def test_key_derivation_master_seed_isolation(self):
        """Test that different master seeds produce completely different key spaces."""
        username = "isolation_user"
        
        # Generate two different master seeds
        seed1 = secrets.token_bytes(32)
        seed2 = secrets.token_bytes(32)
        
        # Derive keys for same user with different seeds
        key1, _ = derive_user_private_key(seed1, username)
        key2, _ = derive_user_private_key(seed2, username)
        
        # Keys should be different
        assert key1 != key2
        assert validate_starknet_private_key(key1)
        assert validate_starknet_private_key(key2)
    
    def test_key_derivation_username_sensitivity(self, test_master_seed):
        """Test that small username changes produce different keys."""
        base_username = "sensitive_user"
        
        # Generate variations of the username
        username_variations = [
            base_username,
            base_username + "1",
            base_username.upper(),
            base_username.replace("_", "-"),
            base_username + "x"
        ]
        
        keys = {}
        for username in username_variations:
            try:
                private_key, _ = derive_user_private_key(test_master_seed, username)
                keys[username] = private_key
            except InvalidUserNameError:
                # Some variations might be invalid, skip them
                continue
        
        # All valid keys should be different
        unique_keys = set(keys.values())
        assert len(unique_keys) == len(keys)
    
    def test_key_derivation_avalanche_effect(self, test_master_seed):
        """Test that small changes in inputs cause large changes in outputs."""
        username = "avalanche_user"
        
        # Base key
        base_key, _ = derive_user_private_key(test_master_seed, username, 0)
        
        # Key with different index
        index_key, _ = derive_user_private_key(test_master_seed, username, 1)
        
        # Convert to bytes for bit comparison
        base_bytes = base_key.to_bytes(32, 'big')
        index_bytes = index_key.to_bytes(32, 'big')
        
        # Count differing bits
        diff_bits = 0
        for b1, b2 in zip(base_bytes, index_bytes):
            diff_bits += bin(b1 ^ b2).count('1')
        
        # Should have significant bit difference (avalanche effect)
        total_bits = 32 * 8
        diff_ratio = diff_bits / total_bits
        assert 0.3 < diff_ratio < 0.7  # Approximately 50% difference expected
    
    def test_key_derivation_no_patterns(self, test_master_seed):
        """Test that derived keys don't exhibit obvious patterns."""
        keys = []
        
        # Generate many keys
        for i in range(100):
            username = f"pattern_user_{i:03d}"
            private_key, _ = derive_user_private_key(test_master_seed, username)
            keys.append(private_key)
        
        # All keys should be unique
        assert len(keys) == len(set(keys))
        
        # Convert to bytes for pattern analysis
        key_bytes = [key.to_bytes(32, 'big') for key in keys]
        
        # Check first bytes for distribution
        first_bytes = [kb[0] for kb in key_bytes]
        unique_first_bytes = len(set(first_bytes))
        assert unique_first_bytes > 50  # Should have good distribution
        
        # Check that keys don't follow arithmetic progression
        diffs = [keys[i+1] - keys[i] for i in range(len(keys)-1)]
        unique_diffs = len(set(diffs))
        assert unique_diffs > len(diffs) * 0.8  # Most differences should be unique
    
    def test_key_derivation_timing_consistency(self, test_master_seed):
        """Test that key derivation timing is reasonably consistent."""
        username = "timing_user"
        times = []
        
        # Measure derivation times
        for i in range(50):
            start_time = time.perf_counter()
            derive_user_private_key(test_master_seed, f"{username}_{i}")
            end_time = time.perf_counter()
            times.append(end_time - start_time)
        
        # Calculate timing statistics
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        
        # Timing should be reasonably consistent
        # (Allow for some variation due to different attempt counts)
        assert max_time < avg_time * 10  # Max shouldn't be more than 10x average
        assert min_time > 0  # All should take some time


class TestKeyDerivationEdgeCases:
    """Test edge cases and error conditions in key derivation."""
    
    @pytest.fixture
    def test_master_seed(self):
        """Provide a deterministic test master seed."""
        return create_test_master_seed(deterministic=True)
    
    def test_key_derivation_extreme_usernames(self, test_master_seed):
        """Test key derivation with extreme but valid usernames."""
        extreme_usernames = [
            "a",  # Single character
            "A" * 255,  # Maximum length
            "user.with.many.dots",
            "user-with-many-hyphens",
            "user_with_many_underscores",
            "MixedCaseUserName123",
            "123456789",  # All digits
        ]
        
        keys = {}
        for username in extreme_usernames:
            private_key, attempt = derive_user_private_key(test_master_seed, username)
            keys[username] = private_key
            assert validate_starknet_private_key(private_key)
        
        # All keys should be unique
        unique_keys = set(keys.values())
        assert len(unique_keys) == len(keys)
    
    def test_key_derivation_high_key_indices(self, test_master_seed):
        """Test key derivation with high key indices."""
        username = "high_index_user"
        high_indices = [100, 1000, 10000, 100000, 2**20]
        
        keys = {}
        for key_index in high_indices:
            private_key, attempt = derive_user_private_key(
                test_master_seed, username, key_index
            )
            keys[key_index] = private_key
            assert validate_starknet_private_key(private_key)
        
        # All keys should be unique
        unique_keys = set(keys.values())
        assert len(unique_keys) == len(keys)
    
    def test_key_derivation_max_attempts_zero(self, test_master_seed):
        """Test key derivation with max_attempts=0 (should use fallback)."""
        username = "zero_attempts_user"
        
        private_key, attempt = derive_user_private_key(
            test_master_seed, username, max_attempts=0
        )
        
        # Should still produce valid key via fallback
        assert validate_starknet_private_key(private_key)
        assert attempt == 0  # Should indicate fallback was used
    
    def test_key_derivation_reproducibility_across_runs(self, test_master_seed):
        """Test that key derivation is reproducible across separate runs."""
        username = "reproducible_user"
        key_index = 42
        
        # Generate key multiple times in separate "runs"
        keys = []
        for run in range(10):
            # Simulate separate process by not reusing any state
            private_key, attempt = derive_user_private_key(
                test_master_seed, username, key_index
            )
            keys.append((private_key, attempt))
        
        # All runs should produce identical results
        assert all(key == keys[0] for key in keys)
    
    def test_key_derivation_memory_cleanup(self, test_master_seed):
        """Test that key derivation doesn't leave sensitive data in memory."""
        username = "memory_test_user"
        
        # This is a basic test - in practice, memory analysis would be more complex
        import gc
        
        before_objects = len(gc.get_objects())
        
        # Derive many keys
        for i in range(100):
            derive_user_private_key(test_master_seed, f"{username}_{i}")
        
        # Force garbage collection
        gc.collect()
        
        after_objects = len(gc.get_objects())
        
        # Should not have created excessive persistent objects
        object_growth = after_objects - before_objects
        assert object_growth < 1000  # Reasonable threshold


class TestKeyDerivationProbabilities:
    """Test the key derivation probability calculations."""
    
    def test_calculate_key_derivation_probabilities_basic(self):
        """Test basic probability calculations."""
        probs = calculate_key_derivation_probabilities(1000)
        
        # Check expected fields are present
        required_fields = [
            'single_attempt_rejection_probability',
            'single_attempt_success_probability',
            'fallback_probability',
            'expected_attempts',
            'max_attempts'
        ]
        
        for field in required_fields:
            assert field in probs
            assert isinstance(probs[field], (int, float))
        
        # Check probability values are reasonable
        assert 0 <= probs['single_attempt_rejection_probability'] <= 1
        assert 0 <= probs['single_attempt_success_probability'] <= 1
        assert probs['single_attempt_rejection_probability'] + probs['single_attempt_success_probability'] == 1
        
        # Expected values based on STARK curve
        assert abs(probs['single_attempt_rejection_probability'] - 31/32) < 0.001
        assert abs(probs['single_attempt_success_probability'] - 1/32) < 0.001
    
    def test_calculate_key_derivation_probabilities_different_attempts(self):
        """Test probability calculations with different max_attempts values."""
        attempt_values = [10, 100, 500, 1000, 2000]
        
        for max_attempts in attempt_values:
            probs = calculate_key_derivation_probabilities(max_attempts)
            
            assert probs['max_attempts'] == max_attempts
            
            # Fallback probability should decrease with more attempts
            assert 0 <= probs['fallback_probability'] <= 1
            
            # Expected attempts should be consistent regardless of max_attempts
            assert abs(probs['expected_attempts'] - 32) < 1  # Should be approximately 32
    
    def test_calculate_key_derivation_probabilities_validation(self):
        """Test that probability calculations are mathematically consistent."""
        probs = calculate_key_derivation_probabilities(1000)
        
        # Single attempt probabilities should sum to 1
        total_prob = (probs['single_attempt_rejection_probability'] + 
                     probs['single_attempt_success_probability'])
        assert abs(total_prob - 1.0) < 1e-10
        
        # Expected attempts should match theoretical value
        success_prob = probs['single_attempt_success_probability']
        theoretical_expected = 1 / success_prob
        assert abs(probs['expected_attempts'] - theoretical_expected) < 0.001
        
        # Fallback probability should match theoretical calculation
        rejection_prob = probs['single_attempt_rejection_probability']
        theoretical_fallback = rejection_prob ** probs['max_attempts']
        assert abs(probs['fallback_probability'] - theoretical_fallback) < 1e-10


@pytest.mark.slow
class TestKeyDerivationPerformance:
    """Performance tests for key derivation (marked as slow)."""
    
    def test_key_derivation_performance_baseline(self):
        """Establish performance baseline for key derivation."""
        master_seed = create_test_master_seed(deterministic=True)
        
        # Measure time to derive 1000 keys
        start_time = time.perf_counter()
        
        for i in range(1000):
            username = f"perf_user_{i:04d}"
            private_key, _ = derive_user_private_key(master_seed, username)
            assert validate_starknet_private_key(private_key)
        
        end_time = time.perf_counter()
        duration = end_time - start_time
        keys_per_second = 1000 / duration
        
        # Should be reasonably fast (adjust threshold based on expected performance)
        assert keys_per_second > 50  # At least 50 keys per second
        
        print(f"Key derivation performance: {keys_per_second:.1f} keys/second")
    
    def test_key_derivation_scaling(self):
        """Test how key derivation performance scales."""
        master_seed = create_test_master_seed(deterministic=True)
        
        key_counts = [10, 50, 100, 500]
        performance_results = {}
        
        for key_count in key_counts:
            start_time = time.perf_counter()
            
            for i in range(key_count):
                username = f"scale_user_{key_count}_{i:04d}"
                derive_user_private_key(master_seed, username)
            
            end_time = time.perf_counter()
            duration = end_time - start_time
            keys_per_second = key_count / duration
            performance_results[key_count] = keys_per_second
        
        # Performance should be roughly consistent (not degrade significantly)
        min_performance = min(performance_results.values())
        max_performance = max(performance_results.values())
        
        # Performance variance should be reasonable
        assert max_performance / min_performance < 3  # Less than 3x difference
    
    def test_key_derivation_concurrent_simulation(self):
        """Test key derivation under simulated concurrent load."""
        import threading
        import queue
        
        master_seed = create_test_master_seed(deterministic=True)
        results_queue = queue.Queue()
        
        def derive_keys_worker(worker_id: int, num_keys: int):
            """Worker function to derive keys."""
            worker_results = []
            for i in range(num_keys):
                username = f"concurrent_user_{worker_id}_{i:03d}"
                try:
                    private_key, attempt = derive_user_private_key(master_seed, username)
                    worker_results.append((private_key, attempt, True))
                except Exception as e:
                    worker_results.append((None, None, False))
            results_queue.put(worker_results)
        
        # Simulate concurrent access with multiple threads
        num_workers = 10
        keys_per_worker = 20
        threads = []
        
        start_time = time.perf_counter()
        
        for worker_id in range(num_workers):
            thread = threading.Thread(
                target=derive_keys_worker, 
                args=(worker_id, keys_per_worker)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.perf_counter()
        
        # Collect all results
        all_results = []
        while not results_queue.empty():
            worker_results = results_queue.get()
            all_results.extend(worker_results)
        
        # Verify all operations succeeded
        successful_results = [r for r in all_results if r[2]]
        assert len(successful_results) == num_workers * keys_per_worker
        
        # Verify all keys are valid and unique
        private_keys = [r[0] for r in successful_results]
        assert all(validate_starknet_private_key(key) for key in private_keys)
        assert len(private_keys) == len(set(private_keys))  # All unique
        
        # Performance should still be reasonable under concurrent load
        total_keys = len(successful_results)
        duration = end_time - start_time
        keys_per_second = total_keys / duration
        assert keys_per_second > 20  # Should maintain reasonable performance


if __name__ == "__main__":
    pytest.main([__file__, "-v"])