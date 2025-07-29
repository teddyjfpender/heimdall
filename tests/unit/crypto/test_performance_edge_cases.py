"""
Comprehensive performance tests and edge case validation for crypto operations.

This module contains stress tests, performance benchmarks, and edge case
validation for all cryptographic operations in the Heimdall system.
"""

import gc
import os
import secrets
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import pytest

try:
    import psutil
except ImportError:
    psutil = None


# Import the modules under test
from application.starknet.enclave.key_derivation import (
    StarknetMultiUserKeyManager,
    create_test_master_seed,
    derive_multiple_user_keys,
    derive_user_private_key,
    hkdf,
    hkdf_expand,
    hkdf_extract,
)


class TestPerformanceBenchmarks:
    """Performance benchmark tests for cryptographic operations."""

    @pytest.fixture
    def test_master_seed(self):
        """Provide a deterministic test master seed."""
        return create_test_master_seed(deterministic=True)

    def test_hkdf_performance_baseline(self):
        """Establish performance baseline for HKDF operations."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        info = b"performance_test"

        # Measure HKDF extract performance
        extract_times = []
        for _ in range(1000):
            start_time = time.perf_counter()
            hkdf_extract(salt, ikm)
            end_time = time.perf_counter()
            extract_times.append(end_time - start_time)

        # Measure HKDF expand performance
        prk = hkdf_extract(salt, ikm)
        expand_times = []
        for _ in range(1000):
            start_time = time.perf_counter()
            hkdf_expand(prk, info, 32)
            end_time = time.perf_counter()
            expand_times.append(end_time - start_time)

        # Measure complete HKDF performance
        complete_times = []
        for _ in range(1000):
            start_time = time.perf_counter()
            hkdf(ikm, salt, info, 32)
            end_time = time.perf_counter()
            complete_times.append(end_time - start_time)

        # Calculate statistics
        extract_avg = statistics.mean(extract_times)
        expand_avg = statistics.mean(expand_times)
        complete_avg = statistics.mean(complete_times)

        # Performance assertions (adjust based on expected performance)
        assert extract_avg < 0.001  # Should be under 1ms
        assert expand_avg < 0.001  # Should be under 1ms
        assert complete_avg < 0.002  # Should be under 2ms

        print(f"HKDF Extract avg: {extract_avg*1000:.2f}ms")
        print(f"HKDF Expand avg: {expand_avg*1000:.2f}ms")
        print(f"HKDF Complete avg: {complete_avg*1000:.2f}ms")

    def test_key_derivation_performance_scaling(self, test_master_seed):
        """Test how key derivation performance scales with number of operations."""
        user_counts = [10, 50, 100, 500, 1000]
        performance_results = {}

        for user_count in user_counts:
            start_time = time.perf_counter()

            for i in range(user_count):
                username = f"perf_user_{i:04d}"
                derive_user_private_key(test_master_seed, username)

            end_time = time.perf_counter()
            duration = end_time - start_time
            keys_per_second = user_count / duration
            performance_results[user_count] = keys_per_second

            print(f"Users: {user_count}, Keys/sec: {keys_per_second:.1f}")

        # Performance should not degrade dramatically with scale
        min_performance = min(performance_results.values())
        max_performance = max(performance_results.values())

        # Allow some variance but should be reasonable
        performance_ratio = max_performance / min_performance
        assert (
            performance_ratio < 5.0
        ), f"Performance degradation too severe: {performance_ratio}"

        # All should meet minimum performance threshold
        for count, perf in performance_results.items():
            assert perf > 10, f"Performance too slow for {count} users: {perf} keys/sec"

    def test_multiple_key_derivation_performance(self, test_master_seed):
        """Test performance of deriving multiple keys for single user."""
        username = "multi_key_perf_user"
        key_counts = [1, 5, 10, 20, 50, 100]

        performance_results = {}

        for key_count in key_counts:
            start_time = time.perf_counter()
            derive_multiple_user_keys(test_master_seed, username, key_count)
            end_time = time.perf_counter()

            duration = end_time - start_time
            keys_per_second = key_count / duration
            performance_results[key_count] = keys_per_second

            print(f"Keys: {key_count}, Keys/sec: {keys_per_second:.1f}")

        # Performance should scale reasonably
        for count, perf in performance_results.items():
            assert (
                perf > 20
            ), f"Multi-key performance too slow for {count} keys: {perf} keys/sec"

    def test_key_manager_caching_performance(self, test_master_seed):
        """Test performance benefit of key manager caching."""
        manager = StarknetMultiUserKeyManager(test_master_seed)
        username = "cache_perf_user"

        # First derivation (not cached)
        start_time = time.perf_counter()
        key1, addr1 = manager.derive_user_key(username)
        first_time = time.perf_counter() - start_time

        # Second derivation (should be cached)
        start_time = time.perf_counter()
        key2, addr2 = manager.derive_user_key(username)
        second_time = time.perf_counter() - start_time

        # Results should be identical
        assert key1 == key2
        assert addr1 == addr2

        # Second call should be faster (cached)
        cache_speedup = first_time / second_time if second_time > 0 else float("inf")
        print(f"Cache speedup: {cache_speedup:.1f}x")

        # Cache should provide significant speedup
        assert cache_speedup > 2, f"Cache speedup insufficient: {cache_speedup}x"


@pytest.mark.skipif(psutil is None, reason="psutil not installed")
class TestMemoryUsageAndLeaks:
    """Test memory usage and potential memory leaks."""

    def get_memory_usage(self):
        """Get current memory usage in MB."""
        if psutil is None:
            pytest.skip("psutil not installed")
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024  # Convert to MB

    def test_hkdf_memory_usage(self):
        """Test HKDF memory usage patterns."""
        initial_memory = self.get_memory_usage()

        # Generate many HKDF outputs
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        for i in range(1000):
            info = f"memory_test_{i}".encode()
            output = hkdf(ikm, salt, info, 32)

            # Use the output to prevent optimization
            assert len(output) == 32

        # Force garbage collection
        gc.collect()

        final_memory = self.get_memory_usage()
        memory_growth = final_memory - initial_memory

        # Memory growth should be minimal
        assert memory_growth < 10, f"Excessive memory growth: {memory_growth:.1f} MB"
        print(f"HKDF memory growth: {memory_growth:.1f} MB")

    def test_key_derivation_memory_scaling(self):
        """Test memory usage scaling with key derivation."""
        master_seed = create_test_master_seed(deterministic=True)
        initial_memory = self.get_memory_usage()

        # Derive many keys
        keys = []
        for i in range(1000):
            username = f"memory_user_{i:04d}"
            private_key, _ = derive_user_private_key(master_seed, username)
            keys.append(private_key)

        mid_memory = self.get_memory_usage()

        # Clear keys and force garbage collection
        keys.clear()
        gc.collect()

        final_memory = self.get_memory_usage()

        # Calculate memory usage
        peak_growth = mid_memory - initial_memory
        final_growth = final_memory - initial_memory

        print(f"Peak memory growth: {peak_growth:.1f} MB")
        print(f"Final memory growth: {final_growth:.1f} MB")

        # Memory should be reasonable
        assert peak_growth < 50, f"Peak memory usage too high: {peak_growth:.1f} MB"
        assert final_growth < 20, f"Memory leak detected: {final_growth:.1f} MB"

    def test_key_manager_memory_cleanup(self):
        """Test that key manager properly cleans up memory."""
        initial_memory = self.get_memory_usage()

        # Create and use many key managers
        managers = []
        for i in range(50):
            master_seed = secrets.token_bytes(32)
            manager = StarknetMultiUserKeyManager(master_seed)

            # Use the manager
            for j in range(10):
                username = f"cleanup_user_{i}_{j}"
                manager.derive_user_key(username)

            managers.append(manager)

        mid_memory = self.get_memory_usage()

        # Clean up managers
        for manager in managers:
            manager.clear_cache()
            del manager

        managers.clear()
        gc.collect()

        final_memory = self.get_memory_usage()

        # Calculate memory usage
        peak_growth = mid_memory - initial_memory
        final_growth = final_memory - initial_memory

        print(f"Peak memory growth: {peak_growth:.1f} MB")
        print(f"Final memory growth after cleanup: {final_growth:.1f} MB")

        # Memory should be cleaned up reasonably well
        assert peak_growth < 100, f"Peak memory usage too high: {peak_growth:.1f} MB"
        assert final_growth < 30, f"Insufficient memory cleanup: {final_growth:.1f} MB"


class TestConcurrencyAndThreadSafety:
    """Test concurrent access and thread safety."""

    def test_concurrent_hkdf_operations(self):
        """Test HKDF operations under concurrent access."""
        base_ikm = secrets.token_bytes(32)
        base_salt = secrets.token_bytes(32)

        def hkdf_worker(worker_id: int) -> List[bytes]:
            """Worker that performs HKDF operations."""
            results = []
            for i in range(100):
                info = f"concurrent_worker_{worker_id}_{i}".encode()
                output = hkdf(base_ikm, base_salt, info, 32)
                results.append(output)
            return results

        # Run concurrent workers
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(hkdf_worker, i) for i in range(10)]
            all_results = []

            for future in as_completed(futures):
                results = future.result()
                all_results.extend(results)

        # All results should be unique (different info strings)
        assert len(all_results) == 1000
        assert len(set(all_results)) == 1000

        # All results should be valid
        for result in all_results:
            assert len(result) == 32
            assert isinstance(result, bytes)

    def test_concurrent_key_derivation(self):
        """Test key derivation under concurrent access."""
        master_seed = create_test_master_seed(deterministic=True)

        def key_derivation_worker(worker_id: int) -> Dict[str, int]:
            """Worker that derives keys for multiple users."""
            keys = {}
            for i in range(50):
                username = f"concurrent_user_{worker_id}_{i:03d}"
                private_key, _ = derive_user_private_key(master_seed, username)
                keys[username] = private_key
            return keys

        # Run concurrent workers
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(key_derivation_worker, i) for i in range(8)]
            all_keys = {}

            for future in as_completed(futures):
                worker_keys = future.result()
                all_keys.update(worker_keys)

        # All keys should be unique
        assert len(all_keys) == 400  # 8 workers * 50 keys each
        unique_keys = set(all_keys.values())
        assert len(unique_keys) == 400

        # Verify deterministic behavior by re-deriving some keys
        test_usernames = list(all_keys.keys())[:10]
        for username in test_usernames:
            expected_key = all_keys[username]
            actual_key, _ = derive_user_private_key(master_seed, username)
            assert actual_key == expected_key

    def test_concurrent_key_manager_access(self):
        """Test key manager under concurrent access."""
        master_seed = create_test_master_seed(deterministic=True)
        manager = StarknetMultiUserKeyManager(master_seed)

        def manager_worker(worker_id: int) -> Dict[str, Tuple[int, int]]:
            """Worker that uses key manager concurrently."""
            results = {}
            for i in range(30):
                username = f"manager_user_{worker_id}_{i:03d}"
                private_key, address = manager.derive_user_key(username)
                results[username] = (private_key, address)
            return results

        # Run concurrent workers
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(manager_worker, i) for i in range(5)]
            all_results = {}

            for future in as_completed(futures):
                worker_results = future.result()
                all_results.update(worker_results)

        # All results should be unique
        assert len(all_results) == 150  # 5 workers * 30 users each

        all_keys = [key for key, _ in all_results.values()]
        all_addresses = [addr for _, addr in all_results.values()]

        assert len(set(all_keys)) == 150
        assert len(set(all_addresses)) == 150

        # Test that caching worked correctly by re-accessing
        test_username = list(all_results.keys())[0]
        expected_key, expected_addr = all_results[test_username]
        actual_key, actual_addr = manager.derive_user_key(test_username)

        assert actual_key == expected_key
        assert actual_addr == expected_addr

    def test_concurrent_user_validation_timing(self):
        """Test timing consistency under concurrent validation."""
        master_seed = create_test_master_seed(deterministic=True)
        manager = StarknetMultiUserKeyManager(master_seed)

        # Setup test data
        username = "timing_validation_user"
        valid_key, _ = manager.derive_user_key(username)
        invalid_key = valid_key + 1

        def validation_worker(key: int, expected: bool) -> List[float]:
            """Worker that performs key validations and measures timing."""
            times = []
            for _ in range(100):
                start_time = time.perf_counter()
                result = manager.validate_user_key(username, key)
                end_time = time.perf_counter()

                assert result == expected
                times.append(end_time - start_time)
            return times

        # Run concurrent validation workers
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Mix of valid and invalid validations
            futures = [
                executor.submit(validation_worker, valid_key, True),
                executor.submit(validation_worker, invalid_key, False),
                executor.submit(validation_worker, valid_key, True),
                executor.submit(validation_worker, invalid_key, False),
            ]

            all_times = []
            for future in as_completed(futures):
                times = future.result()
                all_times.extend(times)

        # Calculate timing statistics
        mean_time = statistics.mean(all_times)
        max_time = max(all_times)
        min_time = min(all_times)

        # Timing should be reasonably consistent even under concurrent load
        timing_ratio = max_time / min_time if min_time > 0 else float("inf")
        assert timing_ratio < 10, f"Concurrent timing too inconsistent: {timing_ratio}"

        print(
            f"Concurrent validation timing - Mean: {mean_time*1000:.2f}ms, "
            f"Min: {min_time*1000:.2f}ms, Max: {max_time*1000:.2f}ms"
        )


class TestEdgeCasesAndLimits:
    """Test edge cases and system limits."""

    def test_hkdf_maximum_output_length(self):
        """Test HKDF with maximum allowed output length."""
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        info = b"max_length_test"

        # Maximum length for SHA256 is 255 * 32 = 8160 bytes
        max_length = 255 * 32

        start_time = time.perf_counter()
        output = hkdf(ikm, salt, info, max_length)
        end_time = time.perf_counter()

        assert len(output) == max_length

        # Should complete in reasonable time
        generation_time = end_time - start_time
        assert (
            generation_time < 1.0
        ), f"Max length HKDF too slow: {generation_time:.3f}s"

        print(
            f"Max HKDF output ({max_length} bytes) generated in {generation_time*1000:.1f}ms"
        )

    def test_hkdf_with_large_inputs(self):
        """Test HKDF with very large input materials."""
        # Very large IKM (10KB)
        large_ikm = secrets.token_bytes(10240)
        large_salt = secrets.token_bytes(1024)
        large_info = b"x" * 1024

        start_time = time.perf_counter()
        output = hkdf(large_ikm, large_salt, large_info, 64)
        end_time = time.perf_counter()

        assert len(output) == 64

        # Should handle large inputs efficiently
        generation_time = end_time - start_time
        assert (
            generation_time < 0.1
        ), f"Large input HKDF too slow: {generation_time:.3f}s"

        print(f"Large input HKDF completed in {generation_time*1000:.1f}ms")

    def test_key_derivation_with_extreme_usernames(self):
        """Test key derivation with extreme but valid usernames."""
        master_seed = create_test_master_seed(deterministic=True)

        extreme_usernames = [
            "a",  # Single character
            "A" * 255,  # Maximum length
            "user." + "x" * 248,  # Near maximum with dots
            "user-" + "y" * 248,  # Near maximum with hyphens
            "user_" + "z" * 248,  # Near maximum with underscores
            "1234567890" * 25 + "12345",  # All digits
            "ABCDEFGHIJ" * 25 + "ABCDE",  # All caps
            "abcdefghij" * 25 + "abcde",  # All lowercase
        ]

        derived_keys = {}
        derivation_times = []

        for username in extreme_usernames:
            start_time = time.perf_counter()
            private_key, attempt = derive_user_private_key(master_seed, username)
            end_time = time.perf_counter()

            derived_keys[username] = private_key
            derivation_times.append(end_time - start_time)

            # Each key should be valid
            from key_derivation import validate_starknet_private_key

            assert validate_starknet_private_key(private_key)

        # All keys should be unique
        unique_keys = set(derived_keys.values())
        assert len(unique_keys) == len(extreme_usernames)

        # Derivation times should be reasonable
        max_time = max(derivation_times)
        mean_time = statistics.mean(derivation_times)

        assert max_time < 1.0, f"Extreme username derivation too slow: {max_time:.3f}s"
        print(
            f"Extreme usernames - Max time: {max_time*1000:.1f}ms, "
            f"Mean time: {mean_time*1000:.1f}ms"
        )

    def test_key_derivation_with_high_indices(self):
        """Test key derivation with very high key indices."""
        master_seed = create_test_master_seed(deterministic=True)
        username = "high_index_user"

        high_indices = [1000, 10000, 100000, 1000000, 2**20, 2**24]
        derived_keys = {}

        for key_index in high_indices:
            start_time = time.perf_counter()
            private_key, attempt = derive_user_private_key(
                master_seed, username, key_index
            )
            end_time = time.perf_counter()

            derived_keys[key_index] = private_key

            # Should be valid and complete in reasonable time
            from key_derivation import validate_starknet_private_key

            assert validate_starknet_private_key(private_key)
            assert (end_time - start_time) < 1.0

        # All keys should be unique
        unique_keys = set(derived_keys.values())
        assert len(unique_keys) == len(high_indices)

    def test_key_manager_with_many_users(self):
        """Test key manager performance with many users."""
        master_seed = create_test_master_seed(deterministic=True)
        manager = StarknetMultiUserKeyManager(master_seed)

        num_users = 10000

        start_time = time.perf_counter()

        # Derive keys for many users
        user_keys = {}
        for i in range(num_users):
            username = f"mass_user_{i:06d}"
            private_key, address = manager.derive_user_key(username)
            user_keys[username] = (private_key, address)

            # Progress indication
            if (i + 1) % 1000 == 0:
                elapsed = time.perf_counter() - start_time
                rate = (i + 1) / elapsed
                print(f"Generated {i+1} keys in {elapsed:.1f}s ({rate:.1f} keys/sec)")

        end_time = time.perf_counter()
        total_time = end_time - start_time
        keys_per_second = num_users / total_time

        print(
            f"Generated {num_users} keys in {total_time:.1f}s ({keys_per_second:.1f} keys/sec)"
        )

        # Performance should be reasonable
        assert (
            keys_per_second > 100
        ), f"Mass key generation too slow: {keys_per_second} keys/sec"

        # All keys should be unique
        all_private_keys = [key for key, _ in user_keys.values()]
        all_addresses = [addr for _, addr in user_keys.values()]

        assert len(set(all_private_keys)) == num_users
        assert len(set(all_addresses)) == num_users

    def test_memory_pressure_handling(self):
        """Test behavior under memory pressure."""
        # This test creates memory pressure and verifies the system handles it gracefully
        initial_memory = self.get_memory_usage()

        # Create memory pressure with large data structures
        large_data = []
        try:
            # Gradually increase memory usage
            for i in range(100):
                # Create 1MB chunks
                chunk = bytearray(1024 * 1024)  # 1MB
                large_data.append(chunk)

                # Test key operations under memory pressure
                if i % 10 == 0:
                    master_seed = create_test_master_seed(deterministic=True)
                    manager = StarknetMultiUserKeyManager(master_seed)

                    # Derive a few keys
                    for j in range(5):
                        username = f"pressure_user_{i}_{j}"
                        private_key, address = manager.derive_user_key(username)

                        # Should still work correctly
                        from key_derivation import validate_starknet_private_key

                        assert validate_starknet_private_key(private_key)

                    # Clean up manager
                    del manager
                    gc.collect()

                current_memory = self.get_memory_usage()
                memory_growth = current_memory - initial_memory

                # Stop if we've used too much memory (avoid OOM)
                if memory_growth > 500:  # 500MB limit
                    break

            print(f"Memory pressure test completed with {memory_growth:.1f}MB growth")

        finally:
            # Clean up large data
            large_data.clear()
            gc.collect()

            final_memory = self.get_memory_usage()
            final_growth = final_memory - initial_memory

            print(f"Final memory growth after cleanup: {final_growth:.1f}MB")

    def get_memory_usage(self):
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024


class TestRobustnessAndReliability:
    """Test system robustness and reliability under various conditions."""

    def test_error_recovery_in_key_derivation(self):
        """Test error recovery in key derivation operations."""
        master_seed = create_test_master_seed(deterministic=True)

        # Test with various error conditions
        error_conditions = [
            (None, "valid_user", ValueError),  # Invalid master seed
            (b"short", "valid_user", ValueError),  # Short master seed
            (master_seed, "", InvalidUserNameError),  # Empty username
            (master_seed, "x" * 256, InvalidUserNameError),  # Long username
        ]

        for seed, username, expected_error in error_conditions:
            pass

            with pytest.raises(expected_error):
                derive_user_private_key(seed, username)

        # System should still work normally after errors
        valid_key, _ = derive_user_private_key(master_seed, "recovery_user")
        from key_derivation import validate_starknet_private_key

        assert validate_starknet_private_key(valid_key)

    def test_deterministic_behavior_across_restarts(self):
        """Test that key derivation is deterministic across 'restarts'."""
        master_seed = create_test_master_seed(deterministic=True)

        # Simulate multiple "sessions" or "restarts"
        session_results = []

        for session in range(5):
            # Create fresh manager for each session
            manager = StarknetMultiUserKeyManager(master_seed)

            session_keys = {}
            for i in range(20):
                username = f"restart_user_{i:03d}"
                private_key, address = manager.derive_user_key(username)
                session_keys[username] = (private_key, address)

            session_results.append(session_keys)

            # Clean up
            del manager
            gc.collect()

        # All sessions should produce identical results
        first_session = session_results[0]
        for session_keys in session_results[1:]:
            assert session_keys == first_session

        print(f"Deterministic behavior verified across {len(session_results)} sessions")

    def test_statistical_properties_validation(self):
        """Test that derived keys maintain good statistical properties."""
        master_seed = create_test_master_seed(deterministic=False)  # Random seed

        # Derive many keys
        keys = []
        for i in range(1000):
            username = f"stats_user_{i:04d}"
            private_key, _ = derive_user_private_key(master_seed, username)
            keys.append(private_key)

        # All keys should be unique
        assert len(keys) == len(set(keys))

        # Convert to bytes for statistical analysis
        key_bytes = b"".join(key.to_bytes(32, "big") for key in keys)

        # Test byte frequency distribution
        byte_counts = [0] * 256
        for byte in key_bytes:
            byte_counts[byte] += 1

        # Calculate chi-square statistic for uniformity test
        total_bytes = len(key_bytes)
        expected_count = total_bytes / 256

        chi_square = sum(
            (count - expected_count) ** 2 / expected_count for count in byte_counts
        )

        # Chi-square should not be too extreme (rough test)
        degrees_freedom = 255
        assert (
            chi_square < degrees_freedom * 3
        ), f"Poor byte distribution: chi-square = {chi_square}"

        # Test bit balance
        bit_counts = [0, 0]  # [0-bits, 1-bits]
        for byte in key_bytes:
            for bit_pos in range(8):
                bit = (byte >> bit_pos) & 1
                bit_counts[bit] += 1

        total_bits = sum(bit_counts)
        ones_ratio = bit_counts[1] / total_bits

        # Should be approximately 50% ones
        assert 0.45 < ones_ratio < 0.55, f"Poor bit balance: {ones_ratio:.3f}"

        print(
            f"Statistical validation passed - Chi-square: {chi_square:.1f}, "
            f"Bit balance: {ones_ratio:.3f}"
        )

    def test_fallback_mechanism_reliability(self):
        """Test reliability of the fallback mechanism in key derivation."""
        master_seed = create_test_master_seed(deterministic=True)

        # Force fallback by using very low max_attempts
        fallback_keys = []
        for i in range(100):
            username = f"fallback_user_{i:03d}"
            private_key, attempt = derive_user_private_key(
                master_seed, username, max_attempts=1  # Force fallback
            )

            fallback_keys.append(private_key)

            # Key should still be valid even with fallback
            from key_derivation import validate_starknet_private_key

            assert validate_starknet_private_key(private_key)

            # Attempt should indicate fallback was used (attempt == max_attempts)
            assert attempt == 1

        # All fallback keys should be unique
        assert len(fallback_keys) == len(set(fallback_keys))

        # Fallback keys should be identical to normal derivation
        for i in range(10):  # Test subset for performance
            username = f"fallback_user_{i:03d}"
            expected_key = fallback_keys[i]

            # Derive with normal parameters
            normal_key, _ = derive_user_private_key(master_seed, username)

            # Should be identical (deterministic)
            assert normal_key == expected_key

        print(f"Fallback mechanism reliability verified for {len(fallback_keys)} keys")


@pytest.mark.slow
class TestStressTestsAndLoadTesting:
    """Stress tests and load testing (marked as slow)."""

    def test_sustained_load_key_derivation(self):
        """Test key derivation under sustained load."""
        master_seed = create_test_master_seed(deterministic=True)

        # Run sustained load for a period of time
        duration_seconds = 30
        start_time = time.perf_counter()

        keys_generated = 0
        while time.perf_counter() - start_time < duration_seconds:
            username = f"load_user_{keys_generated:06d}"
            private_key, _ = derive_user_private_key(master_seed, username)

            # Verify key is valid
            from key_derivation import validate_starknet_private_key

            assert validate_starknet_private_key(private_key)

            keys_generated += 1

            # Progress indication
            if keys_generated % 1000 == 0:
                elapsed = time.perf_counter() - start_time
                rate = keys_generated / elapsed
                print(
                    f"Sustained load: {keys_generated} keys in {elapsed:.1f}s ({rate:.1f} keys/sec)"
                )

        end_time = time.perf_counter()
        actual_duration = end_time - start_time
        final_rate = keys_generated / actual_duration

        print(
            f"Sustained load completed: {keys_generated} keys in {actual_duration:.1f}s "
            f"({final_rate:.1f} keys/sec)"
        )

        # Should maintain reasonable performance under sustained load
        assert (
            final_rate > 50
        ), f"Sustained load performance too low: {final_rate} keys/sec"

    def test_high_concurrency_stress(self):
        """Test system under high concurrency stress."""
        master_seed = create_test_master_seed(deterministic=True)
        manager = StarknetMultiUserKeyManager(master_seed)

        num_threads = 20
        operations_per_thread = 100

        def stress_worker(worker_id: int) -> Dict[str, any]:
            """High-intensity worker function."""
            results = {
                "keys_derived": 0,
                "validations_performed": 0,
                "errors": 0,
                "start_time": time.perf_counter(),
            }

            try:
                for i in range(operations_per_thread):
                    # Derive key
                    username = f"stress_user_{worker_id}_{i:03d}"
                    private_key, address = manager.derive_user_key(username)
                    results["keys_derived"] += 1

                    # Validate key
                    is_valid = manager.validate_user_key(username, private_key)
                    assert is_valid is True
                    results["validations_performed"] += 1

                    # Cross-validate (should fail)
                    other_username = (
                        f"stress_user_{(worker_id+1) % num_threads}_{i:03d}"
                    )
                    cross_valid = manager.validate_user_key(other_username, private_key)
                    assert cross_valid is False
                    results["validations_performed"] += 1

            except Exception as e:
                results["errors"] += 1
                print(f"Worker {worker_id} error: {e}")

            results["end_time"] = time.perf_counter()
            return results

        # Run high concurrency stress test
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(stress_worker, i) for i in range(num_threads)]
            all_results = []

            for future in as_completed(futures):
                result = future.result()
                all_results.append(result)

        # Analyze results
        total_keys = sum(r["keys_derived"] for r in all_results)
        total_validations = sum(r["validations_performed"] for r in all_results)
        total_errors = sum(r["errors"] for r in all_results)

        # Calculate timing statistics
        worker_times = [r["end_time"] - r["start_time"] for r in all_results]
        max_worker_time = max(worker_times)
        min_worker_time = min(worker_times)

        print(f"High concurrency stress results:")
        print(f"  Keys derived: {total_keys}")
        print(f"  Validations: {total_validations}")
        print(f"  Errors: {total_errors}")
        print(f"  Worker time range: {min_worker_time:.1f}s - {max_worker_time:.1f}s")

        # Verify success
        expected_keys = num_threads * operations_per_thread
        expected_validations = num_threads * operations_per_thread * 2

        assert (
            total_keys == expected_keys
        ), f"Missing keys: {expected_keys - total_keys}"
        assert (
            total_validations == expected_validations
        ), f"Missing validations: {expected_validations - total_validations}"
        assert total_errors == 0, f"Unexpected errors: {total_errors}"

        # Worker times should be reasonably balanced
        time_ratio = (
            max_worker_time / min_worker_time if min_worker_time > 0 else float("inf")
        )
        assert time_ratio < 5, f"Worker time imbalance too high: {time_ratio}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not slow"])
