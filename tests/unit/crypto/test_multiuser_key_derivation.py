"""
Comprehensive tests for the multi-user Starknet key derivation system.

These tests validate the security, performance, and correctness of the
deterministic key derivation implementation.
"""

import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor, as_completed


from application.starknet.enclave.aws_multiuser_integration import (
    UserSessionError,
    validate_user_session,
)

# Import modules under test
from application.starknet.enclave.key_derivation import (
    STARK_ORDER,
    InvalidUserNameError,
    StarknetMultiUserKeyManager,
    create_test_master_seed,
    derive_user_private_key,
    generate_master_seed,
    hkdf,
    hkdf_expand,
    hkdf_extract,
    test_key_derivation_performance,
    validate_starknet_private_key,
    validate_username,
)

from ...fixtures.starknet_multiuser_factories import (
    create_concurrent_user_load_test,
    create_multi_user_key_derivation_scenario,
)


class TestHKDFImplementation(unittest.TestCase):
    """Test the HKDF implementation for correctness."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_ikm = b"test_input_keying_material"
        self.test_salt = b"test_salt"
        self.test_info = b"test_info"

    def test_hkdf_extract_basic(self):
        """Test basic HKDF-Extract functionality."""
        prk = hkdf_extract(self.test_salt, self.test_ikm)

        self.assertEqual(len(prk), 32)  # SHA256 output length
        self.assertIsInstance(prk, bytes)

        # Test deterministic behavior
        prk2 = hkdf_extract(self.test_salt, self.test_ikm)
        self.assertEqual(prk, prk2)

    def test_hkdf_expand_basic(self):
        """Test basic HKDF-Expand functionality."""
        prk = hkdf_extract(self.test_salt, self.test_ikm)
        okm = hkdf_expand(prk, self.test_info, 32)

        self.assertEqual(len(okm), 32)
        self.assertIsInstance(okm, bytes)

        # Test deterministic behavior
        okm2 = hkdf_expand(prk, self.test_info, 32)
        self.assertEqual(okm, okm2)

    def test_hkdf_expand_different_lengths(self):
        """Test HKDF-Expand with different output lengths."""
        prk = hkdf_extract(self.test_salt, self.test_ikm)

        for length in [16, 32, 48, 64]:
            okm = hkdf_expand(prk, self.test_info, length)
            self.assertEqual(len(okm), length)

    def test_hkdf_expand_max_length(self):
        """Test HKDF-Expand with maximum allowed length."""
        prk = hkdf_extract(self.test_salt, self.test_ikm)

        # Maximum length for SHA256 is 255 * 32 = 8160 bytes
        max_length = 255 * 32
        okm = hkdf_expand(prk, self.test_info, max_length)
        self.assertEqual(len(okm), max_length)

        # Test that exceeding max length raises error
        with self.assertRaises(ValueError):
            hkdf_expand(prk, self.test_info, max_length + 1)

    def test_hkdf_complete(self):
        """Test complete HKDF (extract + expand)."""
        okm = hkdf(self.test_ikm, self.test_salt, self.test_info, 32)

        self.assertEqual(len(okm), 32)
        self.assertIsInstance(okm, bytes)

        # Test deterministic behavior
        okm2 = hkdf(self.test_ikm, self.test_salt, self.test_info, 32)
        self.assertEqual(okm, okm2)

    def test_hkdf_empty_salt(self):
        """Test HKDF with empty salt (should use default)."""
        okm1 = hkdf(self.test_ikm, b"", self.test_info, 32)
        okm2 = hkdf(self.test_ikm, info=self.test_info, length=32)  # No salt specified

        self.assertEqual(okm1, okm2)


class TestUsernameValidation(unittest.TestCase):
    """Test username validation functionality."""

    def test_valid_usernames(self):
        """Test valid username formats."""
        valid_usernames = [
            "alice",
            "bob123",
            "user_with_underscores",
            "user-with-hyphens",
            "user.with.dots",
            "MixedCase123",
            "a" * 255,  # Maximum length
        ]

        for username in valid_usernames:
            with self.subTest(username=username):
                # Should not raise exception
                validate_username(username)

    def test_invalid_usernames(self):
        """Test invalid username formats."""
        invalid_usernames = [
            "",  # Empty
            "a" * 256,  # Too long
            "user with spaces",  # Spaces not allowed
            "user@domain.com",  # @ not allowed
            "user#hash",  # # not allowed
            "user/slash",  # / not allowed
            "user\\backslash",  # \ not allowed
        ]

        for username in invalid_usernames:
            with self.subTest(username=username):
                with self.assertRaises(InvalidUserNameError):
                    validate_username(username)


class TestStarknetKeyValidation(unittest.TestCase):
    """Test Starknet private key validation."""

    def test_valid_private_keys(self):
        """Test valid private key ranges."""
        valid_keys = [
            1,  # Minimum valid key
            STARK_ORDER // 2,  # Middle range
            STARK_ORDER - 1,  # Maximum valid key
        ]

        for key in valid_keys:
            with self.subTest(key=key):
                self.assertTrue(validate_starknet_private_key(key))

    def test_invalid_private_keys(self):
        """Test invalid private key ranges."""
        invalid_keys = [
            0,  # Zero not allowed
            -1,  # Negative not allowed
            STARK_ORDER,  # Equal to order not allowed
            STARK_ORDER + 1,  # Greater than order not allowed
        ]

        for key in invalid_keys:
            with self.subTest(key=key):
                self.assertFalse(validate_starknet_private_key(key))


class TestUserKeyDerivation(unittest.TestCase):
    """Test user-specific key derivation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.master_seed = create_test_master_seed(deterministic=True)
        self.test_username = "test_user_001"

    def test_deterministic_derivation(self):
        """Test that key derivation is deterministic."""
        key1, attempt1 = derive_user_private_key(self.master_seed, self.test_username)
        key2, attempt2 = derive_user_private_key(self.master_seed, self.test_username)

        self.assertEqual(key1, key2)
        self.assertEqual(attempt1, attempt2)

    def test_different_users_different_keys(self):
        """Test that different users get different keys."""
        user1 = "user1"
        user2 = "user2"

        key1, _ = derive_user_private_key(self.master_seed, user1)
        key2, _ = derive_user_private_key(self.master_seed, user2)

        self.assertNotEqual(key1, key2)

    def test_different_key_indices(self):
        """Test that different key indices produce different keys."""
        key1, _ = derive_user_private_key(self.master_seed, self.test_username, 0)
        key2, _ = derive_user_private_key(self.master_seed, self.test_username, 1)

        self.assertNotEqual(key1, key2)

    def test_derived_keys_valid(self):
        """Test that all derived keys are valid for Starknet."""
        for i in range(10):
            key, _ = derive_user_private_key(self.master_seed, f"user_{i}", 0)
            self.assertTrue(validate_starknet_private_key(key))

    def test_key_derivation_with_invalid_master_seed(self):
        """Test key derivation with invalid master seed."""
        invalid_seeds = [
            b"",  # Empty
            b"too_short",  # Too short
            b"a" * 31,  # 31 bytes
            b"a" * 33,  # 33 bytes
        ]

        for seed in invalid_seeds:
            with self.subTest(seed=seed):
                with self.assertRaises(ValueError):
                    derive_user_private_key(seed, self.test_username)

    def test_key_derivation_performance(self):
        """Test that key derivation is reasonably fast."""
        start_time = time.time()

        # Derive 100 keys
        for i in range(100):
            derive_user_private_key(self.master_seed, f"user_{i}")

        end_time = time.time()
        duration = end_time - start_time

        # Should complete within reasonable time (adjust as needed)
        self.assertLess(duration, 10.0)  # 10 seconds for 100 derivations

        # Log performance for manual inspection
        print(
            f"100 key derivations took {duration:.2f} seconds ({100/duration:.1f} keys/sec)"
        )


class TestMultiUserKeyManager(unittest.TestCase):
    """Test the multi-user key manager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.master_seed = create_test_master_seed(deterministic=True)
        self.manager = StarknetMultiUserKeyManager(self.master_seed)

    def test_manager_initialization(self):
        """Test manager initialization."""
        # Valid initialization
        manager = StarknetMultiUserKeyManager(self.master_seed)
        self.assertIsNotNone(manager)

        # Invalid initialization
        with self.assertRaises(ValueError):
            StarknetMultiUserKeyManager(b"invalid_seed")

    def test_derive_user_key(self):
        """Test user key derivation through manager."""
        username = "test_user"
        private_key, address = self.manager.derive_user_key(username)

        self.assertTrue(validate_starknet_private_key(private_key))
        self.assertIsInstance(address, int)
        self.assertGreater(address, 0)

    def test_get_multiple_user_keys(self):
        """Test deriving multiple keys for a user."""
        username = "test_user"
        num_keys = 5

        keys = self.manager.get_user_keys(username, num_keys)

        self.assertEqual(len(keys), num_keys)

        # All keys should be different
        private_keys = [key[0] for key in keys]
        self.assertEqual(len(private_keys), len(set(private_keys)))

        # All key indices should be sequential
        key_indices = [key[2] for key in keys]
        self.assertEqual(key_indices, list(range(num_keys)))

    def test_validate_user_key(self):
        """Test user key validation."""
        username = "test_user"
        private_key, _ = self.manager.derive_user_key(username)

        # Should validate correctly for the right user
        self.assertTrue(self.manager.validate_user_key(username, private_key))

        # Should not validate for a different user
        self.assertFalse(self.manager.validate_user_key("different_user", private_key))

    def test_manager_caching(self):
        """Test that the manager caches derived keys."""
        username = "test_user"

        # First derivation
        start_time = time.time()
        key1, addr1 = self.manager.derive_user_key(username)
        first_duration = time.time() - start_time

        # Second derivation (should be cached)
        start_time = time.time()
        key2, addr2 = self.manager.derive_user_key(username)
        second_duration = time.time() - start_time

        # Results should be identical
        self.assertEqual(key1, key2)
        self.assertEqual(addr1, addr2)

        # Second call should be faster (cached)
        self.assertLessEqual(second_duration, first_duration)


class TestUserIsolation(unittest.TestCase):
    """Test user isolation and security properties."""

    def setUp(self):
        """Set up test fixtures."""
        self.master_seed = create_test_master_seed(deterministic=True)
        self.manager = StarknetMultiUserKeyManager(self.master_seed)

    def test_user_key_isolation(self):
        """Test that users cannot access each other's keys."""
        users = [f"user_{i}" for i in range(10)]
        user_keys = {}

        # Derive keys for all users
        for user in users:
            user_keys[user] = self.manager.derive_user_key(user)[0]

        # Verify all keys are unique
        all_keys = list(user_keys.values())
        self.assertEqual(len(all_keys), len(set(all_keys)))

        # Verify users can only validate their own keys
        for user, key in user_keys.items():
            self.assertTrue(self.manager.validate_user_key(user, key))

            # Check that other users cannot validate this key
            for other_user in users:
                if other_user != user:
                    self.assertFalse(self.manager.validate_user_key(other_user, key))

    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks."""
        username = "test_user"
        valid_key, _ = self.manager.derive_user_key(username)
        invalid_key = valid_key + 1  # Different but similar key

        # Measure validation times
        valid_times = []
        invalid_times = []

        for _ in range(100):
            # Time valid key validation
            start = time.perf_counter()
            self.manager.validate_user_key(username, valid_key)
            valid_times.append(time.perf_counter() - start)

            # Time invalid key validation
            start = time.perf_counter()
            self.manager.validate_user_key(username, invalid_key)
            invalid_times.append(time.perf_counter() - start)

        # Calculate average times
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)

        # Times should be similar (within 50% difference)
        ratio = max(avg_valid, avg_invalid) / min(avg_valid, avg_invalid)
        self.assertLess(
            ratio, 1.5, "Timing difference suggests vulnerability to timing attacks"
        )


class TestConcurrentAccess(unittest.TestCase):
    """Test concurrent access scenarios."""

    def setUp(self):
        """Set up test fixtures."""
        self.master_seed = create_test_master_seed(deterministic=True)
        self.manager = StarknetMultiUserKeyManager(self.master_seed)

    def test_concurrent_key_derivation(self):
        """Test concurrent key derivation for different users."""
        num_users = 50
        users = [f"user_{i:03d}" for i in range(num_users)]

        def derive_key_for_user(username):
            return (username, self.manager.derive_user_key(username))

        # Use ThreadPoolExecutor for concurrent access
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(derive_key_for_user, user) for user in users]
            results = {}

            for future in as_completed(futures):
                username, (private_key, address) = future.result()
                results[username] = (private_key, address)

        # Verify all keys were derived successfully
        self.assertEqual(len(results), num_users)

        # Verify all keys are unique
        all_keys = [key for key, _ in results.values()]
        self.assertEqual(len(all_keys), len(set(all_keys)))

        # Verify deterministic behavior by re-deriving
        for username, (original_key, original_addr) in results.items():
            new_key, new_addr = self.manager.derive_user_key(username)
            self.assertEqual(original_key, new_key)
            self.assertEqual(original_addr, new_addr)

    def test_concurrent_same_user_access(self):
        """Test concurrent access for the same user."""
        username = "concurrent_user"
        num_threads = 20

        def derive_key():
            return self.manager.derive_user_key(username)

        # Concurrent access to same user
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(derive_key) for _ in range(num_threads)]
            results = [future.result() for future in as_completed(futures)]

        # All results should be identical
        first_result = results[0]
        for result in results[1:]:
            self.assertEqual(result, first_result)


class TestPerformanceMetrics(unittest.TestCase):
    """Test performance characteristics of the system."""

    def setUp(self):
        """Set up test fixtures."""
        self.master_seed = create_test_master_seed(deterministic=True)

    def test_key_derivation_performance_scaling(self):
        """Test how performance scales with number of users."""
        user_counts = [10, 50, 100, 500]
        performance_results = {}

        for user_count in user_counts:
            results = test_key_derivation_performance(
                self.master_seed, user_count, keys_per_user=1
            )
            performance_results[user_count] = results

            print(f"Users: {user_count}, Keys/sec: {results['keys_per_second']:.1f}")

        # Performance should not degrade dramatically with scale
        # (This is a sanity check - adjust thresholds as needed)
        for user_count in user_counts:
            self.assertGreater(
                performance_results[user_count]["keys_per_second"],
                10,  # At least 10 keys per second
                f"Performance too slow for {user_count} users",
            )

    def test_memory_usage_scaling(self):
        """Test memory usage with many users (basic test)."""
        import gc
        import os

        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        manager = StarknetMultiUserKeyManager(self.master_seed)

        # Derive keys for many users
        for i in range(1000):
            manager.derive_user_key(f"user_{i:04d}")

        # Force garbage collection
        gc.collect()

        final_memory = process.memory_info().rss
        memory_growth = final_memory - initial_memory

        # Memory growth should be reasonable (adjust threshold as needed)
        max_allowed_growth = 100 * 1024 * 1024  # 100 MB
        self.assertLess(
            memory_growth,
            max_allowed_growth,
            f"Memory growth too large: {memory_growth / 1024 / 1024:.1f} MB",
        )


class TestUserSessionValidation(unittest.TestCase):
    """Test user session validation functionality."""

    def test_valid_session(self):
        """Test validation of valid session data."""
        username = "test_user"
        session_data = {
            "session_id": "test_session_123",
            "timestamp": int(time.time()),  # Current time
        }

        # Should not raise exception
        self.assertTrue(validate_user_session(username, session_data))

    def test_expired_session(self):
        """Test validation of expired session."""
        username = "test_user"
        session_data = {
            "session_id": "test_session_123",
            "timestamp": int(time.time()) - 7200,  # 2 hours ago
        }

        with self.assertRaises(UserSessionError):
            validate_user_session(username, session_data)

    def test_missing_session_fields(self):
        """Test validation with missing session fields."""
        username = "test_user"

        invalid_sessions = [
            {},  # Empty
            {"session_id": "test"},  # Missing timestamp
            {"timestamp": int(time.time())},  # Missing session_id
        ]

        for session_data in invalid_sessions:
            with self.subTest(session_data=session_data):
                with self.assertRaises(UserSessionError):
                    validate_user_session(username, session_data)

    def test_invalid_username_format(self):
        """Test validation with invalid username formats."""
        invalid_usernames = ["", None, 123, "a" * 256]
        session_data = {"session_id": "test_session", "timestamp": int(time.time())}

        for username in invalid_usernames:
            with self.subTest(username=username):
                with self.assertRaises(UserSessionError):
                    validate_user_session(username, session_data)


class TestSecurityProperties(unittest.TestCase):
    """Test security properties of the system."""

    def test_master_seed_isolation(self):
        """Test that different master seeds produce different key spaces."""
        seed1 = create_test_master_seed(deterministic=True)
        seed2 = generate_master_seed()  # Random seed

        manager1 = StarknetMultiUserKeyManager(seed1)
        manager2 = StarknetMultiUserKeyManager(seed2)

        username = "test_user"

        key1, _ = manager1.derive_user_key(username)
        key2, _ = manager2.derive_user_key(username)

        # Keys should be different with different master seeds
        self.assertNotEqual(key1, key2)

    def test_username_case_sensitivity(self):
        """Test that usernames are case-sensitive."""
        manager = StarknetMultiUserKeyManager(
            create_test_master_seed(deterministic=True)
        )

        user1 = "TestUser"
        user2 = "testuser"
        user3 = "TESTUSER"

        key1, _ = manager.derive_user_key(user1)
        key2, _ = manager.derive_user_key(user2)
        key3, _ = manager.derive_user_key(user3)

        # All keys should be different
        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key2, key3)
        self.assertNotEqual(key1, key3)

    def test_key_entropy(self):
        """Test that derived keys have good entropy."""
        manager = StarknetMultiUserKeyManager(
            create_test_master_seed(deterministic=True)
        )

        # Derive many keys
        keys = []
        for i in range(1000):
            key, _ = manager.derive_user_key(f"user_{i:04d}")
            keys.append(key)

        # Convert keys to bytes for entropy analysis
        key_bytes = b"".join(key.to_bytes(32, "big") for key in keys)

        # Simple entropy check: count unique bytes
        unique_bytes = len(set(key_bytes))

        # Should see good distribution of byte values
        self.assertGreater(unique_bytes, 200, "Poor entropy in derived keys")


class TestIntegrationScenarios(unittest.TestCase):
    """Test complete integration scenarios."""

    def test_complete_multiuser_scenario(self):
        """Test a complete multi-user scenario."""
        scenario = create_multi_user_key_derivation_scenario(user_count=20)

        master_seed = create_test_master_seed(deterministic=True)
        manager = StarknetMultiUserKeyManager(master_seed)

        # Verify all users can derive keys
        for user in scenario["users"]:
            username = user["username"]
            key, address = manager.derive_user_key(username)

            self.assertTrue(validate_starknet_private_key(key))
            self.assertGreater(address, 0)

            # Test key validation
            self.assertTrue(manager.validate_user_key(username, key))

    def test_load_test_scenario(self):
        """Test a concurrent load scenario."""
        load_test = create_concurrent_user_load_test(peak_users=50, ramp_up_seconds=10)

        master_seed = create_test_master_seed(deterministic=True)
        manager = StarknetMultiUserKeyManager(master_seed)

        def simulate_user_request(scenario):
            username = f"load_user_{scenario['scenario_id'][:8]}"
            operations = scenario["operation_types"]

            results = []
            for _ in range(scenario["operations_per_user"]):
                if "key_derive" in operations:
                    key, address = manager.derive_user_key(username)
                    results.append(("key_derive", key is not None))

                if "get_address" in operations:
                    _, address = manager.derive_user_key(username)
                    results.append(("get_address", address > 0))

            return results

        # Execute load test
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for scenario in load_test["user_scenarios"][:20]:  # Limit for test
                futures.append(executor.submit(simulate_user_request, scenario))

            all_results = []
            for future in as_completed(futures):
                all_results.extend(future.result())

        # Verify all operations succeeded
        success_count = sum(1 for _, success in all_results if success)
        self.assertEqual(success_count, len(all_results))


if __name__ == "__main__":
    # Set up test environment
    os.environ["TESTING"] = "true"

    # Run tests with verbose output
    unittest.main(verbosity=2)
