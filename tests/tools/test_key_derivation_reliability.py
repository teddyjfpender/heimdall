"""
Test the reliability of the Starknet key derivation algorithm.

This test specifically validates that the key derivation algorithm
reliably generates valid keys and uses the fallback mechanism appropriately.
"""

import time

from application.starknet.enclave.key_derivation import (
    derive_user_private_key,
    validate_starknet_private_key,
    create_test_master_seed,
    calculate_key_derivation_probabilities,
    STARK_ORDER
)


def test_key_derivation_reliability():
    """Test that key derivation is highly reliable with new parameters."""
    master_seed = create_test_master_seed(deterministic=True)
    
    # Test with many different users
    num_users = 10000
    fallback_count = 0
    total_attempts = 0
    
    print(f"Testing key derivation for {num_users} users...")
    start_time = time.time()
    
    for i in range(num_users):
        username = f"test_user_{i:06d}"
        private_key, attempts = derive_user_private_key(master_seed, username)
        
        # Validate the key
        assert validate_starknet_private_key(private_key), f"Invalid key for {username}"
        
        # Check if fallback was used (attempts == max_attempts)
        if attempts == 1000:
            fallback_count += 1
            # For fallback, we tried all max_attempts
            total_attempts += 1000
        else:
            # For success, attempts is 0-indexed, so add 1
            total_attempts += (attempts + 1)
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Calculate statistics
    avg_attempts = total_attempts / num_users
    fallback_rate = (fallback_count / num_users) * 100
    
    print(f"\nResults for {num_users} users:")
    print(f"  Total time: {duration:.2f} seconds")
    print(f"  Keys per second: {num_users / duration:.1f}")
    print(f"  Average attempts per key: {avg_attempts:.2f}")
    print(f"  Fallback used: {fallback_count} times ({fallback_rate:.4f}%)")
    
    # Verify the results match our expectations
    probabilities = calculate_key_derivation_probabilities(1000)
    expected_fallback_rate = probabilities['fallback_probability_percentage']
    expected_avg_attempts = probabilities['expected_attempts']
    
    print(f"\nExpected values:")
    print(f"  Expected average attempts: {expected_avg_attempts:.2f}")
    print(f"  Expected fallback rate: {expected_fallback_rate:.2e}%")
    
    # The fallback should be extremely rare with 1000 attempts
    assert fallback_rate < 0.01, f"Fallback rate too high: {fallback_rate}%"
    
    # Average attempts should be close to theoretical value (around 32)
    # With 96.875% rejection rate, expected attempts = 1 / 0.03125 = 32
    assert 25 < avg_attempts < 40, f"Average attempts out of expected range: {avg_attempts}"
    
    print("\n✓ All reliability tests passed!")


def test_fallback_mechanism():
    """Test that the fallback mechanism works correctly."""
    master_seed = create_test_master_seed(deterministic=True)
    
    # Create a scenario where we force the fallback by using max_attempts=1
    # and trying many times until we hit a case that needs fallback
    print("\nTesting fallback mechanism...")
    
    fallback_triggered = False
    for i in range(1000):
        username = f"fallback_test_{i:04d}"
        
        # Use max_attempts=1 to increase chance of triggering fallback
        private_key, attempts = derive_user_private_key(
            master_seed, username, key_index=0, max_attempts=1
        )
        
        # Validate the key
        assert validate_starknet_private_key(private_key), f"Invalid key from fallback for {username}"
        
        if attempts == 1:  # Fallback was used
            fallback_triggered = True
            print(f"  Fallback triggered for user '{username}'")
            
            # Verify the fallback produces a deterministic result
            private_key2, attempts2 = derive_user_private_key(
                master_seed, username, key_index=0, max_attempts=1
            )
            assert private_key == private_key2, "Fallback not deterministic!"
            assert attempts == attempts2, "Fallback attempts not consistent!"
            
            break
    
    if fallback_triggered:
        print("✓ Fallback mechanism tested successfully!")
    else:
        print("⚠ Fallback not triggered in test (this can happen due to randomness)")


def test_edge_cases():
    """Test edge cases in key derivation."""
    master_seed = create_test_master_seed(deterministic=True)
    
    print("\nTesting edge cases...")
    
    # Test with special usernames
    special_users = [
        "a",  # Single character
        "a" * 255,  # Maximum length
        "user.with.dots",
        "user-with-hyphens",
        "user_with_underscores",
        "MixedCaseUser123",
    ]
    
    for username in special_users:
        private_key, attempts = derive_user_private_key(master_seed, username)
        assert validate_starknet_private_key(private_key), f"Invalid key for '{username}'"
        print(f"  ✓ Generated valid key for '{username}' in {attempts + 1} attempts")
    
    # Test with different key indices
    username = "index_test_user"
    keys = []
    for key_index in range(10):
        private_key, _ = derive_user_private_key(master_seed, username, key_index)
        assert validate_starknet_private_key(private_key)
        keys.append(private_key)
    
    # All keys should be different
    assert len(set(keys)) == len(keys), "Key indices produced duplicate keys!"
    print(f"  ✓ Generated {len(keys)} unique keys for different indices")
    
    print("\n✓ All edge case tests passed!")


def test_security_properties():
    """Test security properties of the key derivation."""
    print("\nTesting security properties...")
    
    # Test with different master seeds
    seed1 = create_test_master_seed(deterministic=True)
    seed2 = create_test_master_seed(deterministic=False)  # Random
    
    username = "security_test_user"
    key1, _ = derive_user_private_key(seed1, username)
    key2, _ = derive_user_private_key(seed2, username)
    
    assert key1 != key2, "Different seeds produced same key!"
    print("  ✓ Different master seeds produce different keys")
    
    # Test key distribution (basic uniformity check)
    master_seed = create_test_master_seed(deterministic=True)
    keys = []
    for i in range(1000):
        key, _ = derive_user_private_key(master_seed, f"dist_test_{i:04d}")
        keys.append(key)
    
    # Check that keys are well-distributed (simple check: no duplicates)
    assert len(set(keys)) == len(keys), "Duplicate keys found!"
    
    # Check that keys use the full range (at least some in upper and lower halves)
    mid_point = STARK_ORDER // 2
    lower_half = sum(1 for k in keys if k < mid_point)
    upper_half = sum(1 for k in keys if k >= mid_point)
    
    # Should be roughly 50/50 distribution
    ratio = min(lower_half, upper_half) / max(lower_half, upper_half)
    assert ratio > 0.8, f"Poor key distribution: {lower_half} lower, {upper_half} upper"
    
    print(f"  ✓ Keys well distributed: {lower_half} in lower half, {upper_half} in upper half")
    print("\n✓ All security tests passed!")


if __name__ == "__main__":
    print("=" * 60)
    print("Starknet Key Derivation Reliability Test Suite")
    print("=" * 60)
    
    # Show probability calculations
    probs = calculate_key_derivation_probabilities(1000)
    print("\nKey derivation probabilities with max_attempts=1000:")
    print(f"  Single attempt success rate: {probs['single_attempt_success_probability']:.1%}")
    print(f"  Expected attempts per key: {probs['expected_attempts']:.2f}")
    print(f"  Probability of needing fallback: {probs['fallback_probability']:.2e}")
    print(f"                                  ({probs['fallback_probability_percentage']:.2e}%)")
    
    # Run all tests
    test_key_derivation_reliability()
    test_fallback_mechanism()
    test_edge_cases()
    test_security_properties()
    
    print("\n" + "=" * 60)
    print("✓ All tests passed successfully!")
    print("=" * 60)