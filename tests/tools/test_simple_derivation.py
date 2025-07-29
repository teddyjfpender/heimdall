"""Simple test to verify key derivation works."""

from application.starknet.enclave.key_derivation import derive_user_private_key, create_test_master_seed, validate_starknet_private_key

def test_basic_derivation():
    """Test basic key derivation."""
    master_seed = create_test_master_seed(deterministic=True)
    username = "test_user"
    
    # Test deterministic behavior
    key1, attempts1 = derive_user_private_key(master_seed, username)
    key2, attempts2 = derive_user_private_key(master_seed, username)
    
    assert key1 == key2, "Keys should be deterministic"
    assert attempts1 == attempts2, "Attempts should be deterministic"
    assert validate_starknet_private_key(key1), "Key should be valid"
    
    print(f"✓ Generated valid key in {attempts1 + 1} attempts")
    print(f"  Key: {key1}")
    print(f"  Key hex: {hex(key1)}")

if __name__ == "__main__":
    test_basic_derivation()
    print("✓ Basic test passed!")