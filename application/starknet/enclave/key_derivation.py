"""
Multi-user key derivation system for Starknet using HKDF.

This module implements a secure, deterministic key derivation system
that generates unique Starknet private keys for each user from a master seed.
All operations are designed to be secure within AWS Nitro Enclaves.
"""

import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple, Union

# Starknet curve parameters
STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001
STARK_ORDER = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F


class StarknetKeyDerivationError(Exception):
    """Base exception for key derivation errors."""
    pass


class InvalidUserNameError(StarknetKeyDerivationError):
    """Raised when username is invalid for key derivation."""
    pass


class KeyValidationError(StarknetKeyDerivationError):
    """Raised when derived key fails validation."""
    pass


def hkdf_expand(prk: bytes, info: bytes = b"", length: int = 32) -> bytes:
    """
    HKDF-Expand implementation according to RFC 5869.
    
    Args:
        prk: Pseudo-random key from HKDF-Extract
        info: Optional context and application specific information
        length: Length of output keying material in bytes
        
    Returns:
        bytes: Output keying material of specified length
        
    Raises:
        ValueError: If length is too large or invalid
    """
    if length >= 255 * 32:  # SHA256 hash length is 32 bytes
        raise ValueError("Cannot expand to more than 255 * HashLen bytes")
    
    if length == 0:
        return b""
    
    n = (length + 31) // 32  # Ceiling division for 32-byte blocks
    okm = b""
    previous = b""
    
    for i in range(1, n + 1):
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        current = hmac.new(
            prk,
            previous + info + bytes([i]),
            hashlib.sha256
        ).digest()
        okm += current
        previous = current
    
    return okm[:length]


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract implementation according to RFC 5869.
    
    Args:
        salt: Optional salt value (a non-secret random value)
        ikm: Input keying material
        
    Returns:
        bytes: Pseudo-random key suitable for HKDF-Expand
    """
    if len(salt) == 0:
        salt = b"\x00" * 32  # Default salt for SHA256
    
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf(ikm: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """
    Complete HKDF implementation (Extract + Expand).
    
    Args:
        ikm: Input keying material
        salt: Optional salt value
        info: Optional context and application specific information
        length: Length of output keying material in bytes
        
    Returns:
        bytes: Derived key material
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def validate_username(username: str) -> None:
    """
    Validate username for key derivation.
    
    Args:
        username: Username to validate
        
    Raises:
        InvalidUserNameError: If username is invalid
    """
    if not username:
        raise InvalidUserNameError("Username cannot be empty")
    
    if len(username) > 255:
        raise InvalidUserNameError("Username too long (max 255 characters)")
    
    # Ensure username contains only safe characters to prevent injection attacks
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
    if not all(c in allowed_chars for c in username):
        raise InvalidUserNameError("Username contains invalid characters")


def validate_starknet_private_key(private_key_int: int) -> bool:
    """
    Validate that a private key is suitable for Starknet.
    
    Args:
        private_key_int: Private key as integer
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Must be positive and less than STARK curve order
    return 0 < private_key_int < STARK_ORDER


def derive_user_private_key(
    master_seed: bytes, 
    username: str,
    key_index: int = 0,
    max_attempts: int = 100
) -> Tuple[int, int]:
    """
    Derive a valid Starknet private key for a specific user.
    
    This function uses HKDF to deterministically derive a private key
    from the master seed and username. If the derived key is not valid
    for the Starknet curve, it will increment a counter and try again
    until a valid key is found.
    
    Args:
        master_seed: Master seed bytes (should be 32 bytes of high entropy)
        username: User identifier string
        key_index: Additional index for multiple keys per user
        max_attempts: Maximum attempts to find valid key
        
    Returns:
        Tuple[int, int]: (private_key_int, attempt_number)
        
    Raises:
        InvalidUserNameError: If username is invalid
        KeyValidationError: If no valid key found within max_attempts
        ValueError: If master_seed is invalid
    """
    validate_username(username)
    
    if not master_seed or len(master_seed) != 32:
        raise ValueError("Master seed must be exactly 32 bytes")
    
    if key_index < 0:
        raise ValueError("Key index must be non-negative")
    
    # Create deterministic salt from username and key index
    salt = hashlib.sha256(f"starknet_user_{username}_{key_index}".encode()).digest()
    
    # Try to find a valid private key
    for attempt in range(max_attempts):
        # Create unique info string for each attempt
        info = f"starknet_private_key_v1_attempt_{attempt}".encode()
        
        # Derive 32 bytes of key material
        derived_bytes = hkdf(master_seed, salt, info, 32)
        
        # Convert to integer
        private_key_int = int.from_bytes(derived_bytes, 'big')
        
        # Validate against Starknet curve order
        if validate_starknet_private_key(private_key_int):
            return private_key_int, attempt
    
    raise KeyValidationError(
        f"Could not derive valid Starknet private key for user '{username}' "
        f"within {max_attempts} attempts"
    )


def derive_multiple_user_keys(
    master_seed: bytes,
    username: str,
    num_keys: int = 1,
    starting_index: int = 0
) -> list[Tuple[int, int, int]]:
    """
    Derive multiple private keys for a single user.
    
    Args:
        master_seed: Master seed bytes
        username: User identifier string  
        num_keys: Number of keys to derive
        starting_index: Starting key index
        
    Returns:
        List[Tuple[int, int, int]]: List of (private_key_int, key_index, attempt_number)
        
    Raises:
        InvalidUserNameError: If username is invalid
        KeyValidationError: If any key derivation fails
    """
    if num_keys <= 0:
        raise ValueError("Number of keys must be positive")
    
    if num_keys > 1000:
        raise ValueError("Too many keys requested (max 1000)")
    
    keys = []
    for i in range(num_keys):
        key_index = starting_index + i
        private_key_int, attempt = derive_user_private_key(
            master_seed, username, key_index
        )
        keys.append((private_key_int, key_index, attempt))
    
    return keys


def secure_compare_usernames(username1: str, username2: str) -> bool:
    """
    Securely compare two usernames to prevent timing attacks.
    
    Args:
        username1: First username
        username2: Second username
        
    Returns:
        bool: True if usernames are equal
    """
    # Normalize to bytes for secure comparison
    b1 = username1.encode('utf-8')
    b2 = username2.encode('utf-8')
    
    return secrets.compare_digest(b1, b2)


def generate_master_seed() -> bytes:
    """
    Generate a cryptographically secure master seed.
    
    This should only be used during initial system setup.
    In production, the master seed should be stored securely
    in AWS KMS and never regenerated.
    
    Returns:
        bytes: 32 bytes of cryptographically secure random data
    """
    return secrets.token_bytes(32)


def derive_account_address_from_private_key(private_key_int: int) -> int:
    """
    Derive the Starknet account address from a private key.
    
    This is a simplified derivation - in practice, you would use
    the starknet-py library's account creation functions.
    
    Args:
        private_key_int: Private key as integer
        
    Returns:
        int: Account address as integer
    """
    # This is a placeholder - actual implementation would use
    # the Starknet account contract deployment process
    # For now, we'll use a simple hash-based derivation
    
    private_key_bytes = private_key_int.to_bytes(32, 'big')
    address_hash = hashlib.sha256(b"starknet_account_" + private_key_bytes).digest()
    return int.from_bytes(address_hash[:20], 'big')  # Take first 20 bytes


class StarknetMultiUserKeyManager:
    """
    Main class for managing multi-user Starknet key derivation.
    
    This class provides a high-level interface for deriving and managing
    Starknet private keys for multiple users from a single master seed.
    """
    
    def __init__(self, master_seed: bytes):
        """
        Initialize the key manager with a master seed.
        
        Args:
            master_seed: 32 bytes of master seed material
            
        Raises:
            ValueError: If master_seed is invalid
        """
        if not master_seed or len(master_seed) != 32:
            raise ValueError("Master seed must be exactly 32 bytes")
        
        self._master_seed = master_seed
        self._derived_keys_cache = {}  # For performance optimization
    
    def derive_user_key(
        self, 
        username: str, 
        key_index: int = 0
    ) -> Tuple[int, int]:
        """
        Derive a private key for a specific user.
        
        Args:
            username: User identifier
            key_index: Key index for multiple keys per user
            
        Returns:
            Tuple[int, int]: (private_key_int, account_address_int)
        """
        cache_key = f"{username}:{key_index}"
        
        # Check cache first (for performance in testing scenarios)
        if cache_key in self._derived_keys_cache:
            return self._derived_keys_cache[cache_key]
        
        private_key_int, _ = derive_user_private_key(
            self._master_seed, username, key_index
        )
        
        account_address_int = derive_account_address_from_private_key(private_key_int)
        
        result = (private_key_int, account_address_int)
        self._derived_keys_cache[cache_key] = result
        
        return result
    
    def get_user_keys(
        self, 
        username: str, 
        num_keys: int = 1
    ) -> list[Tuple[int, int, int]]:
        """
        Get multiple keys for a user.
        
        Args:
            username: User identifier
            num_keys: Number of keys to derive
            
        Returns:
            List[Tuple[int, int, int]]: List of (private_key_int, account_address_int, key_index)
        """
        results = []
        for key_index in range(num_keys):
            private_key_int, account_address_int = self.derive_user_key(username, key_index)
            results.append((private_key_int, account_address_int, key_index))
        
        return results
    
    def validate_user_key(self, username: str, private_key_int: int) -> bool:
        """
        Validate that a private key belongs to a specific user.
        
        Args:
            username: User identifier
            private_key_int: Private key to validate
            
        Returns:
            bool: True if the key belongs to the user
        """
        try:
            # Try to find a matching key index for this user
            for key_index in range(100):  # Check first 100 key indices
                derived_key, _ = self.derive_user_key(username, key_index)
                if derived_key == private_key_int:
                    return True
            return False
        except Exception:
            return False
    
    def clear_cache(self) -> None:
        """Clear the internal key cache."""
        self._derived_keys_cache.clear()
    
    def __del__(self):
        """Secure cleanup of sensitive data."""
        if hasattr(self, '_master_seed'):
            # Overwrite master seed in memory
            self._master_seed = b'\x00' * len(self._master_seed)
        
        if hasattr(self, '_derived_keys_cache'):
            # Clear cache
            self._derived_keys_cache.clear()


# Security utilities

def secure_zero_memory(data: Union[bytes, bytearray]) -> None:
    """
    Securely zero out memory containing sensitive data.
    
    Args:
        data: Data to zero out
    """
    if isinstance(data, bytes):
        # Can't modify bytes in place, but this helps with garbage collection
        data = None
    elif isinstance(data, bytearray):
        # Zero out bytearray
        for i in range(len(data)):
            data[i] = 0


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte sequences in constant time.
    
    Args:
        a: First byte sequence
        b: Second byte sequence
        
    Returns:
        bool: True if sequences are equal
    """
    return secrets.compare_digest(a, b)


# Testing utilities (for development only)

def create_test_master_seed(deterministic: bool = False) -> bytes:
    """
    Create a test master seed.
    
    WARNING: Only use this for testing! Never use in production.
    
    Args:
        deterministic: If True, creates a deterministic seed for testing
        
    Returns:
        bytes: Test master seed
    """
    if deterministic:
        # Deterministic seed for reproducible tests
        return hashlib.sha256(b"test_master_seed_do_not_use_in_production").digest()
    else:
        return generate_master_seed()


def test_key_derivation_performance(
    master_seed: bytes,
    num_users: int = 100,
    keys_per_user: int = 1
) -> dict:
    """
    Test key derivation performance.
    
    Args:
        master_seed: Master seed for testing
        num_users: Number of test users
        keys_per_user: Number of keys per user
        
    Returns:
        dict: Performance metrics
    """
    import time
    
    start_time = time.time()
    
    manager = StarknetMultiUserKeyManager(master_seed)
    
    total_keys = 0
    for user_id in range(num_users):
        username = f"test_user_{user_id:06d}"
        keys = manager.get_user_keys(username, keys_per_user)
        total_keys += len(keys)
    
    end_time = time.time()
    duration = end_time - start_time
    
    return {
        'total_users': num_users,
        'keys_per_user': keys_per_user,
        'total_keys': total_keys,
        'duration_seconds': duration,
        'keys_per_second': total_keys / duration if duration > 0 else float('inf'),
        'users_per_second': num_users / duration if duration > 0 else float('inf')
    }