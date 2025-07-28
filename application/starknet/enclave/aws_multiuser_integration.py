"""
AWS integration layer for multi-user Starknet key derivation system.

This module handles the integration with AWS services (KMS, Secrets Manager)
for secure master seed management and user session handling in Nitro Enclaves.
"""

import base64
import json
import os
import subprocess
import time
from typing import Dict, Optional, Tuple, Any

from key_derivation import (
    StarknetMultiUserKeyManager,
    StarknetKeyDerivationError,
    InvalidUserNameError,
    KeyValidationError,
    secure_zero_memory
)


class AWSIntegrationError(Exception):
    """Base exception for AWS integration errors."""
    pass


class KMSDecryptionError(AWSIntegrationError):
    """Raised when KMS decryption fails."""
    pass


class MasterSeedError(AWSIntegrationError):
    """Raised when master seed operations fail."""
    pass


class UserSessionError(AWSIntegrationError):
    """Raised when user session validation fails."""
    pass


def kms_decrypt_master_seed(credential: Dict[str, str], ciphertext: str) -> bytes:
    """
    Decrypt the master seed using AWS KMS within Nitro Enclave.
    
    Args:
        credential: AWS credentials dictionary
        ciphertext: Base64 encoded encrypted master seed
        
    Returns:
        bytes: Decrypted master seed (32 bytes)
        
    Raises:
        KMSDecryptionError: If decryption fails
        MasterSeedError: If decrypted seed is invalid
    """
    aws_access_key_id = credential["access_key_id"]
    aws_secret_access_key = credential["secret_access_key"]
    aws_session_token = credential["token"]

    subprocess_args = [
        "/app/kmstool_enclave_cli",
        "decrypt",
        "--region",
        os.getenv("REGION", "us-east-1"),
        "--proxy-port",
        "8000",
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext,
    ]

    try:
        proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        
        if proc.returncode != 0:
            raise KMSDecryptionError(f"KMS decryption failed: {stderr.decode()}")
        
        # Parse the output (format: "PLAINTEXT: <base64_encoded_data>")
        result_b64 = stdout.decode().strip()
        if not result_b64.startswith("PLAINTEXT:"):
            raise KMSDecryptionError("Unexpected KMS output format")
        
        plaintext_b64 = result_b64.split(":", 1)[1].strip()
        master_seed = base64.standard_b64decode(plaintext_b64)
        
        # Validate master seed length
        if len(master_seed) != 32:
            raise MasterSeedError(f"Invalid master seed length: {len(master_seed)} bytes (expected 32)")
        
        return master_seed
        
    except subprocess.SubprocessError as e:
        raise KMSDecryptionError(f"KMS subprocess error: {e}")
    except base64.binascii.Error as e:
        raise KMSDecryptionError(f"Base64 decoding error: {e}")


def validate_user_session(username: str, session_data: Optional[Dict[str, Any]] = None) -> bool:
    """
    Validate user session and authentication.
    
    Args:
        username: Username to validate
        session_data: Optional session metadata
        
    Returns:
        bool: True if session is valid
        
    Raises:
        UserSessionError: If session validation fails
    """
    try:
        # Basic username validation
        if not username or not isinstance(username, str):
            raise UserSessionError("Invalid username format")
        
        if len(username) > 255:
            raise UserSessionError("Username too long")
        
        # Additional session validation if provided
        if session_data is not None:
            # Check if session_data is an empty dictionary
            if not session_data:
                raise UserSessionError("Session data cannot be empty")
            
            required_fields = ['session_id', 'timestamp']
            for field in required_fields:
                if field not in session_data:
                    raise UserSessionError(f"Missing session field: {field}")
            
            # Check session timestamp (example: 1 hour timeout)
            current_time = time.time()
            session_time = session_data.get('timestamp', 0)
            if current_time - session_time > 3600:  # 1 hour
                raise UserSessionError("Session expired")
        
        return True
        
    except Exception as e:
        if isinstance(e, UserSessionError):
            raise
        raise UserSessionError(f"Session validation error: {e}")


class StarknetMultiUserAWSManager:
    """
    AWS-integrated multi-user Starknet key manager.
    
    This class combines the key derivation functionality with AWS services
    for secure operation within Nitro Enclaves.
    """
    
    def __init__(self):
        """Initialize the AWS manager without master seed (loaded on demand)."""
        self._key_manager: Optional[StarknetMultiUserKeyManager] = None
        self._master_seed: Optional[bytes] = None
        self._master_seed_loaded = False
    
    def load_master_seed(self, credential: Dict[str, str], encrypted_master_seed: str) -> None:
        """
        Load and decrypt the master seed from AWS KMS.
        
        Args:
            credential: AWS credentials
            encrypted_master_seed: Encrypted master seed from KMS
            
        Raises:
            KMSDecryptionError: If decryption fails
            MasterSeedError: If seed is invalid
        """
        try:
            self._master_seed = kms_decrypt_master_seed(credential, encrypted_master_seed)
            self._key_manager = StarknetMultiUserKeyManager(self._master_seed)
            self._master_seed_loaded = True
            
        except Exception as e:
            # Ensure cleanup on failure
            self._cleanup_master_seed()
            raise
    
    def derive_user_key_with_validation(
        self, 
        username: str, 
        key_index: int = 0,
        session_data: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, int]:
        """
        Derive a user key with full validation.
        
        Args:
            username: Username for key derivation
            key_index: Key index (for multiple keys per user)
            session_data: Optional session validation data
            
        Returns:
            Tuple[int, int]: (private_key_int, account_address_int)
            
        Raises:
            UserSessionError: If user session is invalid
            StarknetKeyDerivationError: If key derivation fails
            MasterSeedError: If master seed not loaded
        """
        if not self._master_seed_loaded or not self._key_manager:
            raise MasterSeedError("Master seed not loaded")
        
        # Validate user session
        validate_user_session(username, session_data)
        
        # Derive the key
        try:
            return self._key_manager.derive_user_key(username, key_index)
        except Exception as e:
            raise StarknetKeyDerivationError(f"Key derivation failed for user '{username}': {e}")
    
    def process_user_transaction_request(
        self,
        username: str,
        transaction_payload: Dict[str, Any],
        session_data: Optional[Dict[str, Any]] = None,
        key_index: int = 0
    ) -> Dict[str, Any]:
        """
        Process a transaction request for a specific user.
        
        Args:
            username: Username for the transaction
            transaction_payload: Starknet transaction parameters
            session_data: Session validation data
            key_index: Key index to use
            
        Returns:
            Dict[str, Any]: Transaction response with key material
            
        Raises:
            UserSessionError: If user session is invalid
            StarknetKeyDerivationError: If key operations fail
        """
        try:
            # Derive user-specific key
            private_key_int, account_address_int = self.derive_user_key_with_validation(
                username, key_index, session_data
            )
            
            # Format the response for the existing transaction signing logic
            response = {
                'private_key_int': private_key_int,
                'account_address_int': account_address_int,
                'username': username,
                'key_index': key_index,
                'transaction_payload': transaction_payload,
                'success': True
            }
            
            # Validate transaction payload
            required_fields = ['contract_address', 'function_name']
            for field in required_fields:
                if field not in transaction_payload:
                    raise ValueError(f"Missing required transaction field: {field}")
            
            return response
            
        except Exception as e:
            return {
                'error': str(e),
                'username': username,
                'success': False
            }
    
    def get_user_account_info(
        self,
        username: str,
        session_data: Optional[Dict[str, Any]] = None,
        key_index: int = 0
    ) -> Dict[str, Any]:
        """
        Get account information for a user without exposing private key.
        
        Args:
            username: Username
            session_data: Session validation data
            key_index: Key index
            
        Returns:
            Dict[str, Any]: Account information
        """
        try:
            validate_user_session(username, session_data)
            
            if not self._master_seed_loaded or not self._key_manager:
                raise MasterSeedError("Master seed not loaded")
            
            private_key_int, account_address_int = self._key_manager.derive_user_key(username, key_index)
            
            return {
                'username': username,
                'account_address': hex(account_address_int),
                'key_index': key_index,
                'success': True
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'username': username,
                'success': False
            }
    
    def validate_user_ownership(
        self,
        username: str,
        account_address: str,
        session_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Validate that a user owns a specific account address.
        
        This implementation uses constant-time validation to prevent timing attacks.
        All code paths take approximately the same time regardless of ownership validity.
        
        Args:
            username: Username to validate
            account_address: Account address to check
            session_data: Session validation data
            
        Returns:
            bool: True if user owns the account
        """
        try:
            validate_user_session(username, session_data)
            
            if not self._master_seed_loaded or not self._key_manager:
                # Perform some dummy work to maintain timing consistency
                import hashlib
                for dummy_index in range(10):
                    dummy_data = hashlib.sha256(f"dummy_{username}_{dummy_index}".encode()).digest()
                    _ = int.from_bytes(dummy_data[:8], 'big')  # Dummy computation
                return False
            
            # Convert address to int for comparison
            if account_address.startswith('0x'):
                account_address_int = int(account_address, 16)
            else:
                account_address_int = int(account_address)
            
            # Use constant-time validation to prevent timing attacks
            found_match = False
            
            # Always check all 10 key indices regardless of when we find a match
            for key_index in range(10):  # Check first 10 keys
                try:
                    _, derived_address = self._key_manager.derive_user_key(username, key_index)
                    # Use constant-time comparison - import from key_derivation module
                    from key_derivation import constant_time_int_compare
                    if constant_time_int_compare(derived_address, account_address_int):
                        found_match = True
                    # Continue execution regardless of match to maintain constant timing
                except Exception:
                    # Continue processing even if individual derivation fails
                    continue
            
            return found_match
            
        except Exception:
            # Even in exception cases, maintain timing consistency
            import hashlib
            try:
                for dummy_index in range(10):
                    dummy_data = hashlib.sha256(f"error_dummy_{username}_{dummy_index}".encode()).digest()
                    _ = int.from_bytes(dummy_data[:8], 'big')  # Dummy computation
            except:
                pass
            return False
    
    def _cleanup_master_seed(self) -> None:
        """Securely cleanup master seed from memory."""
        if self._master_seed:
            # Create a bytearray copy for secure zeroing
            seed_copy = bytearray(self._master_seed)
            secure_zero_memory(seed_copy)
            self._master_seed = None
        
        if self._key_manager:
            # Cleanup key manager
            del self._key_manager
            self._key_manager = None
        
        self._master_seed_loaded = False
    
    def __del__(self):
        """Secure cleanup on object destruction."""
        self._cleanup_master_seed()


def create_multiuser_transaction_payload(
    username: str,
    transaction_data: Dict[str, Any],
    session_id: Optional[str] = None,
    key_index: int = 0
) -> Dict[str, Any]:
    """
    Create a complete transaction payload for multi-user processing.
    
    Args:
        username: Username for the transaction
        transaction_data: Base transaction data
        session_id: Optional session identifier
        key_index: Key index to use
        
    Returns:
        Dict[str, Any]: Complete transaction payload
    """
    payload = {
        'username': username,
        'key_index': key_index,
        'transaction_payload': transaction_data,
        'timestamp': int(time.time())
    }
    
    if session_id:
        payload['session_data'] = {
            'session_id': session_id,
            'timestamp': int(time.time())
        }
    
    return payload


def extract_user_context_from_request(request_payload: Dict[str, Any]) -> Tuple[str, int, Optional[Dict]]:
    """
    Extract user context from incoming request payload.
    
    Args:
        request_payload: Incoming request data
        
    Returns:
        Tuple[str, int, Optional[Dict]]: (username, key_index, session_data)
        
    Raises:
        UserSessionError: If required user context is missing
    """
    username = request_payload.get('username')
    if not username:
        raise UserSessionError("Username required in request")
    
    key_index = request_payload.get('key_index', 0)
    if not isinstance(key_index, int) or key_index < 0:
        raise UserSessionError("Invalid key_index")
    
    session_data = request_payload.get('session_data')
    
    return username, key_index, session_data


# Security and audit utilities

def log_user_key_access(
    username: str,
    key_index: int,
    operation: str,
    success: bool,
    session_id: Optional[str] = None
) -> None:
    """
    Log user key access for audit purposes.
    
    Args:
        username: Username (will be hashed for privacy)
        key_index: Key index accessed
        operation: Type of operation
        success: Whether operation succeeded
        session_id: Session identifier
    """
    import hashlib
    
    # Hash username for privacy in logs
    username_hash = hashlib.sha256(username.encode()).hexdigest()[:12]
    
    log_entry = {
        'timestamp': int(time.time()),
        'username_hash': username_hash,
        'key_index': key_index,
        'operation': operation,
        'success': success,
        'session_id': session_id
    }
    
    # In production, this would go to a secure audit log
    print(f"AUDIT: {json.dumps(log_entry)}")


def validate_enclave_environment() -> bool:
    """
    Validate that we're running in a secure Nitro Enclave environment.
    
    Returns:
        bool: True if environment is secure
    """
    try:
        # Check for Nitro Enclave specific files/environment
        nitro_indicators = [
            '/dev/nsm',  # Nitro Security Module device
            '/sys/devices/virtual/misc/nsm'  # NSM sysfs entry
        ]
        
        for indicator in nitro_indicators:
            if os.path.exists(indicator):
                return True
        
        # Check environment variable
        if os.getenv('NITRO_ENCLAVE') == 'true':
            return True
        
        return False
        
    except Exception:
        return False


# Performance monitoring utilities

class PerformanceMonitor:
    """Monitor performance metrics for multi-user operations."""
    
    def __init__(self):
        self.metrics = {
            'key_derivations': 0,
            'total_derivation_time': 0.0,
            'user_sessions': 0,
            'failed_operations': 0
        }
    
    def record_key_derivation(self, duration: float) -> None:
        """Record a key derivation operation."""
        self.metrics['key_derivations'] += 1
        self.metrics['total_derivation_time'] += duration
    
    def record_user_session(self) -> None:
        """Record a user session."""
        self.metrics['user_sessions'] += 1
    
    def record_failure(self) -> None:
        """Record a failed operation."""
        self.metrics['failed_operations'] += 1
    
    def get_average_derivation_time(self) -> float:
        """Get average key derivation time."""
        if self.metrics['key_derivations'] == 0:
            return 0.0
        return self.metrics['total_derivation_time'] / self.metrics['key_derivations']
    
    def get_failure_rate(self) -> float:
        """Get failure rate percentage."""
        total_ops = self.metrics['key_derivations'] + self.metrics['failed_operations']
        if total_ops == 0:
            return 0.0
        return (self.metrics['failed_operations'] / total_ops) * 100
    
    def reset(self) -> None:
        """Reset all metrics."""
        for key in self.metrics:
            self.metrics[key] = 0 if isinstance(self.metrics[key], int) else 0.0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        return {
            'total_key_derivations': self.metrics['key_derivations'],
            'total_user_sessions': self.metrics['user_sessions'],
            'total_failures': self.metrics['failed_operations'],
            'average_derivation_time_ms': self.get_average_derivation_time() * 1000,
            'failure_rate_percentage': self.get_failure_rate(),
            'total_derivation_time_seconds': self.metrics['total_derivation_time']
        }


# Global performance monitor instance
performance_monitor = PerformanceMonitor()