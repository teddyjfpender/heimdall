"""
Comprehensive AWS KMS mock for local testing.

This module provides a realistic KMS mock that simulates AWS KMS behavior
including encryption, decryption, key management, and error conditions.
"""

import base64
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from unittest.mock import Mock, patch
import subprocess

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class KMSMockError(Exception):
    """Base exception for KMS mock errors."""
    pass


class AccessDeniedError(KMSMockError):
    """Simulates AWS KMS AccessDeniedException."""
    pass


class InvalidKeyIdError(KMSMockError):
    """Simulates AWS KMS NotFoundException for invalid key IDs."""
    pass


class InvalidCiphertextError(KMSMockError):
    """Simulates AWS KMS InvalidCiphertextException."""
    pass


class MockKMSKey:
    """Represents a mock KMS key with realistic properties."""
    
    def __init__(self, key_id: str, region: str = "us-east-1"):
        self.key_id = key_id
        self.region = region
        self.arn = f"arn:aws:kms:{region}:123456789012:key/{key_id}"
        self.creation_date = datetime.now(timezone.utc)
        self.enabled = True
        self.key_usage = "ENCRYPT_DECRYPT"
        self.key_spec = "SYMMETRIC_DEFAULT"
        self.description = f"Mock KMS key {key_id}"
        self.policy = self._default_key_policy()
        
        # Generate a symmetric key for actual encryption/decryption
        salt = secrets.randbits(128).to_bytes(16, 'big')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(key_id.encode())
        self._encryption_key = base64.urlsafe_b64encode(key)
        self._fernet = Fernet(self._encryption_key)
        
    def _default_key_policy(self) -> Dict[str, Any]:
        """Generate a default key policy similar to AWS KMS."""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "kms:*",
                    "Resource": "*"
                }
            ]
        }
    
    def encrypt(self, plaintext: bytes, encryption_context: Optional[Dict[str, str]] = None) -> bytes:
        """Encrypt plaintext using this key."""
        if not self.enabled:
            raise KMSMockError("Key is disabled")
            
        # Create a mock ciphertext blob that includes metadata
        metadata = {
            "key_id": self.key_id,
            "encryption_context": encryption_context or {},
            "timestamp": int(time.time())
        }
        
        # Encrypt the plaintext
        encrypted_data = self._fernet.encrypt(plaintext)
        
        # Create the full ciphertext blob with metadata
        ciphertext_blob = {
            "metadata": metadata,
            "ciphertext": base64.b64encode(encrypted_data).decode()
        }
        
        return base64.b64encode(json.dumps(ciphertext_blob).encode())
    
    def decrypt(self, ciphertext_blob: bytes, encryption_context: Optional[Dict[str, str]] = None) -> bytes:
        """Decrypt ciphertext using this key."""
        if not self.enabled:
            raise KMSMockError("Key is disabled")
            
        try:
            # Decode the ciphertext blob
            decoded_blob = json.loads(base64.b64decode(ciphertext_blob).decode())
            metadata = decoded_blob["metadata"]
            encrypted_data = base64.b64decode(decoded_blob["ciphertext"])
            
            # Verify key ID matches
            if metadata["key_id"] != self.key_id:
                raise InvalidCiphertextError("Key ID mismatch")
            
            # Verify encryption context if provided
            if encryption_context:
                stored_context = metadata.get("encryption_context", {})
                if stored_context != encryption_context:
                    raise InvalidCiphertextError("Encryption context mismatch")
            
            # Decrypt the data
            return self._fernet.decrypt(encrypted_data)
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise InvalidCiphertextError(f"Invalid ciphertext format: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert key to dictionary representation."""
        return {
            "KeyId": self.key_id,
            "Arn": self.arn,
            "CreationDate": self.creation_date.isoformat(),
            "Enabled": self.enabled,
            "KeyUsage": self.key_usage,
            "KeySpec": self.key_spec,
            "Description": self.description
        }


class MockKMSService:
    """
    Comprehensive AWS KMS service mock.
    
    This mock provides realistic KMS behavior for testing, including:
    - Key creation, retrieval, and management
    - Encryption and decryption operations
    - Error simulation (access denied, key not found, etc.)
    - Support for encryption contexts
    - Realistic response formats
    """
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.keys: Dict[str, MockKMSKey] = {}
        self.access_policies: Dict[str, Dict[str, Any]] = {}
        self._setup_default_keys()
        
    def _setup_default_keys(self):
        """Set up default test keys."""
        default_keys = [
            "12345678-1234-1234-1234-123456789012",
            "test-key-id",
            "master-seed-key",
            "starknet-key"
        ]
        
        for key_id in default_keys:
            self.keys[key_id] = MockKMSKey(key_id, self.region)
    
    def create_key(self, 
                   description: Optional[str] = None,
                   key_usage: str = "ENCRYPT_DECRYPT",
                   key_spec: str = "SYMMETRIC_DEFAULT") -> Dict[str, Any]:
        """Create a new KMS key."""
        key_id = secrets.token_hex(16)
        key = MockKMSKey(key_id, self.region)
        
        if description:
            key.description = description
        key.key_usage = key_usage
        key.key_spec = key_spec
        
        self.keys[key_id] = key
        
        return {
            "KeyMetadata": key.to_dict()
        }
    
    def describe_key(self, key_id: str) -> Dict[str, Any]:
        """Describe a KMS key."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        return {
            "KeyMetadata": self.keys[key_id].to_dict()
        }
    
    def list_keys(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """List KMS keys."""
        keys = list(self.keys.values())[:limit] if limit else list(self.keys.values())
        
        return {
            "Keys": [
                {
                    "KeyId": key.key_id,
                    "KeyArn": key.arn
                }
                for key in keys
            ]
        }
    
    def encrypt(self, 
                key_id: str, 
                plaintext: Union[str, bytes],
                encryption_context: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Encrypt data with a KMS key."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        key = self.keys[key_id]
        
        # Check access permissions (simplified)
        if not self._check_access(key_id, "kms:Encrypt"):
            raise AccessDeniedError("Access denied for encrypt operation")
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()
            
        ciphertext_blob = key.encrypt(plaintext, encryption_context)
        
        return {
            "CiphertextBlob": ciphertext_blob,
            "KeyId": key.arn,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
        }
    
    def decrypt(self, 
                ciphertext_blob: Union[str, bytes],
                encryption_context: Optional[Dict[str, str]] = None,
                key_id: Optional[str] = None) -> Dict[str, Any]:
        """Decrypt data with a KMS key."""
        if isinstance(ciphertext_blob, str):
            ciphertext_blob = ciphertext_blob.encode()
            
        # Extract key ID from ciphertext blob
        try:
            decoded_blob = json.loads(base64.b64decode(ciphertext_blob).decode())
            blob_key_id = decoded_blob["metadata"]["key_id"]
        except (json.JSONDecodeError, KeyError):
            raise InvalidCiphertextError("Invalid ciphertext blob format")
        
        if blob_key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{blob_key_id}' does not exist")
            
        key = self.keys[blob_key_id]
        
        # Check access permissions
        if not self._check_access(blob_key_id, "kms:Decrypt"):
            raise AccessDeniedError("Access denied for decrypt operation")
        
        plaintext = key.decrypt(ciphertext_blob, encryption_context)
        
        return {
            "Plaintext": plaintext,
            "KeyId": key.arn,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
        }
    
    def enable_key(self, key_id: str) -> None:
        """Enable a KMS key."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        if not self._check_access(key_id, "kms:EnableKey"):
            raise AccessDeniedError("Access denied for enable key operation")
            
        self.keys[key_id].enabled = True
    
    def disable_key(self, key_id: str) -> None:
        """Disable a KMS key."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        if not self._check_access(key_id, "kms:DisableKey"):
            raise AccessDeniedError("Access denied for disable key operation")
            
        self.keys[key_id].enabled = False
    
    def put_key_policy(self, key_id: str, policy: Dict[str, Any]) -> None:
        """Set key policy."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        if not self._check_access(key_id, "kms:PutKeyPolicy"):
            raise AccessDeniedError("Access denied for put key policy operation")
            
        self.keys[key_id].policy = policy
    
    def get_key_policy(self, key_id: str) -> Dict[str, Any]:
        """Get key policy."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        if not self._check_access(key_id, "kms:GetKeyPolicy"):
            raise AccessDeniedError("Access denied for get key policy operation")
            
        return {
            "Policy": json.dumps(self.keys[key_id].policy)
        }
    
    def _check_access(self, key_id: str, action: str) -> bool:
        """Check if access is allowed for the operation (simplified)."""
        # In a real implementation, this would check IAM policies
        # For testing, we'll use simple allow/deny rules
        access_policy = self.access_policies.get(key_id, {})
        denied_actions = access_policy.get("denied_actions", [])
        
        return action not in denied_actions
    
    def set_access_policy(self, key_id: str, policy: Dict[str, Any]) -> None:
        """Set access policy for testing (not a real KMS operation)."""
        self.access_policies[key_id] = policy
    
    def generate_data_key(self, 
                         key_id: str,
                         key_spec: str = "AES_256",
                         number_of_bytes: Optional[int] = None) -> Dict[str, Any]:
        """Generate a data key."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
            
        key = self.keys[key_id]
        
        if not self._check_access(key_id, "kms:GenerateDataKey"):
            raise AccessDeniedError("Access denied for generate data key operation")
        
        # Generate data key based on spec
        if key_spec == "AES_256":
            data_key = secrets.randbits(256).to_bytes(32, 'big')
        elif key_spec == "AES_128":
            data_key = secrets.randbits(128).to_bytes(16, 'big')
        elif number_of_bytes:
            data_key = secrets.randbits(number_of_bytes * 8).to_bytes(number_of_bytes, 'big')
        else:
            data_key = secrets.randbits(256).to_bytes(32, 'big')
        
        # Encrypt the data key
        encrypted_data_key = key.encrypt(data_key)
        
        return {
            "CiphertextBlob": encrypted_data_key,
            "Plaintext": data_key,
            "KeyId": key.arn
        }
    
    def generate_random(self, number_of_bytes: int) -> Dict[str, Any]:
        """Generate cryptographically secure random bytes."""
        if number_of_bytes < 1 or number_of_bytes > 1024:
            raise InvalidParameterError("NumberOfBytes must be between 1 and 1024")
        
        random_bytes = secrets.randbits(number_of_bytes * 8).to_bytes(number_of_bytes, 'big')
        
        return {
            "Plaintext": random_bytes
        }
    
    def create_alias(self, alias_name: str, target_key_id: str) -> Dict[str, Any]:
        """Create an alias for a KMS key."""
        if not alias_name.startswith("alias/"):
            alias_name = f"alias/{alias_name}"
        
        if target_key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{target_key_id}' does not exist")
        
        # Store alias mapping (simplified)
        if not hasattr(self, 'aliases'):
            self.aliases = {}
        
        self.aliases[alias_name] = target_key_id
        
        return {
            "AliasName": alias_name,
            "AliasArn": f"arn:aws:kms:{self.region}:123456789012:{alias_name}",
            "TargetKeyId": target_key_id
        }
    
    def list_aliases(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """List KMS aliases."""
        if not hasattr(self, 'aliases'):
            self.aliases = {}
        
        aliases = []
        for alias_name, target_key_id in self.aliases.items():
            if key_id is None or target_key_id == key_id:
                aliases.append({
                    "AliasName": alias_name,
                    "AliasArn": f"arn:aws:kms:{self.region}:123456789012:{alias_name}",
                    "TargetKeyId": target_key_id
                })
        
        return {"Aliases": aliases}
    
    def get_key_rotation_status(self, key_id: str) -> Dict[str, Any]:
        """Get key rotation status."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
        
        # Mock rotation status
        return {
            "KeyRotationEnabled": False  # Simplified for testing
        }
    
    def enable_key_rotation(self, key_id: str) -> None:
        """Enable automatic key rotation."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
        
        if not self._check_access(key_id, "kms:EnableKeyRotation"):
            raise AccessDeniedError("Access denied for enable key rotation operation")
        
        # Mock implementation - just validate the key exists
        pass
    
    def get_public_key(self, key_id: str) -> Dict[str, Any]:
        """Get public key for asymmetric keys."""
        if key_id not in self.keys:
            raise InvalidKeyIdError(f"Key '{key_id}' does not exist")
        
        key = self.keys[key_id]
        
        if key.key_spec == "SYMMETRIC_DEFAULT":
            raise InvalidParameterError("Cannot get public key for symmetric key")
        
        # Mock public key data
        public_key_data = secrets.randbits(2048).to_bytes(256, 'big')  # Mock RSA-2048 public key
        
        return {
            "KeyId": key.arn,
            "PublicKey": public_key_data,
            "KeyUsage": key.key_usage,
            "KeySpec": key.key_spec,
            "SigningAlgorithms": ["RSASSA_PSS_SHA_256", "RSASSA_PKCS1_V1_5_SHA_256"]
        }
    
    def simulate_error(self, error_type: str, key_id: Optional[str] = None) -> None:
        """Simulate various error conditions for testing."""
        if error_type == "access_denied" and key_id:
            self.access_policies[key_id] = {"denied_actions": ["kms:*"]}
        elif error_type == "key_disabled" and key_id:
            if key_id in self.keys:
                self.keys[key_id].enabled = False
        elif error_type == "invalid_key":
            # This will be handled by operations checking key existence
            pass
        elif error_type == "throttling":
            # Simulate rate limiting
            if not hasattr(self, '_throttle_count'):
                self._throttle_count = 0
            self._throttle_count += 1
        elif error_type == "kms_unavailable":
            # Simulate service unavailability
            self._service_unavailable = True
    
    def simulate_realistic_latency(self, operation: str) -> None:
        """Simulate realistic AWS KMS latency."""
        import time
        
        # Realistic latency patterns (in seconds)
        latencies = {
            "encrypt": 0.05,  # 50ms
            "decrypt": 0.08,  # 80ms
            "generate_data_key": 0.12,  # 120ms
            "create_key": 0.15,  # 150ms
            "describe_key": 0.03,  # 30ms
        }
        
        if operation in latencies and not os.getenv("__DEV_MODE__") == "test":
            time.sleep(latencies[operation])
    
    def reset(self) -> None:
        """Reset the mock service to initial state."""
        self.keys.clear()
        self.access_policies.clear()
        self._setup_default_keys()
        
        # Reset error states
        if hasattr(self, '_throttle_count'):
            self._throttle_count = 0
        if hasattr(self, '_service_unavailable'):
            self._service_unavailable = False


class MockKMSToolEnclaveClient:
    """
    Mock for the kmstool_enclave_cli tool used in Nitro Enclaves.
    
    This mock simulates the behavior of AWS KMS tool within enclaves,
    providing realistic command-line interface responses.
    """
    
    def __init__(self, kms_service: MockKMSService):
        self.kms_service = kms_service
        self.tool_path = "/app/kmstool_enclave_cli"
    
    def mock_subprocess_call(self, args: List[str], **kwargs) -> Mock:
        """Mock subprocess call to kmstool_enclave_cli."""
        mock_process = Mock()
        
        try:
            if len(args) < 2 or args[1] != "decrypt":
                mock_process.returncode = 1
                mock_process.communicate.return_value = (
                    b"",
                    b"Error: Invalid operation"
                )
                return mock_process
            
            # Extract parameters
            ciphertext = None
            key_id = None
            
            for i, arg in enumerate(args):
                if arg == "--ciphertext" and i + 1 < len(args):
                    ciphertext = args[i + 1]
                elif arg == "--key-id" and i + 1 < len(args):
                    key_id = args[i + 1]
            
            if not ciphertext:
                mock_process.returncode = 1
                mock_process.communicate.return_value = (
                    b"",
                    b"Error: No ciphertext provided"
                )
                return mock_process
            
            # Perform decryption
            result = self.kms_service.decrypt(ciphertext)
            plaintext = result["Plaintext"]
            
            # Format output like real kmstool
            encoded_plaintext = base64.standard_b64encode(plaintext).decode()
            output = f"PLAINTEXT:{encoded_plaintext}"
            
            mock_process.returncode = 0
            mock_process.communicate.return_value = (
                output.encode(),
                b""
            )
            
        except Exception as e:
            mock_process.returncode = 1
            mock_process.communicate.return_value = (
                b"",
                f"KMS decryption failed: {str(e)}".encode()
            )
        
        return mock_process
    
    def create_patches(self):
        """Create patches for subprocess calls to kmstool."""
        return patch('subprocess.Popen', side_effect=self.mock_subprocess_call)


def create_kms_mock(region: str = "us-east-1") -> MockKMSService:
    """Create a configured KMS mock for testing."""
    mock_service = MockKMSService(region)
    
    # Add some test data
    test_key_id = "test-master-seed-key"
    test_plaintext = secrets.randbits(256).to_bytes(32, 'big')  # 32-byte master seed
    
    # Create encrypted test data
    encrypted_result = mock_service.encrypt(test_key_id, test_plaintext)
    
    # Store test data as service attributes for easy access
    mock_service.test_key_id = test_key_id
    mock_service.test_plaintext = test_plaintext
    mock_service.test_ciphertext = encrypted_result["CiphertextBlob"]
    
    return mock_service


# Integration helpers for existing tests
def patch_kms_decrypt_master_seed(mock_service: MockKMSService):
    """Patch kms_decrypt_master_seed function to use mock service."""
    from application.starknet.enclave import aws_multiuser_integration
    
    def mock_decrypt(credential: Dict[str, str], ciphertext: str) -> bytes:
        try:
            result = mock_service.decrypt(ciphertext)
            return result["Plaintext"]
        except Exception as e:
            raise aws_multiuser_integration.KMSDecryptionError(f"KMS decryption failed: {e}")
    
    return patch.object(aws_multiuser_integration, 'kms_decrypt_master_seed', mock_decrypt)