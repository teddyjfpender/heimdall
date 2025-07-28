"""
Integration helpers for seamless testing with the existing codebase.

This module provides utilities to integrate AWS service mocks with the actual
application code, ensuring tests can run without real AWS dependencies while
maintaining realistic behavior patterns.
"""

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional, Callable, Union, List
from unittest.mock import Mock, patch, MagicMock

from .test_environment import TestEnvironmentManager
from .kms_mock import MockKMSService
from .secrets_manager_mock import MockSecretsManagerService
from .nitro_enclave_mock import MockNitroEnclaveService


class IntegrationError(Exception):
    """Base exception for integration errors."""
    pass


class MockAWSBoto3Client:
    """Universal boto3 client mock that routes to appropriate service mocks."""
    
    def __init__(self, service_name: str, env_manager: TestEnvironmentManager, **kwargs):
        self.service_name = service_name
        self.env_manager = env_manager
        self.region_name = kwargs.get('region_name', 'us-east-1')
        
        # Get the appropriate service mock
        if service_name == 'kms':
            self.service_mock = env_manager.get_kms_service()
        elif service_name == 'secretsmanager':
            self.service_mock = env_manager.get_secrets_manager_service()
        else:
            raise IntegrationError(f"Unsupported service: {service_name}")
    
    def __getattr__(self, name: str):
        """Route method calls to the appropriate service mock."""
        if hasattr(self.service_mock, name):
            method = getattr(self.service_mock, name)
            
            # Wrap method with latency simulation if available
            if hasattr(self.service_mock, 'simulate_realistic_latency'):
                def wrapped_method(*args, **kwargs):
                    self.service_mock.simulate_realistic_latency(name)
                    return method(*args, **kwargs)
                return wrapped_method
            
            return method
        
        # Handle boto3-specific method mappings
        if self.service_name == 'kms':
            return self._handle_kms_method(name)
        elif self.service_name == 'secretsmanager':
            return self._handle_secrets_method(name)
        
        raise AttributeError(f"'{self.service_name}' mock has no method '{name}'")
    
    def _handle_kms_method(self, method_name: str):
        """Handle KMS-specific method mappings."""
        kms = self.service_mock
        
        if method_name == 'encrypt':
            def encrypt(KeyId, Plaintext, EncryptionContext=None):
                return kms.encrypt(KeyId, Plaintext, EncryptionContext)
            return encrypt
        
        elif method_name == 'decrypt':
            def decrypt(CiphertextBlob, EncryptionContext=None):
                return kms.decrypt(CiphertextBlob, EncryptionContext)
            return decrypt
        
        elif method_name == 'describe_key':
            def describe_key(KeyId):
                return kms.describe_key(KeyId)
            return describe_key
        
        elif method_name == 'create_key':
            def create_key(Description=None, KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT"):
                return kms.create_key(Description, KeyUsage, KeySpec)
            return create_key
        
        elif method_name == 'generate_data_key':
            def generate_data_key(KeyId, KeySpec="AES_256", NumberOfBytes=None):
                return kms.generate_data_key(KeyId, KeySpec, NumberOfBytes)
            return generate_data_key
        
        elif method_name == 'generate_random':
            def generate_random(NumberOfBytes):
                return kms.generate_random(NumberOfBytes)
            return generate_random
        
        else:
            raise AttributeError(f"KMS method '{method_name}' not implemented")
    
    def _handle_secrets_method(self, method_name: str):
        """Handle Secrets Manager-specific method mappings."""
        secrets = self.service_mock
        
        if method_name == 'get_secret_value':
            def get_secret_value(SecretId, VersionId=None, VersionStage=None):
                return secrets.get_secret_value(SecretId, VersionId, VersionStage)
            return get_secret_value
        
        elif method_name == 'put_secret_value':
            def put_secret_value(SecretId, SecretString=None, SecretBinary=None, VersionStages=None):
                secret_value = SecretString or SecretBinary
                return secrets.put_secret_value(SecretId, secret_value, VersionStages)
            return put_secret_value
        
        elif method_name == 'create_secret':
            def create_secret(Name, SecretString=None, SecretBinary=None, Description=None, KmsKeyId=None, Tags=None):
                secret_value = SecretString or SecretBinary
                return secrets.create_secret(Name, secret_value, Description, KmsKeyId, Tags)
            return create_secret
        
        elif method_name == 'describe_secret':
            def describe_secret(SecretId):
                return secrets.describe_secret(SecretId)
            return describe_secret
        
        elif method_name == 'list_secrets':
            def list_secrets(MaxResults=None, Filters=None):
                return secrets.list_secrets(MaxResults, Filters)
            return list_secrets
        
        elif method_name == 'delete_secret':
            def delete_secret(SecretId, RecoveryWindowInDays=None, ForceDeleteWithoutRecovery=False):
                return secrets.delete_secret(SecretId, RecoveryWindowInDays, ForceDeleteWithoutRecovery)
            return delete_secret
        
        elif method_name == 'get_random_password':
            def get_random_password(**kwargs):
                return secrets.get_random_password(**kwargs)
            return get_random_password
        
        else:
            raise AttributeError(f"Secrets Manager method '{method_name}' not implemented")


class StarknetIntegrationHelper:
    """Helper for integrating with Starknet-specific application code."""
    
    def __init__(self, env_manager: TestEnvironmentManager):
        self.env_manager = env_manager
        self.patches = []
    
    def patch_aws_multiuser_integration(self):
        """Patch the AWS multiuser integration module."""
        try:
            # Import the module if it exists
            sys.path.append(str(Path(__file__).parent.parent.parent.parent / "application/starknet/enclave"))
            import aws_multiuser_integration
            
            kms = self.env_manager.get_kms_service()
            
            def mock_kms_decrypt_master_seed(credential: Dict[str, str], ciphertext: str) -> bytes:
                """Mock KMS decryption for master seed."""
                try:
                    result = kms.decrypt(ciphertext)
                    return result["Plaintext"]
                except Exception as e:
                    raise aws_multiuser_integration.KMSDecryptionError(f"KMS decryption failed: {e}")
            
            patch_obj = patch.object(
                aws_multiuser_integration, 
                'kms_decrypt_master_seed', 
                mock_kms_decrypt_master_seed
            )
            self.patches.append(patch_obj)
            return patch_obj
            
        except ImportError:
            # Module doesn't exist, create a mock patch
            def mock_kms_decrypt_master_seed(credential: Dict[str, str], ciphertext: str) -> bytes:
                kms = self.env_manager.get_kms_service()
                result = kms.decrypt(ciphertext)
                return result["Plaintext"]
            
            # Create a mock module
            mock_module = Mock()
            mock_module.kms_decrypt_master_seed = mock_kms_decrypt_master_seed
            mock_module.KMSDecryptionError = Exception
            
            patch_obj = patch.dict('sys.modules', {'aws_multiuser_integration': mock_module})
            self.patches.append(patch_obj)
            return patch_obj
    
    def patch_key_derivation(self):
        """Patch key derivation functions."""
        try:
            sys.path.append(str(Path(__file__).parent.parent.parent.parent / "application/starknet/enclave"))
            import key_derivation
            
            def mock_create_test_master_seed() -> bytes:
                """Create a test master seed."""
                return self.env_manager.services["secrets_manager"].test_master_seed
            
            patch_obj = patch.object(
                key_derivation,
                'create_test_master_seed',
                mock_create_test_master_seed
            )
            self.patches.append(patch_obj)
            return patch_obj
            
        except ImportError:
            # Create mock key derivation functions
            def mock_create_test_master_seed() -> bytes:
                import secrets
                return secrets.randbits(256).to_bytes(32, 'big')
            
            mock_module = Mock()
            mock_module.create_test_master_seed = mock_create_test_master_seed
            
            patch_obj = patch.dict('sys.modules', {'key_derivation': mock_module})
            self.patches.append(patch_obj)
            return patch_obj
    
    def patch_subprocess_kmstool(self):
        """Patch subprocess calls to kmstool_enclave_cli."""
        enclave = self.env_manager.get_nitro_enclave_service()
        
        def mock_popen(*args, **kwargs):
            if args and len(args[0]) > 1:
                cmd_args = args[0]
                if "kmstool_enclave_cli" in str(cmd_args[0]) and "decrypt" in cmd_args:
                    # Extract parameters
                    ciphertext = None
                    credentials = {}
                    
                    for i, arg in enumerate(cmd_args):
                        if str(arg) == "--ciphertext" and i + 1 < len(cmd_args):
                            ciphertext = str(cmd_args[i + 1])
                        elif str(arg) == "--aws-access-key-id" and i + 1 < len(cmd_args):
                            credentials["access_key_id"] = str(cmd_args[i + 1])
                        elif str(arg) == "--aws-secret-access-key" and i + 1 < len(cmd_args):
                            credentials["secret_access_key"] = str(cmd_args[i + 1])
                        elif str(arg) == "--aws-session-token" and i + 1 < len(cmd_args):
                            credentials["token"] = str(cmd_args[i + 1])
                    
                    try:
                        result = enclave.simulate_kmstool_call("decrypt", ciphertext, credentials)
                        
                        mock_process = Mock()
                        mock_process.returncode = 0
                        mock_process.communicate.return_value = (
                            f"PLAINTEXT:{result['plaintext_b64']}".encode(),
                            b""
                        )
                        return mock_process
                        
                    except Exception as e:
                        mock_process = Mock()
                        mock_process.returncode = 1
                        mock_process.communicate.return_value = (
                            b"",
                            f"KMS decryption failed: {str(e)}".encode()
                        )
                        return mock_process
            
            # Default mock for other subprocess calls
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"")
            return mock_process
        
        patch_obj = patch('subprocess.Popen', side_effect=mock_popen)
        self.patches.append(patch_obj)
        return patch_obj
    
    def start_patches(self):
        """Start all patches."""
        for patch_obj in self.patches:
            patch_obj.start()
    
    def stop_patches(self):
        """Stop all patches."""
        for patch_obj in self.patches:
            try:
                patch_obj.stop()
            except RuntimeError:
                pass  # Patch was not started


class UniversalAWSMockPatcher:
    """Universal patcher that intercepts all AWS SDK calls."""
    
    def __init__(self, env_manager: TestEnvironmentManager):
        self.env_manager = env_manager
        self.patches = []
    
    def patch_boto3_client(self):
        """Patch boto3.client to return mock clients."""
        def mock_boto3_client(service_name, **kwargs):
            return MockAWSBoto3Client(service_name, self.env_manager, **kwargs)
        
        patch_obj = patch('boto3.client', side_effect=mock_boto3_client)
        self.patches.append(patch_obj)
        return patch_obj
    
    def patch_boto3_session(self):
        """Patch boto3 Session to return mock clients."""
        def mock_session(*args, **kwargs):
            mock_session_obj = Mock()
            mock_session_obj.client.side_effect = lambda service_name, **kw: MockAWSBoto3Client(
                service_name, self.env_manager, **kw
            )
            return mock_session_obj
        
        patch_obj = patch('boto3.Session', side_effect=mock_session)
        self.patches.append(patch_obj)
        return patch_obj
    
    def patch_environment_variables(self):
        """Patch environment variables for testing."""
        test_env = {
            'AWS_REGION': self.env_manager.region,
            'AWS_DEFAULT_REGION': self.env_manager.region,
            'AWS_ACCESS_KEY_ID': 'test_access_key',
            'AWS_SECRET_ACCESS_KEY': 'test_secret_key',
            'AWS_SESSION_TOKEN': 'test_session_token',
            'REGION': self.env_manager.region,
        }
        
        patch_obj = patch.dict(os.environ, test_env)
        self.patches.append(patch_obj)
        return patch_obj
    
    def start_all_patches(self):
        """Start all patches."""
        for patch_obj in self.patches:
            patch_obj.start()
    
    def stop_all_patches(self):
        """Stop all patches."""
        for patch_obj in self.patches:
            try:
                patch_obj.stop()
            except RuntimeError:
                pass
    
    def __enter__(self):
        self.start_all_patches()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_all_patches()


def create_comprehensive_test_setup(region: str = "us-east-1") -> Dict[str, Any]:
    """
    Create a comprehensive test setup with all AWS service mocks and patches.
    
    Returns a dictionary with all necessary components for testing.
    """
    # Create environment manager
    env_manager = TestEnvironmentManager(region=region)
    
    # Create integration helpers
    starknet_helper = StarknetIntegrationHelper(env_manager)
    universal_patcher = UniversalAWSMockPatcher(env_manager)
    
    # Set up all patches
    patches = []
    
    # Universal AWS patches
    patches.extend([
        universal_patcher.patch_boto3_client(),
        universal_patcher.patch_boto3_session(),
        universal_patcher.patch_environment_variables(),
    ])
    
    # Starknet-specific patches
    patches.extend([
        starknet_helper.patch_aws_multiuser_integration(),
        starknet_helper.patch_key_derivation(),
        starknet_helper.patch_subprocess_kmstool(),
    ])
    
    return {
        'env_manager': env_manager,
        'starknet_helper': starknet_helper,
        'universal_patcher': universal_patcher,
        'patches': patches,
        'services': {
            'kms': env_manager.get_kms_service(),
            'secrets_manager': env_manager.get_secrets_manager_service(),
            'nitro_enclave': env_manager.get_nitro_enclave_service(),
        }
    }


def patch_application_imports():
    """
    Patch application imports to ensure modules can be imported in test environment.
    
    This is useful when running tests outside the application directory structure.
    """
    app_paths = [
        Path(__file__).parent.parent.parent.parent / "application/starknet/enclave",
        Path(__file__).parent.parent.parent.parent / "application/starknet/server",
        Path(__file__).parent.parent.parent.parent / "application/starknet/lambda",
    ]
    
    for path in app_paths:
        if path.exists() and str(path) not in sys.path:
            sys.path.insert(0, str(path))


class TestScenarioBuilder:
    """Builder for creating specific test scenarios."""
    
    def __init__(self, env_manager: TestEnvironmentManager):
        self.env_manager = env_manager
        self.scenario_data = {}
    
    def with_encrypted_master_seed(self, key_id: Optional[str] = None) -> 'TestScenarioBuilder':
        """Add encrypted master seed to the scenario."""
        kms = self.env_manager.get_kms_service()
        secrets_mgr = self.env_manager.get_secrets_manager_service()
        
        if key_id is None:
            key = kms.create_key(description="Master seed encryption key")
            key_id = key["KeyMetadata"]["KeyId"]
        
        master_seed = secrets_mgr.test_master_seed
        encrypted_result = kms.encrypt(key_id, master_seed)
        
        secrets_mgr.create_secret(
            "master-seed-encrypted",
            encrypted_result["CiphertextBlob"],
            description="Encrypted master seed"
        )
        
        self.scenario_data["master_seed"] = {
            "key_id": key_id,
            "secret_name": "master-seed-encrypted",
            "raw_seed": master_seed
        }
        return self
    
    def with_user_sessions(self, user_ids: List[str]) -> 'TestScenarioBuilder':
        """Add user sessions to the scenario."""
        kms = self.env_manager.get_kms_service()
        secrets_mgr = self.env_manager.get_secrets_manager_service()
        
        users = {}
        for user_id in user_ids:
            # Create user key
            user_key = kms.create_key(description=f"Key for user {user_id}")
            user_key_id = user_key["KeyMetadata"]["KeyId"]
            
            # Create user session
            session_data = {
                "user_id": user_id,
                "key_id": user_key_id,
                "permissions": ["starknet:sign", "starknet:derive_key"],
                "expires_at": int(time.time()) + 3600
            }
            
            secret_name = f"users/{user_id}/session"
            secrets_mgr.create_secret(secret_name, session_data)
            
            users[user_id] = {
                "key_id": user_key_id,
                "secret_name": secret_name,
                "session_data": session_data
            }
        
        self.scenario_data["users"] = users
        return self
    
    def with_enclave_attestation(self, enclave_id: Optional[str] = None) -> 'TestScenarioBuilder':
        """Add enclave attestation to the scenario."""
        enclave = self.env_manager.get_nitro_enclave_service()
        
        if enclave_id is None:
            enclave_config = enclave.create_enclave("/app/test_enclave.eif")
            enclave_id = enclave_config["EnclaveID"]
        
        user_data = b"test_attestation_data"
        attestation_doc = enclave.generate_attestation_document(enclave_id, user_data)
        
        self.scenario_data["attestation"] = {
            "enclave_id": enclave_id,
            "document": attestation_doc,
            "user_data": user_data
        }
        return self
    
    def build(self) -> Dict[str, Any]:
        """Build and return the complete scenario."""
        return self.scenario_data


# Convenience functions for common test patterns

def quick_aws_test_setup(services: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Quick setup for AWS service testing.
    
    Args:
        services: List of services to include ["kms", "secrets_manager", "nitro_enclave"]
                 If None, includes all services.
    
    Returns:
        Dictionary with service mocks and environment manager
    """
    if services is None:
        services = ["kms", "secrets_manager", "nitro_enclave"]
    
    env_manager = TestEnvironmentManager(auto_setup=False)
    
    result = {"env_manager": env_manager}
    
    if "kms" in services:
        from .kms_mock import create_kms_mock
        kms = create_kms_mock()
        env_manager.services["kms"] = kms
        result["kms"] = kms
    
    if "secrets_manager" in services:
        from .secrets_manager_mock import create_secrets_manager_mock
        secrets = create_secrets_manager_mock()
        env_manager.services["secrets_manager"] = secrets
        result["secrets_manager"] = secrets
    
    if "nitro_enclave" in services:
        from .nitro_enclave_mock import create_nitro_enclave_mock
        enclave = create_nitro_enclave_mock()
        env_manager.services["nitro_enclave"] = enclave
        result["nitro_enclave"] = enclave
    
    env_manager._setup_complete = True
    return result


def assert_starknet_key_format(key: Union[str, bytes]) -> None:
    """Assert that a key has valid Starknet format."""
    if isinstance(key, bytes):
        assert len(key) == 32, f"Starknet key must be 32 bytes, got {len(key)}"
    elif isinstance(key, str):
        assert key.startswith("0x"), "Starknet key must start with 0x"
        assert len(key) == 66, f"Starknet key must be 66 characters (0x + 64 hex), got {len(key)}"
        # Validate it's valid hex
        try:
            int(key, 16)
        except ValueError:
            raise AssertionError(f"Invalid hex format: {key}")
    else:
        raise AssertionError(f"Key must be str or bytes, got {type(key)}")


def assert_aws_arn_format(arn: str, service: str) -> None:
    """Assert that an ARN has valid AWS format."""
    assert isinstance(arn, str), "ARN must be a string"
    assert arn.startswith("arn:aws:"), "ARN must start with 'arn:aws:'"
    assert f":{service}:" in arn, f"ARN must contain service '{service}'"
    
    parts = arn.split(":")
    assert len(parts) >= 6, "ARN must have at least 6 parts separated by ':'"