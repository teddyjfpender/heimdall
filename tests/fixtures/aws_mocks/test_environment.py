"""
Test environment manager for orchestrating AWS service mocks.

This module provides a centralized way to manage all AWS service mocks,
coordinate their interactions, and provide realistic testing scenarios.
"""

import os
import tempfile
import time
from contextlib import contextmanager
from typing import Dict, Any, Optional, List, Union
from unittest.mock import patch, Mock

from .kms_mock import MockKMSService, create_kms_mock
from .secrets_manager_mock import MockSecretsManagerService, create_secrets_manager_mock
from .nitro_enclave_mock import MockNitroEnclaveService, create_nitro_enclave_mock, MockNitroEnclavePatches


class TestEnvironmentError(Exception):
    """Base exception for test environment errors."""
    pass


class ServiceIntegrationError(TestEnvironmentError):
    """Raised when service integration fails."""
    pass


class TestEnvironmentManager:
    """
    Centralized manager for AWS service mocks and test environment setup.
    
    This manager coordinates multiple AWS service mocks to provide realistic
    testing scenarios with proper service interactions and state management.
    """
    
    def __init__(self, region: str = "us-east-1", auto_setup: bool = True):
        self.region = region
        self.services: Dict[str, Any] = {}
        self.patches: List[Any] = []
        self.temp_files: List[str] = []
        self.environment_backup: Dict[str, str] = {}
        self._setup_complete = False
        
        if auto_setup:
            self.setup_services()
    
    def setup_services(self) -> None:
        """Initialize all AWS service mocks."""
        if self._setup_complete:
            return
        
        # Initialize service mocks
        self.services["kms"] = create_kms_mock(self.region)
        self.services["secrets_manager"] = create_secrets_manager_mock(self.region)
        self.services["nitro_enclave"] = create_nitro_enclave_mock(self.region)
        
        # Configure service interactions
        self._configure_service_interactions()
        
        self._setup_complete = True
    
    def _configure_service_interactions(self) -> None:
        """Configure realistic interactions between services."""
        kms = self.services["kms"]
        secrets = self.services["secrets_manager"]
        enclave = self.services["nitro_enclave"]
        
        # Create integrated test scenarios
        self._setup_starknet_scenario(kms, secrets, enclave)
        self._setup_multiuser_scenario(kms, secrets, enclave)
    
    def _setup_starknet_scenario(self, kms, secrets, enclave):
        """Set up Starknet-specific test scenario."""
        # Create KMS key for Starknet master seed
        starknet_key = kms.create_key(
            description="Starknet master seed encryption key",
            key_usage="ENCRYPT_DECRYPT"
        )
        starknet_key_id = starknet_key["KeyMetadata"]["KeyId"]
        
        # Create encrypted master seed
        master_seed = secrets.test_master_seed  # From secrets manager mock
        encrypted_result = kms.encrypt(starknet_key_id, master_seed)
        
        # Store in secrets manager
        secrets.create_secret(
            "starknet/encrypted-master-seed",
            encrypted_result["CiphertextBlob"],
            description="Encrypted Starknet master seed"
        )
        
        # Configure enclave environment
        enclave.set_environment_variable("STARKNET_KMS_KEY_ID", starknet_key_id)
        enclave.set_environment_variable("STARKNET_MASTER_SEED_SECRET", "starknet/encrypted-master-seed")
        
        # Store references for easy access
        self.starknet_key_id = starknet_key_id
        self.starknet_encrypted_seed = encrypted_result["CiphertextBlob"]
    
    def _setup_multiuser_scenario(self, kms, secrets, enclave):
        """Set up multi-user test scenario."""
        # Create user-specific keys and secrets
        test_users = ["alice", "bob", "charlie"]
        
        for user in test_users:
            # Create user-specific KMS key
            user_key = kms.create_key(
                description=f"Key for user {user}",
                key_usage="ENCRYPT_DECRYPT"
            )
            user_key_id = user_key["KeyMetadata"]["KeyId"]
            
            # Create user session data
            session_data = {
                "user_id": user,
                "session_token": f"session_{user}_{int(time.time())}",
                "permissions": ["starknet:sign", "starknet:derive_key"],
                "expires_at": int(time.time()) + 3600  # 1 hour from now
            }
            
            # Store user session in secrets manager
            secrets.create_secret(
                f"users/{user}/session",
                session_data,
                description=f"Session data for user {user}"
            )
            
            # Store user key ID reference
            setattr(self, f"{user}_key_id", user_key_id)
    
    def get_service(self, service_name: str) -> Any:
        """Get a specific service mock."""
        if service_name not in self.services:
            raise TestEnvironmentError(f"Service '{service_name}' not found")
        return self.services[service_name]
    
    def get_kms_service(self) -> MockKMSService:
        """Get KMS service mock."""
        return self.get_service("kms")
    
    def get_secrets_manager_service(self) -> MockSecretsManagerService:
        """Get Secrets Manager service mock."""
        return self.get_service("secrets_manager")
    
    def get_nitro_enclave_service(self) -> MockNitroEnclaveService:
        """Get Nitro Enclave service mock."""
        return self.get_service("nitro_enclave")
    
    def create_test_credentials(self, user_id: str = "test-user") -> Dict[str, str]:
        """Create mock AWS credentials for testing."""
        return {
            "access_key_id": f"AKIA_TEST_{user_id.upper()}",
            "secret_access_key": f"test_secret_key_{user_id}",
            "token": f"test_session_token_{user_id}_{int(time.time())}"
        }
    
    def setup_test_environment_variables(self, extra_vars: Optional[Dict[str, str]] = None) -> None:
        """Set up test environment variables."""
        # Backup current environment
        test_vars = {
            "AWS_REGION": self.region,
            "AWS_DEFAULT_REGION": self.region,
            "AWS_ACCESS_KEY_ID": "test_access_key",
            "AWS_SECRET_ACCESS_KEY": "test_secret_key",
            "AWS_SESSION_TOKEN": "test_session_token",
            "REGION": self.region,
            "LOG_LEVEL": "DEBUG",
            "__DEV_MODE__": "test",
            "NITRO_CLI_TIMEOUT": "30",
            "ENCLAVE_CPU_COUNT": "2",
            "ENCLAVE_MEMORY_MIB": "512"
        }
        
        if extra_vars:
            test_vars.update(extra_vars)
        
        for key, value in test_vars.items():
            if key in os.environ:
                self.environment_backup[key] = os.environ[key]
            os.environ[key] = value
    
    def restore_environment_variables(self) -> None:
        """Restore original environment variables."""
        # Remove test variables and restore originals
        test_vars = [
            "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "REGION",
            "LOG_LEVEL", "__DEV_MODE__", "NITRO_CLI_TIMEOUT",
            "ENCLAVE_CPU_COUNT", "ENCLAVE_MEMORY_MIB"
        ]
        
        for key in test_vars:
            if key in self.environment_backup:
                os.environ[key] = self.environment_backup[key]
            elif key in os.environ:
                del os.environ[key]
        
        self.environment_backup.clear()
    
    def create_temp_kmstool_binary(self) -> str:
        """Create a temporary mock kmstool binary for testing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix="_kmstool", delete=False) as f:
            f.write("""#!/bin/bash
if [ "$1" = "decrypt" ]; then
    # Extract ciphertext from arguments
    CIPHERTEXT=""
    for i in "$@"; do
        if [ "$prev_arg" = "--ciphertext" ]; then
            CIPHERTEXT="$i"
            break
        fi
        prev_arg="$i"
    done
    
    if [ -z "$CIPHERTEXT" ]; then
        echo "Error: No ciphertext provided" >&2
        exit 1
    fi
    
    # Mock successful decryption - return test master seed
    echo "PLAINTEXT:$(echo "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" | base64 -w 0)"
else
    echo "Unknown operation: $1" >&2
    exit 1
fi
""")
            f.flush()
            os.chmod(f.name, 0o755)
            self.temp_files.append(f.name)
            return f.name
    
    def setup_patches(self) -> None:
        """Set up all necessary patches for testing."""
        # Patch KMS boto3 client
        kms_service = self.get_kms_service()
        
        def mock_kms_client(*args, **kwargs):
            mock_client = Mock()
            mock_client.encrypt.side_effect = lambda **kw: kms_service.encrypt(
                kw["KeyId"], kw["Plaintext"], kw.get("EncryptionContext")
            )
            mock_client.decrypt.side_effect = lambda **kw: kms_service.decrypt(
                kw["CiphertextBlob"], kw.get("EncryptionContext")
            )
            mock_client.describe_key.side_effect = lambda **kw: kms_service.describe_key(kw["KeyId"])
            mock_client.create_key.side_effect = lambda **kw: kms_service.create_key(**kw)
            return mock_client
        
        kms_patch = patch("boto3.client", side_effect=lambda service, **kwargs: 
                         mock_kms_client() if service == "kms" else Mock())
        self.patches.append(kms_patch)
        
        # Patch Secrets Manager boto3 client
        secrets_service = self.get_secrets_manager_service()
        
        def mock_secrets_client(*args, **kwargs):
            mock_client = Mock()
            mock_client.get_secret_value.side_effect = lambda **kw: secrets_service.get_secret_value(**kw)
            mock_client.create_secret.side_effect = lambda **kw: secrets_service.create_secret(**kw)
            mock_client.put_secret_value.side_effect = lambda **kw: secrets_service.put_secret_value(**kw)
            return mock_client
        
        secrets_patch = patch("boto3.client", side_effect=lambda service, **kwargs:
                             mock_secrets_client() if service == "secretsmanager" else Mock())
        self.patches.append(secrets_patch)
        
        # Patch Nitro Enclave environment
        enclave_service = self.get_nitro_enclave_service()
        enclave_patches = MockNitroEnclavePatches(enclave_service)
        enclave_patches.patch_subprocess_popen()
        enclave_patches.patch_socket_vsock()
        enclave_patches.patch_environment_checks()
        self.patches.extend(enclave_patches.patches)
    
    def start_patches(self) -> None:
        """Start all patches."""
        for patch_obj in self.patches:
            patch_obj.start()
    
    def stop_patches(self) -> None:
        """Stop all patches."""
        for patch_obj in self.patches:
            try:
                patch_obj.stop()
            except RuntimeError:
                # Patch was not started or already stopped
                pass
    
    def cleanup_temp_files(self) -> None:
        """Clean up temporary files."""
        for temp_file in self.temp_files:
            try:
                os.unlink(temp_file)
            except (OSError, FileNotFoundError):
                pass
        self.temp_files.clear()
    
    def reset_services(self) -> None:
        """Reset all services to initial state."""
        for service in self.services.values():
            if hasattr(service, 'reset'):
                service.reset()
    
    def simulate_service_error(self, service_name: str, error_type: str, **kwargs) -> None:
        """Simulate errors in specific services."""
        if service_name not in self.services:
            raise TestEnvironmentError(f"Service '{service_name}' not found")
        
        service = self.services[service_name]
        if hasattr(service, 'simulate_error'):
            service.simulate_error(error_type, **kwargs)
        else:
            raise TestEnvironmentError(f"Service '{service_name}' does not support error simulation")
    
    def validate_service_integration(self) -> Dict[str, Any]:
        """Validate that all services are properly integrated."""
        validation_results = {
            "valid": True,
            "services": {},
            "integration_tests": {}
        }
        
        # Check individual services
        for service_name, service in self.services.items():
            try:
                if hasattr(service, 'validate_service'):
                    service_validation = service.validate_service()
                else:
                    service_validation = {"status": "available", "healthy": True}
                
                validation_results["services"][service_name] = service_validation
            except Exception as e:
                validation_results["services"][service_name] = {
                    "status": "error",
                    "error": str(e),
                    "healthy": False
                }
                validation_results["valid"] = False
        
        # Check KMS + Secrets Manager integration
        try:
            kms = self.get_kms_service()
            secrets = self.get_secrets_manager_service()
            
            # Test encrypt/decrypt flow
            test_data = b"integration_test_data"
            key_id = list(kms.keys.keys())[0]  # Use first available key
            
            # Encrypt with KMS
            encrypted = kms.encrypt(key_id, test_data)
            
            # Store in Secrets Manager
            secret_name = "integration-test-secret"
            secrets.create_secret(secret_name, encrypted["CiphertextBlob"])
            
            # Retrieve from Secrets Manager
            retrieved = secrets.get_secret_value(secret_name)
            
            # Decrypt with KMS
            decrypted = kms.decrypt(retrieved["SecretString"])
            
            integration_success = decrypted["Plaintext"] == test_data
            validation_results["integration_tests"]["kms_secrets"] = {
                "success": integration_success,
                "details": "KMS encryption + Secrets Manager storage + KMS decryption"
            }
            
            if not integration_success:
                validation_results["valid"] = False
            
        except Exception as e:
            validation_results["integration_tests"]["kms_secrets"] = {
                "success": False,
                "error": str(e)
            }
            validation_results["valid"] = False
        
        return validation_results
    
    def __enter__(self):
        """Context manager entry."""
        self.setup_test_environment_variables()
        self.setup_patches()
        self.start_patches()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.stop_patches()
        self.restore_environment_variables()
        self.cleanup_temp_files()


@contextmanager
def aws_test_environment(region: str = "us-east-1", **kwargs):
    """
    Context manager for setting up a complete AWS test environment.
    
    Usage:
        with aws_test_environment() as env:
            kms = env.get_kms_service()
            secrets = env.get_secrets_manager_service()
            # ... perform tests
    """
    env_manager = TestEnvironmentManager(region=region, **kwargs)
    
    with env_manager:
        yield env_manager


def create_integrated_test_scenario(scenario_name: str, region: str = "us-east-1") -> TestEnvironmentManager:
    """
    Create predefined integrated test scenarios.
    
    Available scenarios:
    - "starknet_basic": Basic Starknet wallet functionality
    - "starknet_multiuser": Multi-user Starknet environment  
    - "enclave_attestation": Nitro Enclave attestation testing
    - "kms_secrets_integration": KMS and Secrets Manager integration
    """
    env_manager = TestEnvironmentManager(region=region)
    
    if scenario_name == "starknet_basic":
        # Basic Starknet scenario is already set up in _setup_starknet_scenario
        pass
    
    elif scenario_name == "starknet_multiuser":
        # Multi-user scenario is already set up in _setup_multiuser_scenario  
        pass
    
    elif scenario_name == "enclave_attestation":
        # Set up enclave-specific testing
        enclave = env_manager.get_nitro_enclave_service()
        
        # Create multiple enclaves for testing
        test_enclaves = []
        for i in range(3):
            enclave_config = enclave.create_enclave(
                f"/app/test_enclave_{i}.eif",
                cpu_count=2,
                memory_mib=256,
                debug_mode=True
            )
            test_enclaves.append(enclave_config)
        
        env_manager.test_enclaves = test_enclaves
    
    elif scenario_name == "kms_secrets_integration":
        # Enhanced KMS + Secrets Manager testing
        kms = env_manager.get_kms_service()
        secrets = env_manager.get_secrets_manager_service()
        
        # Create multiple keys for different purposes
        key_purposes = ["master-seed", "user-data", "transaction-signing", "backup"]
        for purpose in key_purposes:
            key = kms.create_key(description=f"Key for {purpose}")
            key_id = key["KeyMetadata"]["KeyId"]
            setattr(env_manager, f"{purpose.replace('-', '_')}_key_id", key_id)
    
    else:
        raise TestEnvironmentError(f"Unknown scenario: {scenario_name}")
    
    return env_manager