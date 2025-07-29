"""
AWS Mock Fixtures for comprehensive test setup and teardown.

This module provides pytest fixtures and utility classes for easy integration
of AWS service mocks into test suites with proper setup and cleanup.
"""

import base64
import json
import secrets
import time
from typing import Dict, Any, Optional, List, Callable, Union
from unittest.mock import Mock, patch

import pytest

from .test_environment import TestEnvironmentManager, create_integrated_test_scenario
from .kms_mock import MockKMSService
from .secrets_manager_mock import MockSecretsManagerService  
from .nitro_enclave_mock import MockNitroEnclaveService


class AWSMockFixtures:
    """
    Comprehensive fixture management for AWS service mocks.
    
    This class provides a centralized way to manage test fixtures, handle
    common test patterns, and provide convenient access to mock services.
    """
    
    def __init__(self, env_manager: TestEnvironmentManager):
        self.env_manager = env_manager
        self.test_data: Dict[str, Any] = {}
        self.cleanup_callbacks: List[Callable] = []
        self._setup_test_data()
    
    def _setup_test_data(self) -> None:
        """Set up common test data across all services."""
        # Starknet test vectors
        self.test_data["starknet"] = {
            "private_keys": [
                "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "0x1111111111111111111111111111111111111111111111111111111111111111",
                "0x2222222222222222222222222222222222222222222222222222222222222222"
            ],
            "addresses": [
                "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                "0x02b5ce4d999c9cc7c6c6cc7e7f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
                "0x03c6df5e111d1dd8d7d7dd8f8g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7"
            ],
            "transactions": [
                {
                    "version": 1,
                    "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                    "entry_point_selector": "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                    "calldata": ["0x123", "0x456"],
                    "max_fee": "0x16345785d8a0000",
                    "nonce": 1,
                    "chain_id": "SN_GOERLI"
                }
            ]
        }
        
        # AWS test credentials
        self.test_data["credentials"] = {
            "primary": {
                "access_key_id": "AKIA_TEST_PRIMARY",
                "secret_access_key": "test_primary_secret",
                "token": "test_primary_token"
            },
            "secondary": {
                "access_key_id": "AKIA_TEST_SECONDARY", 
                "secret_access_key": "test_secondary_secret",
                "token": "test_secondary_token"
            }
        }
        
        # Test master seeds and encryption keys
        self.test_data["crypto"] = {
            "master_seed": secrets.randbits(256).to_bytes(32, 'big'),
            "user_seeds": {
                f"user_{i}": secrets.randbits(256).to_bytes(32, 'big')
                for i in range(5)
            },
            "encryption_keys": {
                f"key_{i}": secrets.randbits(256).to_bytes(32, 'big')
                for i in range(3)
            }
        }
    
    def get_kms_service(self) -> MockKMSService:
        """Get KMS service mock."""
        return self.env_manager.get_kms_service()
    
    def get_secrets_manager_service(self) -> MockSecretsManagerService:
        """Get Secrets Manager service mock."""
        return self.env_manager.get_secrets_manager_service()
    
    def get_nitro_enclave_service(self) -> MockNitroEnclaveService:
        """Get Nitro Enclave service mock."""
        return self.env_manager.get_nitro_enclave_service()
    
    def create_test_user_session(self, user_id: str, permissions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Create a test user session with proper credentials and secrets."""
        if permissions is None:
            permissions = ["starknet:sign", "starknet:derive_key"]
        
        # Generate user credentials
        credentials = self.env_manager.create_test_credentials(user_id)
        
        # Create user-specific KMS key
        kms = self.get_kms_service()
        user_key = kms.create_key(description=f"Key for user {user_id}")
        user_key_id = user_key["KeyMetadata"]["KeyId"]
        
        # Create user seed
        user_seed = secrets.randbits(256).to_bytes(32, 'big')
        
        # Encrypt user seed with KMS
        encrypted_seed = kms.encrypt(user_key_id, user_seed)
        
        # Store in Secrets Manager
        secrets_manager = self.get_secrets_manager_service()
        session_data = {
            "user_id": user_id,
            "credentials": credentials,
            "encrypted_seed": encrypted_seed["CiphertextBlob"].decode() if isinstance(
                encrypted_seed["CiphertextBlob"], bytes) else encrypted_seed["CiphertextBlob"],
            "key_id": user_key_id,
            "permissions": permissions,
            "created_at": int(time.time()),
            "expires_at": int(time.time()) + 3600
        }
        
        secret_name = f"users/{user_id}/session"
        secrets_manager.create_secret(
            secret_name,
            session_data,
            description=f"Session data for user {user_id}"
        )
        
        return {
            "user_id": user_id,
            "credentials": credentials,
            "key_id": user_key_id,
            "secret_name": secret_name,
            "session_data": session_data,
            "raw_seed": user_seed
        }
    
    def create_encrypted_master_seed(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """Create an encrypted master seed for testing."""
        kms = self.get_kms_service()
        
        if key_id is None:
            # Create a new key for the master seed
            master_key = kms.create_key(description="Master seed encryption key")
            key_id = master_key["KeyMetadata"]["KeyId"]
        
        master_seed = self.test_data["crypto"]["master_seed"]
        encrypted_result = kms.encrypt(key_id, master_seed)
        
        # Store in Secrets Manager
        secrets_manager = self.get_secrets_manager_service()
        secret_name = "master-seed-encrypted"
        secrets_manager.create_secret(
            secret_name,
            encrypted_result["CiphertextBlob"],
            description="Encrypted master seed for key derivation"
        )
        
        return {
            "key_id": key_id,
            "secret_name": secret_name,
            "encrypted_blob": encrypted_result["CiphertextBlob"],
            "raw_seed": master_seed
        }
    
    def create_test_transaction_payload(self, transaction_type: str = "invoke") -> Dict[str, Any]:
        """Create a test transaction payload."""
        base_payload = {
            "credential": self.test_data["credentials"]["primary"],
            "network": "goerli",
            "cairo_version": "1"
        }
        
        if transaction_type == "invoke":
            base_payload["transaction_payload"] = self.test_data["starknet"]["transactions"][0].copy()
        elif transaction_type == "declare":
            base_payload["transaction_payload"] = {
                "version": 2,
                "contract_class_hash": "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
                "sender_address": self.test_data["starknet"]["addresses"][0],
                "max_fee": "0x5af3107a4000",
                "nonce": 1,
                "chain_id": "SN_GOERLI"
            }
        else:
            raise ValueError(f"Unknown transaction type: {transaction_type}")
        
        return base_payload
    
    def create_enclave_attestation_scenario(self) -> Dict[str, Any]:
        """Create a test scenario for enclave attestation."""
        enclave = self.get_nitro_enclave_service()
        
        # Create test enclave
        enclave_config = enclave.create_enclave(
            "/app/test_enclave.eif",
            cpu_count=2,
            memory_mib=512,
            debug_mode=True
        )
        
        enclave_id = enclave_config["EnclaveID"]
        
        # Generate attestation document
        user_data = b"test_attestation_data"
        attestation_doc = enclave.generate_attestation_document(
            enclave_id,
            user_data=user_data
        )
        
        # Get PCR measurements for verification
        doc_data = json.loads(base64.b64decode(attestation_doc).decode())
        pcr_measurements = doc_data["pcrs"]
        
        return {
            "enclave_id": enclave_id,
            "enclave_config": enclave_config,
            "attestation_document": attestation_doc,
            "user_data": user_data,
            "pcr_measurements": pcr_measurements
        }
    
    def simulate_kmstool_scenario(self, success: bool = True) -> Dict[str, Any]:
        """Set up a kmstool decryption scenario."""
        # Create encrypted data that kmstool would decrypt
        kms = self.get_kms_service()
        key_id = list(kms.keys.keys())[0]  # Use first available key
        
        test_data = self.test_data["crypto"]["master_seed"]
        encrypted_result = kms.encrypt(key_id, test_data)
        
        credentials = self.test_data["credentials"]["primary"]
        
        if success:
            # Configure enclave to return successful decryption
            enclave = self.get_nitro_enclave_service()
            result = enclave.simulate_kmstool_call(
                "decrypt",
                encrypted_result["CiphertextBlob"],
                credentials
            )
            
            return {
                "success": True,
                "key_id": key_id,
                "ciphertext": encrypted_result["CiphertextBlob"],
                "credentials": credentials,
                "expected_plaintext": test_data,
                "kmstool_result": result
            }
        else:
            # Simulate failure scenario
            return {
                "success": False,
                "key_id": key_id,
                "ciphertext": encrypted_result["CiphertextBlob"],
                "credentials": credentials,
                "error": "Mock KMS decryption failure"
            }
    
    def create_performance_test_data(self, num_users: int = 100) -> Dict[str, Any]:
        """Create test data for performance testing."""
        users = []
        
        for i in range(num_users):
            user_id = f"perf_user_{i:04d}"
            user_session = self.create_test_user_session(user_id)
            users.append(user_session)
        
        # Create batch transaction payloads
        transactions = []
        for i in range(num_users * 3):  # 3 transactions per user
            tx = self.create_test_transaction_payload("invoke")
            tx["transaction_payload"]["nonce"] = i % 10
            transactions.append(tx)
        
        return {
            "users": users,
            "transactions": transactions,
            "num_users": num_users,
            "total_transactions": len(transactions)
        }
    
    def setup_error_scenarios(self) -> Dict[str, Callable]:
        """Set up various error scenarios for testing."""
        scenarios = {}
        
        # KMS errors
        def trigger_kms_access_denied():
            kms = self.get_kms_service()
            key_id = list(kms.keys.keys())[0]
            kms.simulate_error("access_denied", key_id)
        
        def trigger_kms_key_disabled():
            kms = self.get_kms_service()
            key_id = list(kms.keys.keys())[0]
            kms.simulate_error("key_disabled", key_id)
        
        scenarios["kms_access_denied"] = trigger_kms_access_denied
        scenarios["kms_key_disabled"] = trigger_kms_key_disabled
        
        # Secrets Manager errors
        def trigger_secrets_access_denied():
            secrets = self.get_secrets_manager_service()
            secret_name = list(secrets.secrets.keys())[0]
            secrets.simulate_error("access_denied", secret_name)
        
        scenarios["secrets_access_denied"] = trigger_secrets_access_denied
        
        # Enclave errors
        def trigger_enclave_crashed():
            enclave = self.get_nitro_enclave_service()
            enclave_id = list(enclave.enclaves.keys())[0]
            enclave.simulate_error("enclave_crashed", enclave_id)
        
        def trigger_attestation_failure():
            enclave = self.get_nitro_enclave_service()
            enclave.simulate_error("attestation_failure")
        
        scenarios["enclave_crashed"] = trigger_enclave_crashed
        scenarios["attestation_failure"] = trigger_attestation_failure
        
        return scenarios
    
    def validate_test_environment(self) -> Dict[str, Any]:
        """Validate that the test environment is properly configured."""
        return self.env_manager.validate_service_integration()
    
    def add_cleanup_callback(self, callback: Callable) -> None:
        """Add a cleanup callback to be executed during teardown."""
        self.cleanup_callbacks.append(callback)
    
    def cleanup(self) -> None:
        """Perform cleanup operations."""
        # Execute cleanup callbacks
        for callback in self.cleanup_callbacks:
            try:
                callback()
            except Exception as e:
                # Log error but continue cleanup
                print(f"Cleanup callback failed: {e}")
        
        self.cleanup_callbacks.clear()
        
        # Reset services
        self.env_manager.reset_services()


# Pytest fixtures

@pytest.fixture(scope="session")
def aws_test_environment():
    """Session-scoped AWS test environment."""
    env_manager = TestEnvironmentManager()
    
    with env_manager:
        yield env_manager




@pytest.fixture(scope="function")
def aws_test_environment():
    """AWS test environment fixture."""
    from .test_environment import aws_test_environment as aws_env_context
    with aws_env_context() as env:
        yield env


@pytest.fixture(scope="function") 
def aws_mock_fixtures(aws_test_environment):
    """Function-scoped AWS mock fixtures."""
    fixtures = AWSMockFixtures(aws_test_environment)
    yield fixtures
    fixtures.cleanup()


@pytest.fixture(scope="function")
def kms_service(aws_mock_fixtures):
    """KMS service mock fixture."""
    return aws_mock_fixtures.get_kms_service()


@pytest.fixture(scope="function")
def secrets_manager_service(aws_mock_fixtures):
    """Secrets Manager service mock fixture."""
    return aws_mock_fixtures.get_secrets_manager_service()


@pytest.fixture(scope="function") 
def nitro_enclave_service(aws_mock_fixtures):
    """Nitro Enclave service mock fixture."""
    return aws_mock_fixtures.get_nitro_enclave_service()


@pytest.fixture(scope="function")
def test_user_session(aws_mock_fixtures):
    """Create a test user session."""
    return aws_mock_fixtures.create_test_user_session("test_user")


@pytest.fixture(scope="function")
def encrypted_master_seed(aws_mock_fixtures):
    """Create an encrypted master seed."""
    return aws_mock_fixtures.create_encrypted_master_seed()


@pytest.fixture(scope="function")
def starknet_transaction_payload(aws_mock_fixtures):
    """Create a Starknet transaction payload."""
    return aws_mock_fixtures.create_test_transaction_payload("invoke")


@pytest.fixture(scope="function")
def enclave_attestation_scenario(aws_mock_fixtures):
    """Create an enclave attestation test scenario."""
    return aws_mock_fixtures.create_enclave_attestation_scenario()


@pytest.fixture(scope="function")
def performance_test_data(aws_mock_fixtures):
    """Create performance test data."""
    return aws_mock_fixtures.create_performance_test_data(10)  # 10 users for tests


@pytest.fixture(scope="function")
def error_scenarios(aws_mock_fixtures):
    """Set up error scenarios."""
    return aws_mock_fixtures.setup_error_scenarios()


# Specialized scenario fixtures

@pytest.fixture(scope="function")
def starknet_basic_scenario():
    """Basic Starknet testing scenario."""
    env_manager = create_integrated_test_scenario("starknet_basic")
    fixtures = AWSMockFixtures(env_manager)
    
    with env_manager:
        yield fixtures
        fixtures.cleanup()


@pytest.fixture(scope="function")
def starknet_multiuser_scenario():
    """Multi-user Starknet testing scenario."""
    env_manager = create_integrated_test_scenario("starknet_multiuser")
    fixtures = AWSMockFixtures(env_manager)
    
    with env_manager:
        yield fixtures
        fixtures.cleanup()


@pytest.fixture(scope="function")
def enclave_attestation_test_scenario():
    """Enclave attestation testing scenario."""
    env_manager = create_integrated_test_scenario("enclave_attestation")
    fixtures = AWSMockFixtures(env_manager)
    
    with env_manager:
        yield fixtures
        fixtures.cleanup()


@pytest.fixture(scope="function")
def kms_secrets_integration_scenario():
    """KMS and Secrets Manager integration testing scenario."""
    env_manager = create_integrated_test_scenario("kms_secrets_integration")
    fixtures = AWSMockFixtures(env_manager)
    
    with env_manager:
        yield fixtures
        fixtures.cleanup()


# Utility functions for test setup

def create_custom_test_scenario(services: List[str], region: str = "us-east-1") -> AWSMockFixtures:
    """Create a custom test scenario with specific services."""
    env_manager = TestEnvironmentManager(region=region, auto_setup=False)
    
    # Initialize only requested services
    if "kms" in services:
        from .kms_mock import create_kms_mock
        env_manager.services["kms"] = create_kms_mock(region)
    
    if "secrets_manager" in services:
        from .secrets_manager_mock import create_secrets_manager_mock
        env_manager.services["secrets_manager"] = create_secrets_manager_mock(region)
    
    if "nitro_enclave" in services:
        from .nitro_enclave_mock import create_nitro_enclave_mock
        env_manager.services["nitro_enclave"] = create_nitro_enclave_mock(region)
    
    env_manager._setup_complete = True
    return AWSMockFixtures(env_manager)


def assert_valid_starknet_signature(signature: Dict[str, str]) -> None:
    """Assert that a signature has valid Starknet format."""
    assert "r" in signature, "Signature missing 'r' component"
    assert "s" in signature, "Signature missing 's' component"
    
    # Validate hex format
    assert signature["r"].startswith("0x"), "Signature 'r' must be hex"
    assert signature["s"].startswith("0x"), "Signature 's' must be hex"
    
    # Validate lengths (64 hex characters = 32 bytes)
    assert len(signature["r"]) == 66, f"Invalid 'r' length: {len(signature['r'])}"
    assert len(signature["s"]) == 66, f"Invalid 's' length: {len(signature['s'])}"


def assert_valid_aws_credentials(credentials: Dict[str, str]) -> None:
    """Assert that AWS credentials have valid format."""
    required_fields = ["access_key_id", "secret_access_key", "token"]
    
    for field in required_fields:
        assert field in credentials, f"Missing credential field: {field}"
        assert isinstance(credentials[field], str), f"Credential field {field} must be string"
        assert len(credentials[field]) > 0, f"Credential field {field} cannot be empty"


def assert_valid_enclave_attestation(attestation_doc: bytes) -> None:
    """Assert that an attestation document has valid format."""
    assert isinstance(attestation_doc, bytes), "Attestation document must be bytes"
    assert len(attestation_doc) > 0, "Attestation document cannot be empty"
    
    # Decode and validate structure
    try:
        decoded = base64.b64decode(attestation_doc)
        doc_data = json.loads(decoded.decode())
        
        required_fields = ["module_id", "timestamp", "digest", "pcrs", "certificate"]
        for field in required_fields:
            assert field in doc_data, f"Missing attestation field: {field}"
            
    except (json.JSONDecodeError, ValueError) as e:
        pytest.fail(f"Invalid attestation document format: {e}")