"""Test configuration and shared fixtures for AWS Nitro Enclave Blockchain Wallet."""

import base64
import json
import os
import tempfile
from unittest.mock import Mock, patch

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(scope="session")
def aws_credentials():
    """Mock AWS credentials for testing."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def test_region():
    """Test AWS region."""
    return "us-east-1"


@pytest.fixture
def test_ethereum_private_key():
    """Test Ethereum private key (secp256k1)."""
    return "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"


@pytest.fixture
def test_ethereum_address():
    """Test Ethereum address corresponding to the test private key."""
    return "0x742d35Cc6634C0532925a3b8D8f8e57C25B8C8A7"


@pytest.fixture
def test_transaction_dict():
    """Test Ethereum transaction dictionary."""
    return {
        "value": 0.01,
        "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
        "nonce": 0,
        "gas": 100000,
        "gasPrice": 100000000000,
    }


@pytest.fixture
def test_credentials():
    """Test AWS credentials payload."""
    return {
        "access_key_id": "AKIA_TEST_ACCESS_KEY",
        "secret_access_key": "test_secret_access_key",
        "token": "test_session_token",
    }


@pytest.fixture
def mock_kms_client():
    """Mock KMS client for testing."""
    with mock_aws():
        yield boto3.client("kms", region_name="us-east-1")


@pytest.fixture
def mock_secrets_client():
    """Mock Secrets Manager client for testing."""
    with mock_aws():
        yield boto3.client("secretsmanager", region_name="us-east-1")


@pytest.fixture
def encrypted_key_blob():
    """Mock encrypted key blob from KMS."""
    return base64.b64encode(b"mock_encrypted_key_blob").decode()


@pytest.fixture
def mock_kmstool_result():
    """Mock result from kmstool_enclave_cli."""
    test_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    encoded_key = base64.b64encode(test_key.encode()).decode()
    return f"PlaintextBlob:{encoded_key}"


@pytest.fixture
def mock_vsock_socket():
    """Mock VSOCK socket for testing enclave communication."""
    mock_socket = Mock()
    mock_conn = Mock()
    mock_addr = ("test_cid", 5000)

    # Configure socket behavior
    mock_socket.bind.return_value = None
    mock_socket.listen.return_value = None
    mock_socket.accept.return_value = (mock_conn, mock_addr)

    return mock_socket, mock_conn, mock_addr


@pytest.fixture
def sample_payload_json():
    """Sample JSON payload for enclave communication."""
    return {
        "credential": {
            "access_key_id": "AKIA_TEST_ACCESS_KEY",
            "secret_access_key": "test_secret_access_key",
            "token": "test_session_token",
        },
        "transaction_payload": {
            "value": 0.01,
            "to": "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
            "nonce": 0,
            "type": 2,
            "chainId": 4,
            "gas": 100000,
            "maxFeePerGas": 100000000000,
            "maxPriorityFeePerGas": 3000000000,
        },
        "encrypted_key": "mock_encrypted_key_blob",
    }


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up test environment variables."""
    with patch.dict(
        os.environ,
        {
            "REGION": "us-east-1",
            "LOG_LEVEL": "DEBUG",
            "__DEV_MODE__": "test",
        },
    ):
        yield


@pytest.fixture
def temp_kmstool_binary():
    """Create a temporary mock kmstool binary for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix="_kmstool", delete=False) as f:
        f.write(
            """#!/bin/bash
if [ "$1" = "decrypt" ]; then
    # Mock KMS decrypt - returns base64 encoded test key
    echo "PlaintextBlob:$(echo "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" | base64 -w 0)"
else
    echo "Unknown operation: $1" >&2
    exit 1
fi
"""
        )
        f.flush()
        os.chmod(f.name, 0o755)

        # Patch the kmstool path
        with patch("application.eth1.enclave.server.subprocess.Popen") as mock_popen:
            mock_process = Mock()
            test_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            encoded_key = base64.b64encode(test_key.encode()).decode()
            mock_process.communicate.return_value = (
                f"PlaintextBlob:{encoded_key}".encode(),
                b"",
            )
            mock_popen.return_value = mock_process
            yield f.name

        os.unlink(f.name)


@pytest.fixture
def lambda_context():
    """Mock AWS Lambda context."""
    context = Mock()
    context.function_name = "test-function"
    context.function_version = "1"
    context.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
    context.memory_limit_in_mb = 128
    context.remaining_time_in_millis = lambda: 30000
    context.aws_request_id = "test-request-id"
    return context


# Starknet-specific fixtures

@pytest.fixture
def test_starknet_private_key():
    """Test Starknet private key (STARK curve)."""
    return "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def test_starknet_address():
    """Test Starknet contract address."""
    return "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5"


@pytest.fixture
def test_starknet_field_element():
    """Test Starknet field element."""
    return "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123"


@pytest.fixture
def test_starknet_invoke_transaction():
    """Test Starknet invoke transaction dictionary."""
    return {
        "version": 1,
        "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
        "entry_point_selector": "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
        "calldata": [
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
            "0x456789abcdef123456789abcdef123456789abcdef123456789abcdef123456"
        ],
        "max_fee": "0x16345785d8a0000",  # 0.1 ETH in hex
        "nonce": 1,
        "chain_id": "SN_GOERLI"
    }


@pytest.fixture
def test_starknet_declare_transaction():
    """Test Starknet declare transaction dictionary."""
    return {
        "version": 2,
        "contract_class_hash": "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
        "sender_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
        "max_fee": "0x5af3107a4000",  # 0.01 ETH in hex
        "nonce": 2,
        "chain_id": "SN_GOERLI"
    }


@pytest.fixture
def test_starknet_signature():
    """Test Starknet signature components."""
    return {
        "r": "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
        "s": "0x456789abcdef123456789abcdef123456789abcdef123456789abcdef123456"
    }


@pytest.fixture
def test_starknet_credentials():
    """Test AWS credentials payload for Starknet operations."""
    return {
        "access_key_id": "AKIA_TEST_STARKNET_KEY",
        "secret_access_key": "test_starknet_secret_key",
        "token": "test_starknet_session_token",
    }


@pytest.fixture
def mock_starknet_kmstool_result():
    """Mock result from kmstool_enclave_cli for Starknet."""
    test_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    encoded_key = base64.b64encode(test_key.encode()).decode()
    return f"PlaintextBlob:{encoded_key}"


@pytest.fixture
def sample_starknet_payload_json():
    """Sample JSON payload for Starknet enclave communication."""
    return {
        "credential": {
            "access_key_id": "AKIA_TEST_STARKNET_KEY",
            "secret_access_key": "test_starknet_secret_key",
            "token": "test_starknet_session_token",
        },
        "transaction_payload": {
            "version": 1,
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "entry_point_selector": "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
            "calldata": [
                "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
                "0x456789abcdef123456789abcdef123456789abcdef123456789abcdef123456"
            ],
            "max_fee": "0x16345785d8a0000",
            "nonce": 1,
            "chain_id": "SN_GOERLI"
        },
        "encrypted_key": "mock_encrypted_starknet_key_blob",
        "network": "goerli",
        "cairo_version": "1"
    }


@pytest.fixture
def temp_starknet_kmstool_binary():
    """Create a temporary mock kmstool binary for Starknet testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix="_starknet_kmstool", delete=False) as f:
        f.write(
            """#!/bin/bash
if [ "$1" = "decrypt" ]; then
    # Mock KMS decrypt for Starknet - returns base64 encoded test key
    echo "PlaintextBlob:$(echo "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" | base64 -w 0)"
else
    echo "Unknown operation: $1" >&2
    exit 1
fi
"""
        )
        f.flush()
        os.chmod(f.name, 0o755)

        # Patch the kmstool path for Starknet
        with patch("application.starknet.enclave.server.subprocess.Popen") as mock_popen:
            mock_process = Mock()
            test_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            encoded_key = base64.b64encode(test_key.encode()).decode()
            mock_process.communicate.return_value = (
                f"PlaintextBlob:{encoded_key}".encode(),
                b"",
            )
            mock_popen.return_value = mock_process
            yield f.name

        os.unlink(f.name)


@pytest.fixture
def mock_starknet_curve_validation():
    """Mock Starknet curve validation functions."""
    def mock_validate_stark_private_key(key):
        """Mock validation for STARK private keys."""
        if not isinstance(key, str) or not key.startswith('0x'):
            return False
        try:
            key_int = int(key, 16)
            # STARK curve order for validation
            stark_order = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
            return 1 <= key_int < stark_order
        except ValueError:
            return False
    
    def mock_validate_stark_field_element(element):
        """Mock validation for STARK field elements."""
        if not isinstance(element, str) or not element.startswith('0x'):
            return False
        try:
            element_int = int(element, 16)
            # STARK prime for field validation
            stark_prime = 0x800000000000011000000000000000000000000000000000000000000000001
            return 0 <= element_int < stark_prime
        except ValueError:
            return False
    
    return {
        'validate_private_key': mock_validate_stark_private_key,
        'validate_field_element': mock_validate_stark_field_element
    }


@pytest.fixture
def starknet_test_vectors():
    """Comprehensive test vectors for Starknet cryptographic operations."""
    return {
        'valid_private_keys': [
            "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ],
        'invalid_private_keys': [
            "0x0",  # Zero is invalid
            "0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F",  # Order is invalid
            "invalid_key",  # Not hex
            "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"  # Invalid hex
        ],
        'valid_field_elements': [
            "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0x800000000000011000000000000000000000000000000000000000000000000"  # Prime - 1
        ],
        'invalid_field_elements': [
            "0x800000000000011000000000000000000000000000000000000000000000001",  # Equal to prime
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  # Too large
            "invalid_element"  # Not hex
        ],
        'transaction_templates': {
            'invoke_v1': {
                "version": 1,
                "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                "entry_point_selector": "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                "calldata": [],
                "max_fee": "0x16345785d8a0000",
                "nonce": 0,
                "chain_id": "SN_GOERLI"
            },
            'declare_v2': {
                "version": 2,
                "contract_class_hash": "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
                "sender_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                "max_fee": "0x5af3107a4000",
                "nonce": 0,
                "chain_id": "SN_GOERLI"
            }
        }
    }