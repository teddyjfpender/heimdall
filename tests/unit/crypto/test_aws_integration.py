"""
Comprehensive tests for AWS KMS integration and secure master seed handling.

This module tests the AWS integration layer, KMS decryption, master seed
management, and related security features.
"""

import base64
import json
import subprocess
import time
from unittest.mock import Mock, patch

import pytest

# Import the modules under test
from application.starknet.enclave.aws_multiuser_integration import (
    KMSDecryptionError,
    MasterSeedError,
    PerformanceMonitor,
    StarknetMultiUserAWSManager,
    UserSessionError,
    create_multiuser_transaction_payload,
    extract_user_context_from_request,
    kms_decrypt_master_seed,
    log_user_key_access,
    performance_monitor,
    validate_enclave_environment,
    validate_user_session,
)
from application.starknet.enclave.key_derivation import (
    create_test_master_seed,
)


class TestKMSDecryption:
    """Test KMS decryption functionality."""

    def test_kms_decrypt_master_seed_success(self):
        """Test successful KMS decryption."""
        # Mock subprocess call
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup mock process
            mock_process = Mock()
            test_seed = create_test_master_seed(deterministic=True)
            encoded_seed = base64.standard_b64encode(test_seed).decode()
            mock_process.communicate.return_value = (
                f"PLAINTEXT:{encoded_seed}".encode(),
                b"",
            )
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            # Test credentials
            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            ciphertext = "mock_encrypted_seed"

            # Execute function
            result = kms_decrypt_master_seed(credential, ciphertext)

            # Verify result
            assert result == test_seed
            assert len(result) == 32

            # Verify subprocess was called correctly
            mock_popen.assert_called_once()
            call_args = mock_popen.call_args[0][0]
            assert "/app/kmstool_enclave_cli" in call_args
            assert "decrypt" in call_args
            assert credential["access_key_id"] in call_args
            assert credential["secret_access_key"] in call_args
            assert credential["token"] in call_args
            assert ciphertext in call_args

    def test_kms_decrypt_master_seed_process_failure(self):
        """Test KMS decryption with process failure."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup failing process
            mock_process = Mock()
            mock_process.communicate.return_value = (
                b"",
                b"KMS decryption failed: Access denied",
            )
            mock_process.returncode = 1
            mock_popen.return_value = mock_process

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            ciphertext = "invalid_ciphertext"

            # Should raise KMSDecryptionError
            with pytest.raises(KMSDecryptionError, match="KMS decryption failed"):
                kms_decrypt_master_seed(credential, ciphertext)

    def test_kms_decrypt_master_seed_invalid_output_format(self):
        """Test KMS decryption with invalid output format."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup process with invalid output format
            mock_process = Mock()
            mock_process.communicate.return_value = (b"INVALID_FORMAT:some_data", b"")
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            ciphertext = "valid_ciphertext"

            # Should raise KMSDecryptionError
            with pytest.raises(
                KMSDecryptionError, match="Unexpected KMS output format"
            ):
                kms_decrypt_master_seed(credential, ciphertext)

    def test_kms_decrypt_master_seed_invalid_seed_length(self):
        """Test KMS decryption with invalid seed length."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup process with wrong seed length
            mock_process = Mock()
            invalid_seed = b"short_seed"  # Not 32 bytes
            encoded_seed = base64.standard_b64encode(invalid_seed).decode()
            mock_process.communicate.return_value = (
                f"PLAINTEXT:{encoded_seed}".encode(),
                b"",
            )
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            ciphertext = "valid_ciphertext"

            # Should raise MasterSeedError
            with pytest.raises(MasterSeedError, match="Invalid master seed length"):
                kms_decrypt_master_seed(credential, ciphertext)

    def test_kms_decrypt_master_seed_base64_error(self):
        """Test KMS decryption with base64 decoding error."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup process with invalid base64
            mock_process = Mock()
            mock_process.communicate.return_value = (
                b"PLAINTEXT:invalid_base64!@#$",
                b"",
            )
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            ciphertext = "valid_ciphertext"

            # Should raise KMSDecryptionError
            with pytest.raises(KMSDecryptionError, match="Base64 decoding error"):
                kms_decrypt_master_seed(credential, ciphertext)

    def test_kms_decrypt_master_seed_subprocess_error(self):
        """Test KMS decryption with subprocess error."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup subprocess to raise exception
            mock_popen.side_effect = subprocess.SubprocessError("Process failed")

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            ciphertext = "valid_ciphertext"

            # Should raise KMSDecryptionError
            with pytest.raises(KMSDecryptionError, match="KMS subprocess error"):
                kms_decrypt_master_seed(credential, ciphertext)


class TestUserSessionValidation:
    """Test user session validation functionality."""

    def test_validate_user_session_basic_valid(self):
        """Test validation with valid basic session."""
        username = "valid_user"
        session_data = None  # No session data should be valid

        result = validate_user_session(username, session_data)
        assert result is True

    def test_validate_user_session_with_valid_session_data(self):
        """Test validation with valid session data."""
        username = "valid_user"
        current_time = time.time()
        session_data = {
            "session_id": "session_12345",
            "timestamp": current_time - 1800,  # 30 minutes ago
        }

        result = validate_user_session(username, session_data)
        assert result is True

    def test_validate_user_session_invalid_username(self):
        """Test validation with invalid usernames."""
        invalid_usernames = [None, "", 123, [], "a" * 256]  # Too long

        for invalid_username in invalid_usernames:
            with pytest.raises(UserSessionError):
                validate_user_session(invalid_username, None)

    def test_validate_user_session_empty_session_data(self):
        """Test validation with empty session data."""
        username = "valid_user"
        session_data = {}  # Empty dict

        with pytest.raises(UserSessionError, match="Session data cannot be empty"):
            validate_user_session(username, session_data)

    def test_validate_user_session_missing_fields(self):
        """Test validation with missing session fields."""
        username = "valid_user"

        # Missing session_id
        session_data = {"timestamp": time.time()}
        with pytest.raises(UserSessionError, match="Missing session field: session_id"):
            validate_user_session(username, session_data)

        # Missing timestamp
        session_data = {"session_id": "session_123"}
        with pytest.raises(UserSessionError, match="Missing session field: timestamp"):
            validate_user_session(username, session_data)

    def test_validate_user_session_expired(self):
        """Test validation with expired session."""
        username = "valid_user"
        expired_time = time.time() - 7200  # 2 hours ago
        session_data = {"session_id": "session_123", "timestamp": expired_time}

        with pytest.raises(UserSessionError, match="Session expired"):
            validate_user_session(username, session_data)

    def test_validate_user_session_edge_cases(self):
        """Test validation with edge case session data."""
        username = "valid_user"

        # Session exactly at 1 hour limit
        edge_time = time.time() - 3600  # Exactly 1 hour ago
        session_data = {"session_id": "session_123", "timestamp": edge_time}

        # Should be expired (> 1 hour)
        with pytest.raises(UserSessionError, match="Session expired"):
            validate_user_session(username, session_data)

        # Session just under 1 hour limit
        valid_time = time.time() - 3599  # Just under 1 hour ago
        session_data = {"session_id": "session_123", "timestamp": valid_time}

        # Should be valid
        result = validate_user_session(username, session_data)
        assert result is True


class TestStarknetMultiUserAWSManager:
    """Test the AWS-integrated multi-user manager."""

    @pytest.fixture
    def aws_manager(self):
        """Create an AWS manager for testing."""
        return StarknetMultiUserAWSManager()

    @pytest.fixture
    def mock_master_seed(self):
        """Create a mock master seed."""
        return create_test_master_seed(deterministic=True)

    def test_aws_manager_initialization(self, aws_manager):
        """Test AWS manager initialization."""
        assert aws_manager._key_manager is None
        assert aws_manager._master_seed is None
        assert aws_manager._master_seed_loaded is False

    def test_load_master_seed_success(self, aws_manager, mock_master_seed):
        """Test successful master seed loading."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            encrypted_seed = "encrypted_master_seed"

            aws_manager.load_master_seed(credential, encrypted_seed)

            # Verify state
            assert aws_manager._master_seed == mock_master_seed
            assert aws_manager._key_manager is not None
            assert aws_manager._master_seed_loaded is True

            # Verify KMS decrypt was called
            mock_decrypt.assert_called_once_with(credential, encrypted_seed)

    def test_load_master_seed_failure_cleanup(self, aws_manager):
        """Test that failures during seed loading trigger cleanup."""
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.side_effect = KMSDecryptionError("Decryption failed")

            credential = {
                "access_key_id": "AKIA_TEST_KEY",
                "secret_access_key": "test_secret",
                "token": "test_token",
            }
            encrypted_seed = "encrypted_master_seed"

            # Should raise exception and cleanup
            with pytest.raises(KMSDecryptionError):
                aws_manager.load_master_seed(credential, encrypted_seed)

            # State should be cleaned up
            assert aws_manager._master_seed is None
            assert aws_manager._key_manager is None
            assert aws_manager._master_seed_loaded is False

    def test_derive_user_key_with_validation_success(
        self, aws_manager, mock_master_seed
    ):
        """Test successful user key derivation with validation."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        username = "test_user"
        session_data = {
            "session_id": "session_123",
            "timestamp": time.time() - 1800,  # 30 minutes ago
        }

        private_key, address = aws_manager.derive_user_key_with_validation(
            username, 0, session_data
        )

        # Verify result
        assert isinstance(private_key, int)
        assert isinstance(address, int)
        assert private_key > 0
        assert address > 0

    def test_derive_user_key_with_validation_no_master_seed(self, aws_manager):
        """Test key derivation without loaded master seed."""
        username = "test_user"

        with pytest.raises(MasterSeedError, match="Master seed not loaded"):
            aws_manager.derive_user_key_with_validation(username)

    def test_derive_user_key_with_validation_invalid_session(
        self, aws_manager, mock_master_seed
    ):
        """Test key derivation with invalid session."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        username = "test_user"
        invalid_session = {
            "session_id": "session_123",
            "timestamp": time.time() - 7200,  # 2 hours ago (expired)
        }

        with pytest.raises(UserSessionError, match="Session expired"):
            aws_manager.derive_user_key_with_validation(username, 0, invalid_session)

    def test_process_user_transaction_request_success(
        self, aws_manager, mock_master_seed
    ):
        """Test successful transaction request processing."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        username = "transaction_user"
        transaction_payload = {
            "contract_address": "0x123456789abcdef",
            "function_name": "transfer",
            "arguments": ["0xrecipient", "1000"],
        }
        session_data = {"session_id": "session_123", "timestamp": time.time() - 1800}

        response = aws_manager.process_user_transaction_request(
            username, transaction_payload, session_data
        )

        # Verify response
        assert response["success"] is True
        assert response["username"] == username
        assert "private_key_int" in response
        assert "account_address_int" in response
        assert response["transaction_payload"] == transaction_payload

    def test_process_user_transaction_request_missing_fields(
        self, aws_manager, mock_master_seed
    ):
        """Test transaction request with missing required fields."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        username = "transaction_user"
        incomplete_payload = {
            "contract_address": "0x123456789abcdef",
            # Missing function_name
        }

        response = aws_manager.process_user_transaction_request(
            username, incomplete_payload
        )

        # Should return error response
        assert response["success"] is False
        assert "error" in response
        assert response["username"] == username

    def test_get_user_account_info_success(self, aws_manager, mock_master_seed):
        """Test getting user account info."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        username = "account_info_user"

        response = aws_manager.get_user_account_info(username)

        # Verify response
        assert response["success"] is True
        assert response["username"] == username
        assert "account_address" in response
        assert response["account_address"].startswith("0x")
        assert response["key_index"] == 0

    def test_get_user_account_info_no_master_seed(self, aws_manager):
        """Test getting account info without loaded master seed."""
        username = "account_info_user"

        response = aws_manager.get_user_account_info(username)

        # Should return error response
        assert response["success"] is False
        assert "error" in response
        assert response["username"] == username

    def test_validate_user_ownership_success(self, aws_manager, mock_master_seed):
        """Test successful user ownership validation."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        username = "ownership_user"

        # Get the user's actual address
        private_key, address = aws_manager.derive_user_key_with_validation(username)
        address_hex = hex(address)

        # Should validate ownership
        result = aws_manager.validate_user_ownership(username, address_hex)
        assert result is True

        # Should not validate wrong address
        wrong_address = hex(address + 1)
        result = aws_manager.validate_user_ownership(username, wrong_address)
        assert result is False

    def test_validate_user_ownership_no_master_seed(self, aws_manager):
        """Test ownership validation without master seed."""
        username = "ownership_user"
        address = "0x123456789abcdef"

        # Should return False and maintain timing consistency
        result = aws_manager.validate_user_ownership(username, address)
        assert result is False

    def test_cleanup_master_seed(self, aws_manager, mock_master_seed):
        """Test master seed cleanup."""
        # Load master seed first
        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            mock_decrypt.return_value = mock_master_seed
            aws_manager.load_master_seed({}, "encrypted_seed")

        # Verify loaded
        assert aws_manager._master_seed_loaded is True
        assert aws_manager._master_seed is not None
        assert aws_manager._key_manager is not None

        # Cleanup
        aws_manager._cleanup_master_seed()

        # Verify cleaned up
        assert aws_manager._master_seed_loaded is False
        assert aws_manager._master_seed is None
        assert aws_manager._key_manager is None


class TestUtilityFunctions:
    """Test utility functions in AWS integration."""

    def test_create_multiuser_transaction_payload(self):
        """Test creation of multiuser transaction payload."""
        username = "payload_user"
        transaction_data = {
            "contract_address": "0x123456789abcdef",
            "function_name": "transfer",
            "arguments": ["0xrecipient", "1000"],
        }
        session_id = "session_12345"
        key_index = 5

        payload = create_multiuser_transaction_payload(
            username, transaction_data, session_id, key_index
        )

        # Verify structure
        assert payload["username"] == username
        assert payload["key_index"] == key_index
        assert payload["transaction_payload"] == transaction_data
        assert "timestamp" in payload
        assert payload["session_data"]["session_id"] == session_id
        assert "timestamp" in payload["session_data"]

    def test_create_multiuser_transaction_payload_no_session(self):
        """Test payload creation without session ID."""
        username = "payload_user"
        transaction_data = {"contract_address": "0x123"}

        payload = create_multiuser_transaction_payload(username, transaction_data)

        # Verify structure
        assert payload["username"] == username
        assert payload["key_index"] == 0  # Default
        assert payload["transaction_payload"] == transaction_data
        assert "timestamp" in payload
        assert "session_data" not in payload

    def test_extract_user_context_from_request(self):
        """Test extraction of user context from request."""
        request_payload = {
            "username": "context_user",
            "key_index": 3,
            "session_data": {"session_id": "session_123", "timestamp": time.time()},
        }

        username, key_index, session_data = extract_user_context_from_request(
            request_payload
        )

        assert username == "context_user"
        assert key_index == 3
        assert session_data == request_payload["session_data"]

    def test_extract_user_context_missing_username(self):
        """Test context extraction with missing username."""
        request_payload = {"key_index": 0}

        with pytest.raises(UserSessionError, match="Username required"):
            extract_user_context_from_request(request_payload)

    def test_extract_user_context_invalid_key_index(self):
        """Test context extraction with invalid key index."""
        invalid_indices = [-1, "not_int", 1.5]

        for invalid_index in invalid_indices:
            request_payload = {"username": "test_user", "key_index": invalid_index}

            with pytest.raises(UserSessionError, match="Invalid key_index"):
                extract_user_context_from_request(request_payload)

    def test_extract_user_context_defaults(self):
        """Test context extraction with default values."""
        request_payload = {"username": "default_user"}

        username, key_index, session_data = extract_user_context_from_request(
            request_payload
        )

        assert username == "default_user"
        assert key_index == 0  # Default
        assert session_data is None  # Default

    def test_log_user_key_access(self):
        """Test user key access logging."""
        with patch("builtins.print") as mock_print:
            log_user_key_access(
                username="log_user",
                key_index=2,
                operation="derive_key",
                success=True,
                session_id="session_123",
            )

            # Verify logging occurred
            mock_print.assert_called_once()
            log_output = mock_print.call_args[0][0]

            assert "AUDIT:" in log_output
            assert "derive_key" in log_output
            assert "session_123" in log_output

            # Parse JSON to verify structure
            json_part = log_output.split("AUDIT: ")[1]
            log_data = json.loads(json_part)

            assert "username_hash" in log_data
            assert log_data["key_index"] == 2
            assert log_data["operation"] == "derive_key"
            assert log_data["success"] is True
            assert log_data["session_id"] == "session_123"

    def test_validate_enclave_environment_mock_positive(self):
        """Test enclave environment validation (mocked positive)."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True

            result = validate_enclave_environment()
            assert result is True

    def test_validate_enclave_environment_mock_negative(self):
        """Test enclave environment validation (mocked negative)."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False

            with patch.dict("os.environ", {}, clear=True):
                result = validate_enclave_environment()
                assert result is False

    def test_validate_enclave_environment_env_var(self):
        """Test enclave environment validation with environment variable."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False

            with patch.dict("os.environ", {"NITRO_ENCLAVE": "true"}):
                result = validate_enclave_environment()
                assert result is True


class TestPerformanceMonitor:
    """Test performance monitoring functionality."""

    @pytest.fixture
    def monitor(self):
        """Create a fresh performance monitor."""
        return PerformanceMonitor()

    def test_performance_monitor_initialization(self, monitor):
        """Test performance monitor initialization."""
        assert monitor.metrics["key_derivations"] == 0
        assert monitor.metrics["total_derivation_time"] == 0.0
        assert monitor.metrics["user_sessions"] == 0
        assert monitor.metrics["failed_operations"] == 0

    def test_record_key_derivation(self, monitor):
        """Test recording key derivation metrics."""
        durations = [0.1, 0.2, 0.15]

        for duration in durations:
            monitor.record_key_derivation(duration)

        assert monitor.metrics["key_derivations"] == 3
        assert monitor.metrics["total_derivation_time"] == sum(durations)

    def test_record_user_session(self, monitor):
        """Test recording user session metrics."""
        monitor.record_user_session()
        monitor.record_user_session()
        monitor.record_user_session()

        assert monitor.metrics["user_sessions"] == 3

    def test_record_failure(self, monitor):
        """Test recording failure metrics."""
        monitor.record_failure()
        monitor.record_failure()

        assert monitor.metrics["failed_operations"] == 2

    def test_get_average_derivation_time(self, monitor):
        """Test average derivation time calculation."""
        # No derivations yet
        assert monitor.get_average_derivation_time() == 0.0

        # Add some derivations
        durations = [0.1, 0.2, 0.3]
        for duration in durations:
            monitor.record_key_derivation(duration)

        expected_avg = sum(durations) / len(durations)
        assert abs(monitor.get_average_derivation_time() - expected_avg) < 1e-10

    def test_get_failure_rate(self, monitor):
        """Test failure rate calculation."""
        # No operations yet
        assert monitor.get_failure_rate() == 0.0

        # Add some operations
        monitor.record_key_derivation(0.1)
        monitor.record_key_derivation(0.2)
        monitor.record_failure()

        # 1 failure out of 3 total operations = 33.33%
        expected_rate = (1 / 3) * 100
        assert abs(monitor.get_failure_rate() - expected_rate) < 1e-10

    def test_reset_metrics(self, monitor):
        """Test metrics reset functionality."""
        # Add some data
        monitor.record_key_derivation(0.1)
        monitor.record_user_session()
        monitor.record_failure()

        # Verify data exists
        assert monitor.metrics["key_derivations"] > 0
        assert monitor.metrics["user_sessions"] > 0
        assert monitor.metrics["failed_operations"] > 0

        # Reset
        monitor.reset()

        # Verify reset
        assert monitor.metrics["key_derivations"] == 0
        assert monitor.metrics["total_derivation_time"] == 0.0
        assert monitor.metrics["user_sessions"] == 0
        assert monitor.metrics["failed_operations"] == 0

    def test_get_summary(self, monitor):
        """Test performance summary generation."""
        # Add some test data
        monitor.record_key_derivation(0.1)
        monitor.record_key_derivation(0.2)
        monitor.record_user_session()
        monitor.record_failure()

        summary = monitor.get_summary()

        # Verify summary structure
        expected_fields = [
            "total_key_derivations",
            "total_user_sessions",
            "total_failures",
            "average_derivation_time_ms",
            "failure_rate_percentage",
            "total_derivation_time_seconds",
        ]

        for field in expected_fields:
            assert field in summary

        # Verify values
        assert summary["total_key_derivations"] == 2
        assert summary["total_user_sessions"] == 1
        assert summary["total_failures"] == 1
        assert summary["average_derivation_time_ms"] == 150.0  # (0.1 + 0.2) / 2 * 1000
        assert abs(summary["failure_rate_percentage"] - 33.33333333333333) < 1e-10
        assert summary["total_derivation_time_seconds"] == 0.3

    def test_global_performance_monitor(self):
        """Test the global performance monitor instance."""
        # Should be able to access the global instance
        assert performance_monitor is not None
        assert isinstance(performance_monitor, PerformanceMonitor)

        # Should be able to use it
        initial_derivations = performance_monitor.metrics["key_derivations"]
        performance_monitor.record_key_derivation(0.1)
        assert performance_monitor.metrics["key_derivations"] == initial_derivations + 1


@pytest.mark.crypto
class TestAWSIntegrationSecurity:
    """Test security aspects of AWS integration."""

    def test_master_seed_isolation_between_managers(self):
        """Test that different managers don't interfere with each other."""
        manager1 = StarknetMultiUserAWSManager()
        manager2 = StarknetMultiUserAWSManager()

        seed1 = create_test_master_seed(deterministic=True)
        seed2 = create_test_master_seed(deterministic=False)

        with patch(
            "application.starknet.enclave.aws_multiuser_integration.kms_decrypt_master_seed"
        ) as mock_decrypt:
            # Load different seeds in different managers
            mock_decrypt.return_value = seed1
            manager1.load_master_seed({}, "encrypted_seed1")

            mock_decrypt.return_value = seed2
            manager2.load_master_seed({}, "encrypted_seed2")

        # Derive keys for same user from both managers
        username = "isolation_test_user"
        key1, addr1 = manager1.derive_user_key_with_validation(username)
        key2, addr2 = manager2.derive_user_key_with_validation(username)

        # Keys should be different (different seeds)
        assert key1 != key2
        assert addr1 != addr2

    def test_credential_isolation_in_kms_calls(self):
        """Test that credentials are properly isolated in KMS calls."""
        credentials = [
            {
                "access_key_id": "AKIA_KEY1",
                "secret_access_key": "secret1",
                "token": "token1",
            },
            {
                "access_key_id": "AKIA_KEY2",
                "secret_access_key": "secret2",
                "token": "token2",
            },
        ]

        with patch(
            "application.starknet.enclave.aws_multiuser_integration.subprocess.Popen"
        ) as mock_popen:
            # Setup mock process
            mock_process = Mock()
            test_seed = create_test_master_seed(deterministic=True)
            encoded_seed = base64.standard_b64encode(test_seed).decode()
            mock_process.communicate.return_value = (
                f"PLAINTEXT:{encoded_seed}".encode(),
                b"",
            )
            mock_process.returncode = 0
            mock_popen.return_value = mock_process

            # Call with first credential set
            kms_decrypt_master_seed(credentials[0], "ciphertext")
            first_call_args = mock_popen.call_args[0][0]

            # Reset mock
            mock_popen.reset_mock()
            mock_popen.return_value = mock_process

            # Call with second credential set
            kms_decrypt_master_seed(credentials[1], "ciphertext")
            second_call_args = mock_popen.call_args[0][0]

            # Verify different credentials were used
            assert credentials[0]["access_key_id"] in first_call_args
            assert credentials[1]["access_key_id"] in second_call_args
            assert credentials[0]["access_key_id"] not in second_call_args
            assert credentials[1]["access_key_id"] not in first_call_args


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
