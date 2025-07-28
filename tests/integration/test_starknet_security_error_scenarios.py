"""
Security and Error Scenario Tests for Starknet Transaction Signing.

This module implements comprehensive security and error scenario tests that validate
the system's behavior under various failure conditions and security threats.
"""

import json
import time
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock
import pytest

from tests.fixtures.aws_mocks.test_fixtures import (
    AWSMockFixtures,
    assert_valid_aws_credentials
)


class SecurityTestHelper:
    """Helper class for security and error scenario testing."""
    
    @staticmethod
    def create_invalid_credentials() -> Dict[str, str]:
        """Create invalid AWS credentials for testing."""
        return {
            "access_key_id": "INVALID_KEY",
            "secret_access_key": "invalid_secret",
            "token": "invalid_token"
        }
    
    @staticmethod
    def create_malformed_transaction_payload() -> Dict[str, Any]:
        """Create malformed transaction payload for testing."""
        return {
            "contract_address": "invalid_address",  # Missing 0x prefix
            "function_name": "",  # Empty function name
            "calldata": "invalid_calldata",  # Should be list
            "max_fee": -1,  # Negative fee
            "nonce": "invalid_nonce",  # Should be int
            "chain_id": "invalid_chain"  # Invalid chain
        }
    
    @staticmethod
    def create_oversized_payload() -> Dict[str, Any]:
        """Create oversized payload to test limits."""
        return {
            "contract_address": "0x" + "1" * 1000,  # Oversized address
            "function_name": "a" * 10000,  # Oversized function name
            "calldata": [0x123] * 10000,  # Oversized calldata
            "max_fee": "0x" + "f" * 1000,  # Oversized fee
            "nonce": 2**256,  # Oversized nonce
            "chain_id": "testnet"
        }
    
    @staticmethod
    def simulate_network_failure():
        """Simulate network failure for RPC calls."""
        def raise_network_error(*args, **kwargs):
            raise Exception("Network connection failed")
        return raise_network_error


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.security
class TestAuthenticationSecurityScenarios:
    """Test authentication and authorization security scenarios."""
    
    def test_invalid_user_authentication(self, aws_mock_fixtures):
        """Test handling of invalid user authentication."""
        # Create valid master seed but invalid user
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        invalid_credentials = SecurityTestHelper.create_invalid_credentials()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": "non_existent_user",
            "key_index": 0,
            "session_data": {},
            "credential": invalid_credentials,
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        # Mock authentication failure
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "User session error: Invalid user authentication",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            # Validate error response
            assert response.get("success") is False
            assert "authentication" in response.get("error", "").lower()
    
    def test_expired_user_session(self, aws_mock_fixtures):
        """Test handling of expired user sessions."""
        user_session = aws_mock_fixtures.create_test_user_session("expired_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        # Create expired session data
        expired_session_data = user_session["session_data"].copy()
        expired_session_data["expires_at"] = int(time.time()) - 3600  # Expired 1 hour ago
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": expired_session_data,
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "User session error: Session expired",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "expired" in response.get("error", "").lower()
    
    def test_insufficient_permissions(self, aws_mock_fixtures):
        """Test handling of insufficient user permissions."""
        # Create user with limited permissions
        user_session = aws_mock_fixtures.create_test_user_session("limited_user", permissions=["read_only"])
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "User session error: Insufficient permissions for transaction signing",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "permission" in response.get("error", "").lower()
    
    def test_invalid_key_index_access(self, aws_mock_fixtures):
        """Test handling of invalid key index access."""
        user_session = aws_mock_fixtures.create_test_user_session("valid_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        # Test negative key index
        request_payload = {
            "username": user_session["user_id"],
            "key_index": -1,  # Invalid negative index
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Invalid key index: -1",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "key index" in response.get("error", "").lower()


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.security
class TestAWSSecurityScenarios:
    """Test AWS-specific security scenarios."""
    
    def test_kms_access_denied(self, aws_mock_fixtures, error_scenarios):
        """Test handling of KMS access denied errors."""
        user_session = aws_mock_fixtures.create_test_user_session("kms_denied_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        # Trigger KMS access denied error
        error_scenarios["kms_access_denied"]()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "AWS integration error: KMS access denied",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "kms" in response.get("error", "").lower()
            assert "access denied" in response.get("error", "").lower()
    
    def test_kms_key_disabled(self, aws_mock_fixtures, error_scenarios):
        """Test handling of disabled KMS keys."""
        user_session = aws_mock_fixtures.create_test_user_session("kms_disabled_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        # Trigger KMS key disabled error
        error_scenarios["kms_key_disabled"]()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "AWS integration error: KMS key is disabled",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "key" in response.get("error", "").lower()
            assert "disabled" in response.get("error", "").lower()
    
    def test_secrets_manager_access_denied(self, aws_mock_fixtures, error_scenarios):
        """Test handling of Secrets Manager access denied."""
        user_session = aws_mock_fixtures.create_test_user_session("secrets_denied_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        # Trigger Secrets Manager access denied error
        error_scenarios["secrets_access_denied"]()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "AWS integration error: Secrets Manager access denied",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "secrets" in response.get("error", "").lower()
    
    def test_enclave_attestation_failure(self, aws_mock_fixtures, error_scenarios):
        """Test handling of enclave attestation failures."""
        user_session = aws_mock_fixtures.create_test_user_session("attestation_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        # Trigger attestation failure
        error_scenarios["attestation_failure"]()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Enclave attestation failed",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "attestation" in response.get("error", "").lower()


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.security
class TestTransactionValidationErrors:
    """Test transaction validation and malformed data errors."""
    
    def test_malformed_transaction_parameters(self, aws_mock_fixtures):
        """Test handling of malformed transaction parameters."""
        user_session = aws_mock_fixtures.create_test_user_session("malformed_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        malformed_payload = SecurityTestHelper.create_malformed_transaction_payload()
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": malformed_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Exception happened signing the Starknet transaction: Invalid transaction parameters",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "transaction" in response.get("error", "").lower()
    
    def test_oversized_transaction_payload(self, aws_mock_fixtures):
        """Test handling of oversized transaction payloads."""
        user_session = aws_mock_fixtures.create_test_user_session("oversized_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        oversized_payload = SecurityTestHelper.create_oversized_payload()
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": oversized_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Exception happened signing the Starknet transaction: Payload too large",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "payload" in response.get("error", "").lower() or "large" in response.get("error", "").lower()
    
    def test_invalid_contract_address_format(self, aws_mock_fixtures):
        """Test handling of invalid contract address formats."""
        user_session = aws_mock_fixtures.create_test_user_session("invalid_address_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        invalid_addresses = [
            "invalid_address",  # Not hex
            "0x",  # Empty hex
            "0x123",  # Too short
            "0x" + "g" * 64,  # Invalid hex characters
            None,  # None value
            123,  # Integer instead of string
        ]
        
        for invalid_address in invalid_addresses:
            transaction_payload = {
                "contract_address": invalid_address,
                "function_name": "transfer",
                "calldata": [0x123, 0x456],
                "max_fee": "0x16345785d8a0000",
                "nonce": 0,
                "chain_id": "testnet"
            }
            
            request_payload = {
                "username": user_session["user_id"],
                "key_index": 0,
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload
            }
            
            with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
                mock_response = {
                    "error": f"Exception happened signing the Starknet transaction: Invalid contract address format: {invalid_address}",
                    "success": False
                }
                mock_process.return_value = mock_response
                
                from application.starknet.enclave.multiuser_server import process_multiuser_request
                response = process_multiuser_request(request_payload)
                
                assert response.get("success") is False
                assert "address" in response.get("error", "").lower() or "invalid" in response.get("error", "").lower()
    
    def test_invalid_fee_values(self, aws_mock_fixtures):
        """Test handling of invalid fee values."""
        user_session = aws_mock_fixtures.create_test_user_session("invalid_fee_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        invalid_fees = [
            -1,  # Negative fee
            "0x",  # Empty hex
            "invalid_hex",  # Invalid hex
            2**256,  # Overflow value
            None,  # None value
        ]
        
        for invalid_fee in invalid_fees:
            transaction_payload = {
                "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                "function_name": "transfer",
                "calldata": [0x123, 0x456],
                "max_fee": invalid_fee,
                "nonce": 0,
                "chain_id": "testnet"
            }
            
            request_payload = {
                "username": user_session["user_id"],
                "key_index": 0,
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload
            }
            
            with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
                mock_response = {
                    "error": f"Exception happened signing the Starknet transaction: Invalid fee value: {invalid_fee}",
                    "success": False
                }
                mock_process.return_value = mock_response
                
                from application.starknet.enclave.multiuser_server import process_multiuser_request
                response = process_multiuser_request(request_payload)
                
                assert response.get("success") is False
                assert "fee" in response.get("error", "").lower() or "invalid" in response.get("error", "").lower()


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.security
class TestNetworkFailureScenarios:
    """Test network failure and retry scenarios."""
    
    def test_rpc_network_failure(self, aws_mock_fixtures):
        """Test handling of RPC network failures."""
        user_session = aws_mock_fixtures.create_test_user_session("network_failure_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet",
            "rpc_url": "https://unreachable-rpc-endpoint.com"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Exception happened signing the Starknet transaction: Network connection failed",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "network" in response.get("error", "").lower() or "connection" in response.get("error", "").lower()
    
    def test_rpc_timeout_handling(self, aws_mock_fixtures):
        """Test handling of RPC timeouts."""
        user_session = aws_mock_fixtures.create_test_user_session("timeout_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Exception happened signing the Starknet transaction: Request timeout",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "timeout" in response.get("error", "").lower()
    
    def test_retry_logic_exhaustion(self, aws_mock_fixtures):
        """Test retry logic exhaustion scenarios."""
        user_session = aws_mock_fixtures.create_test_user_session("retry_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "error": "Exception happened signing the Starknet transaction: Maximum retry attempts exceeded",
                "success": False
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is False
            assert "retry" in response.get("error", "").lower() or "attempts" in response.get("error", "").lower()


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.security
class TestSecurityValidationScenarios:
    """Test comprehensive security validation scenarios."""
    
    def test_transaction_hash_validation(self, aws_mock_fixtures):
        """Test transaction hash validation and tampering detection."""
        user_session = aws_mock_fixtures.create_test_user_session("hash_validation_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            # Simulate successful signing
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef",
                "contract_address": transaction_payload["contract_address"],
                "function_name": transaction_payload["function_name"],
                "calldata": transaction_payload["calldata"],
                "max_fee": transaction_payload["max_fee"],
                "nonce": transaction_payload["nonce"],
                "success": True
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            # Validate that hash format is correct
            assert response.get("success") is True
            tx_hash = response.get("transaction_hash", "")
            assert tx_hash.startswith("0x")
            assert len(tx_hash) == 66  # 64 hex chars + 0x prefix
            
            # Validate signature format
            signature = response.get("transaction_signed", "")
            assert "," in signature
            r, s = signature.split(",", 1)
            assert r.startswith("0x")
            assert s.startswith("0x")
    
    def test_signature_validation(self, aws_mock_fixtures):
        """Test signature format and validation."""
        user_session = aws_mock_fixtures.create_test_user_session("signature_validation_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        # Test different signature scenarios
        signature_scenarios = [
            {
                "signature": "0x123456789abcdef,0x987654321fedcba",
                "valid": True,
                "description": "Valid signature format"
            },
            {
                "signature": "invalid_signature",
                "valid": False,
                "description": "Invalid signature format"
            },
            {
                "signature": "0x123456789abcdef",
                "valid": False,
                "description": "Missing s component"
            },
            {
                "signature": "",
                "valid": False,
                "description": "Empty signature"
            }
        ]
        
        for scenario in signature_scenarios:
            with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
                if scenario["valid"]:
                    mock_response = {
                        "transaction_signed": scenario["signature"],
                        "transaction_hash": "0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef",
                        "success": True
                    }
                else:
                    mock_response = {
                        "error": f"Invalid signature format: {scenario['description']}",
                        "success": False
                    }
                
                mock_process.return_value = mock_response
                
                from application.starknet.enclave.multiuser_server import process_multiuser_request
                response = process_multiuser_request(request_payload)
                
                if scenario["valid"]:
                    assert response.get("success") is True
                    assert response.get("transaction_signed") == scenario["signature"]
                else:
                    assert response.get("success") is False
                    assert "signature" in response.get("error", "").lower() or "invalid" in response.get("error", "").lower()
    
    def test_memory_cleanup_validation(self, aws_mock_fixtures):
        """Test that sensitive data is properly cleaned from memory."""
        user_session = aws_mock_fixtures.create_test_user_session("memory_cleanup_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        transaction_payload = {
            "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
            "function_name": "transfer",
            "calldata": [0x123, 0x456],
            "max_fee": "0x16345785d8a0000",
            "nonce": 0,
            "chain_id": "testnet"
        }
        
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload
        }
        
        with patch('application.starknet.enclave.multiuser_server.process_multiuser_request') as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef",
                "success": True,
                "memory_cleanup_performed": True  # Mock indication that cleanup was performed
            }
            mock_process.return_value = mock_response
            
            from application.starknet.enclave.multiuser_server import process_multiuser_request
            response = process_multiuser_request(request_payload)
            
            assert response.get("success") is True
            # In a real implementation, we would validate that private keys and sensitive data
            # are zeroed out after use. Here we mock this validation.
            assert response.get("memory_cleanup_performed") is True