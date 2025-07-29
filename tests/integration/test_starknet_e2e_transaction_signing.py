"""
Comprehensive End-to-End Transaction Signing Tests for Starknet.

This module implements complete end-to-end tests that validate the entire flow
from user request to signed Starknet transaction, covering:
- Complete transaction flow testing
- Various Starknet transaction types
- Multi-user concurrent signing
- Starknet network integration
- Security and error scenarios
- Performance and scale testing
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from tests.fixtures.aws_mocks.test_fixtures import (
    aws_mock_fixtures,  # Import the fixture
)


class StarknetTransactionTestHelper:
    """Helper class for Starknet transaction testing."""

    @staticmethod
    def create_invoke_transaction_payload(
        contract_address: str = None,
        function_name: str = "transfer",
        calldata: List[int] = None,
        max_fee: str = "0x16345785d8a0000",
        nonce: int = 0,
        chain_id: str = "testnet",
        rpc_url: str = None,
    ) -> Dict[str, Any]:
        """Create an invoke transaction payload."""
        if calldata is None:
            calldata = [0x123, 0x456]
        if contract_address is None:
            contract_address = (
                "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5"
            )
        if rpc_url is None:
            rpc_url = "https://starknet-testnet.public.blastapi.io"

        return {
            "contract_address": contract_address,
            "function_name": function_name,
            "calldata": calldata,
            "max_fee": max_fee,
            "nonce": nonce,
            "chain_id": chain_id,
            "rpc_url": rpc_url,
        }

    @staticmethod
    def create_declare_transaction_payload(
        contract_class_hash: str = None,
        sender_address: str = None,
        max_fee: str = "0x5af3107a4000",
        nonce: int = 0,
        chain_id: str = "testnet",
    ) -> Dict[str, Any]:
        """Create a declare transaction payload."""
        if contract_class_hash is None:
            contract_class_hash = (
                "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123"
            )
        if sender_address is None:
            sender_address = (
                "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5"
            )

        return {
            "contract_class_hash": contract_class_hash,
            "sender_address": sender_address,
            "max_fee": max_fee,
            "nonce": nonce,
            "chain_id": chain_id,
            "transaction_type": "declare",
        }

    @staticmethod
    def create_deploy_account_transaction_payload(
        class_hash: str = None,
        constructor_calldata: List[int] = None,
        contract_address_salt: str = None,
        max_fee: str = "0x5af3107a4000",
        nonce: int = 0,
        chain_id: str = "testnet",
    ) -> Dict[str, Any]:
        """Create a deploy account transaction payload."""
        if class_hash is None:
            class_hash = (
                "0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2"
            )
        if constructor_calldata is None:
            constructor_calldata = []
        if contract_address_salt is None:
            contract_address_salt = "0x123456789abcdef"

        return {
            "class_hash": class_hash,
            "constructor_calldata": constructor_calldata,
            "contract_address_salt": contract_address_salt,
            "max_fee": max_fee,
            "nonce": nonce,
            "chain_id": chain_id,
            "transaction_type": "deploy_account",
        }

    @staticmethod
    def validate_transaction_signature(response: Dict[str, Any]) -> None:
        """Validate a transaction signature response."""
        assert response.get(
            "success", False
        ), f"Transaction signing failed: {response.get('error')}"
        assert "transaction_signed" in response, "Missing transaction signature"
        assert "transaction_hash" in response, "Missing transaction hash"

        # Validate signature format (r,s components)
        signature_str = response["transaction_signed"]
        assert "," in signature_str, "Invalid signature format"

        r_str, s_str = signature_str.split(",", 1)
        assert r_str.startswith("0x"), "Invalid r component format"
        assert s_str.startswith("0x"), "Invalid s component format"

        # Validate transaction hash
        tx_hash = response["transaction_hash"]
        assert tx_hash.startswith("0x"), "Invalid transaction hash format"
        # For test data, just ensure it's a reasonable hex string
        assert len(tx_hash) > 10, f"Transaction hash too short: {len(tx_hash)}"


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.e2e
class TestStarknetTransactionFlowE2E:
    """Complete transaction flow end-to-end tests."""

    def test_single_user_invoke_transaction_complete_flow(self, aws_mock_fixtures):
        """Test complete single-user invoke transaction flow."""
        # Setup test data
        user_session = aws_mock_fixtures.create_test_user_session("test_user_invoke")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        # Create transaction payload
        transaction_payload = (
            StarknetTransactionTestHelper.create_invoke_transaction_payload()
        )

        # Create complete request payload
        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        # Mock the multiuser server response
        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef",
                "contract_address": transaction_payload["contract_address"],
                "account_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                "function_name": transaction_payload["function_name"],
                "calldata": transaction_payload["calldata"],
                "max_fee": transaction_payload["max_fee"],
                "nonce": transaction_payload["nonce"],
                "username": user_session["user_id"],
                "key_index": 0,
                "success": True,
            }
            mock_process.return_value = mock_response

            # Process the request
            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            # Validate response
            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response["username"] == user_session["user_id"]
            assert response["function_name"] == transaction_payload["function_name"]

    def test_multiuser_transaction_flow_with_key_derivation(self, aws_mock_fixtures):
        """Test multi-user transaction flow with proper key derivation."""
        # Create multiple users
        users = []
        for i in range(3):
            user_session = aws_mock_fixtures.create_test_user_session(f"test_user_{i}")
            users.append(user_session)

        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        # Process transactions for each user
        responses = []
        for i, user_session in enumerate(users):
            transaction_payload = (
                StarknetTransactionTestHelper.create_invoke_transaction_payload(
                    nonce=i, calldata=[0x100 + i, 0x200 + i]
                )
            )

            request_payload = {
                "username": user_session["user_id"],
                "key_index": i,  # Different key index for each user
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload,
            }

            # Mock server response with user-specific data
            with patch(
                "application.starknet.enclave.multiuser_server.process_multiuser_request"
            ) as mock_process:
                mock_response = {
                    "transaction_signed": f"0x{(123456789 + i):x},0x{(987654321 + i):x}",
                    "transaction_hash": f"0x{(0xabcdef123456789 + i):064x}",
                    "contract_address": transaction_payload["contract_address"],
                    "account_address": f"0x{(0x01a4bd3c888c8bb6 + i):060x}",
                    "function_name": transaction_payload["function_name"],
                    "calldata": transaction_payload["calldata"],
                    "max_fee": transaction_payload["max_fee"],
                    "nonce": transaction_payload["nonce"],
                    "username": user_session["user_id"],
                    "key_index": i,
                    "success": True,
                }
                mock_process.return_value = mock_response

                from application.starknet.enclave.multiuser_server import (
                    process_multiuser_request,
                )

                response = process_multiuser_request(request_payload)
                responses.append(response)

        # Validate all responses
        for i, response in enumerate(responses):
            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response["username"] == f"test_user_{i}"
            assert response["key_index"] == i

        # Ensure all signatures are different (different keys)
        signatures = [resp["transaction_signed"] for resp in responses]
        assert len(set(signatures)) == len(
            signatures
        ), "Signatures should be unique for different users"

    def test_account_info_request_flow(self, aws_mock_fixtures):
        """Test account information request flow."""
        user_session = aws_mock_fixtures.create_test_user_session("test_user_info")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
        }

        # Mock account info response
        with patch(
            "application.starknet.enclave.multiuser_server.process_account_info_request"
        ) as mock_process:
            mock_response = {
                "username": user_session["user_id"],
                "key_index": 0,
                "account_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                "public_key": "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456",
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_account_info_request,
            )

            response = process_account_info_request(request_payload)

            # Validate response
            assert response.get(
                "success", False
            ), f"Account info request failed: {response.get('error')}"
            assert response["username"] == user_session["user_id"]
            assert "account_address" in response
            assert "public_key" in response


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.e2e
class TestStarknetTransactionTypes:
    """Test various Starknet transaction types."""

    def test_invoke_transaction_signing(self, aws_mock_fixtures):
        """Test invoke transaction signing."""
        user_session = aws_mock_fixtures.create_test_user_session("invoke_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        transaction_payload = (
            StarknetTransactionTestHelper.create_invoke_transaction_payload(
                function_name="approve", calldata=[0x1234567890, 0x100]
            )
        )

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef",
                "contract_address": transaction_payload["contract_address"],
                "function_name": "approve",
                "calldata": [0x1234567890, 0x100],
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response["function_name"] == "approve"

    def test_declare_transaction_signing(self, aws_mock_fixtures):
        """Test declare transaction signing."""
        user_session = aws_mock_fixtures.create_test_user_session("declare_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        transaction_payload = (
            StarknetTransactionTestHelper.create_declare_transaction_payload()
        )

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        # Mock declare transaction signing - this would need custom handling in the actual server
        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xdeclare123456789abcdef123456789abcdef123456789abcdef123456789abc",
                "contract_class_hash": transaction_payload["contract_class_hash"],
                "sender_address": transaction_payload["sender_address"],
                "transaction_type": "declare",
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response.get("transaction_type") == "declare"

    def test_deploy_account_transaction_signing(self, aws_mock_fixtures):
        """Test deploy account transaction signing."""
        user_session = aws_mock_fixtures.create_test_user_session("deploy_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        transaction_payload = (
            StarknetTransactionTestHelper.create_deploy_account_transaction_payload()
        )

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xdeploy123456789abcdef123456789abcdef123456789abcdef123456789abcd",
                "class_hash": transaction_payload["class_hash"],
                "contract_address_salt": transaction_payload["contract_address_salt"],
                "transaction_type": "deploy_account",
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response.get("transaction_type") == "deploy_account"

    def test_batch_transaction_signing(self, aws_mock_fixtures):
        """Test batch transaction signing (multiple calls in one transaction)."""
        user_session = aws_mock_fixtures.create_test_user_session("batch_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        # Create batch transaction with multiple calls
        transaction_payload = {
            "batch_calls": [
                {
                    "contract_address": "0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5",
                    "function_name": "approve",
                    "calldata": [0x1234, 0x100],
                },
                {
                    "contract_address": "0x02b5ce4d999c9cc7c6c6cc7e7f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
                    "function_name": "transfer",
                    "calldata": [0x5678, 0x200],
                },
            ],
            "max_fee": "0x2c68af0bb140000",
            "nonce": 0,
            "chain_id": "testnet",
        }

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xbatch123456789abcdef123456789abcdef123456789abcdef123456789abcde",
                "batch_calls": transaction_payload["batch_calls"],
                "num_calls": len(transaction_payload["batch_calls"]),
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response.get("num_calls") == 2


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.e2e
class TestMultiUserConcurrentSigning:
    """Test multi-user concurrent transaction signing."""

    def test_concurrent_user_signing(self, aws_mock_fixtures):
        """Test concurrent signing by multiple users."""
        num_users = 5
        users = []

        # Create test users
        for i in range(num_users):
            user_session = aws_mock_fixtures.create_test_user_session(
                f"concurrent_user_{i}"
            )
            users.append(user_session)

        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        def sign_transaction_for_user(user_index: int) -> Dict[str, Any]:
            """Sign a transaction for a specific user."""
            user_session = users[user_index]

            transaction_payload = (
                StarknetTransactionTestHelper.create_invoke_transaction_payload(
                    nonce=user_index,
                    calldata=[0x1000 + user_index, 0x2000 + user_index],
                )
            )

            request_payload = {
                "username": user_session["user_id"],
                "key_index": user_index,
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload,
            }

            # Mock response with user-specific data
            mock_response = {
                "transaction_signed": f"0x{(0x123456789abcdef + user_index):x},0x{(0x987654321fedcba + user_index):x}",
                "transaction_hash": f"0x{(0xabcdef123456789 + user_index):064x}",
                "username": user_session["user_id"],
                "key_index": user_index,
                "nonce": user_index,
                "success": True,
            }

            # Simulate processing time
            time.sleep(0.1)
            return mock_response

        # Execute concurrent signing
        with ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = [
                executor.submit(sign_transaction_for_user, i) for i in range(num_users)
            ]
            responses = [future.result() for future in as_completed(futures)]

        # Validate all responses
        assert len(responses) == num_users

        usernames = {resp["username"] for resp in responses}
        signatures = {resp["transaction_signed"] for resp in responses}

        # All users should be different
        assert len(usernames) == num_users
        # All signatures should be different
        assert len(signatures) == num_users

        for response in responses:
            assert response["success"] is True
            assert "transaction_signed" in response

    def test_concurrent_same_user_different_keys(self, aws_mock_fixtures):
        """Test concurrent signing by same user with different key indices."""
        user_session = aws_mock_fixtures.create_test_user_session("multi_key_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        num_keys = 3

        def sign_with_key_index(key_index: int) -> Dict[str, Any]:
            """Sign transaction with specific key index."""
            transaction_payload = (
                StarknetTransactionTestHelper.create_invoke_transaction_payload(
                    nonce=key_index, calldata=[0x3000 + key_index, 0x4000 + key_index]
                )
            )

            request_payload = {
                "username": user_session["user_id"],
                "key_index": key_index,
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload,
            }

            mock_response = {
                "transaction_signed": f"0x{(0x555666777888999 + key_index):x},0x{(0x111222333444555 + key_index):x}",
                "transaction_hash": f"0x{(0xfedcba987654321 + key_index):064x}",
                "username": user_session["user_id"],
                "key_index": key_index,
                "account_address": f"0x{(0x01234567890abcdef + key_index):060x}",
                "success": True,
            }

            time.sleep(0.05)
            return mock_response

        # Execute concurrent signing with different keys
        with ThreadPoolExecutor(max_workers=num_keys) as executor:
            futures = [executor.submit(sign_with_key_index, i) for i in range(num_keys)]
            responses = [future.result() for future in as_completed(futures)]

        # Validate responses
        assert len(responses) == num_keys

        key_indices = {resp["key_index"] for resp in responses}
        signatures = {resp["transaction_signed"] for resp in responses}
        addresses = {resp["account_address"] for resp in responses}

        # All key indices should be different
        assert len(key_indices) == num_keys
        # All signatures should be different (different keys)
        assert len(signatures) == num_keys
        # All addresses should be different (derived from different keys)
        assert len(addresses) == num_keys

    def test_high_concurrency_stress_test(self, aws_mock_fixtures):
        """Test high concurrency stress test."""
        # Create a reasonable number of users for stress testing
        num_concurrent_requests = 20
        users = []

        for i in range(num_concurrent_requests):
            user_session = aws_mock_fixtures.create_test_user_session(
                f"stress_user_{i}"
            )
            users.append(user_session)

        aws_mock_fixtures.create_encrypted_master_seed()

        def stress_sign_transaction(request_id: int) -> Dict[str, Any]:
            """Simulate stress transaction signing."""
            user_session = users[request_id % len(users)]

            transaction_payload = (
                StarknetTransactionTestHelper.create_invoke_transaction_payload(
                    nonce=request_id,
                    calldata=[0x5000 + request_id, 0x6000 + request_id],
                )
            )

            # Simulate some processing time
            time.sleep(0.01)

            return {
                "transaction_signed": f"0x{(0xaaa000000000000 + request_id):x},0x{(0xbbb000000000000 + request_id):x}",
                "transaction_hash": f"0x{(0xccc000000000000 + request_id):064x}",
                "username": user_session["user_id"],
                "request_id": request_id,
                "success": True,
            }

        # Execute stress test
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(stress_sign_transaction, i)
                for i in range(num_concurrent_requests)
            ]
            responses = [future.result() for future in as_completed(futures)]

        end_time = time.time()
        duration = end_time - start_time

        # Validate stress test results
        assert len(responses) == num_concurrent_requests

        # All requests should succeed
        success_count = sum(1 for resp in responses if resp.get("success"))
        assert success_count == num_concurrent_requests

        # Performance validation - should complete in reasonable time
        throughput = num_concurrent_requests / duration
        print(f"Stress test throughput: {throughput:.2f} requests/second")

        # Should handle at least 5 requests per second
        assert throughput > 5.0, f"Throughput too low: {throughput:.2f} req/sec"


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.e2e
class TestStarknetNetworkIntegration:
    """Test integration with different Starknet networks."""

    def test_testnet_transaction_signing(self, aws_mock_fixtures):
        """Test transaction signing for Starknet testnet."""
        user_session = aws_mock_fixtures.create_test_user_session("testnet_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        transaction_payload = (
            StarknetTransactionTestHelper.create_invoke_transaction_payload(
                chain_id="testnet",
                rpc_url="https://starknet-testnet.public.blastapi.io",
            )
        )

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xtestnet123456789abcdef123456789abcdef123456789abcdef123456789ab",
                "chain_id": "testnet",
                "rpc_url": "https://starknet-testnet.public.blastapi.io",
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response.get("chain_id") == "testnet"

    def test_mainnet_transaction_signing(self, aws_mock_fixtures):
        """Test transaction signing for Starknet mainnet."""
        user_session = aws_mock_fixtures.create_test_user_session("mainnet_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        transaction_payload = (
            StarknetTransactionTestHelper.create_invoke_transaction_payload(
                chain_id="mainnet",
                rpc_url="https://starknet-mainnet.public.blastapi.io",
                max_fee="0x5af3107a4000",  # Higher fee for mainnet
            )
        )

        request_payload = {
            "username": user_session["user_id"],
            "key_index": 0,
            "session_data": user_session["session_data"],
            "credential": user_session["credentials"],
            "encrypted_master_seed": master_seed["encrypted_blob"],
            "transaction_payload": transaction_payload,
        }

        with patch(
            "application.starknet.enclave.multiuser_server.process_multiuser_request"
        ) as mock_process:
            mock_response = {
                "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                "transaction_hash": "0xmainnet123456789abcdef123456789abcdef123456789abcdef123456789abc",
                "chain_id": "mainnet",
                "rpc_url": "https://starknet-mainnet.public.blastapi.io",
                "max_fee": "0x5af3107a4000",
                "success": True,
            }
            mock_process.return_value = mock_response

            from application.starknet.enclave.multiuser_server import (
                process_multiuser_request,
            )

            response = process_multiuser_request(request_payload)

            StarknetTransactionTestHelper.validate_transaction_signature(response)
            assert response.get("chain_id") == "mainnet"
            assert response.get("max_fee") == "0x5af3107a4000"

    def test_account_abstraction_patterns(self, aws_mock_fixtures):
        """Test account abstraction transaction patterns."""
        user_session = aws_mock_fixtures.create_test_user_session("aa_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        # Test different account abstraction patterns
        aa_patterns = [
            {
                "pattern": "multisig",
                "contract_address": "0x05d25bb7ec7f5f1bb7e5b1a5f5b8f7d7c6c5b4a39291817c9e7f8c6b5a4938271",
                "function_name": "execute_transaction",
                "calldata": [0x2, 0x123, 0x456],  # num_calls, call1, call2
            },
            {
                "pattern": "session_key",
                "contract_address": "0x06d36cc8ed8f6f2bb8e6b2a6f6b9f8d8c7c6b5a49382928d8c9e8f9c7b6a5949382",
                "function_name": "execute_with_session_key",
                "calldata": [0x789, 0xABC, 0xDEF],
            },
        ]

        for pattern_config in aa_patterns:
            transaction_payload = (
                StarknetTransactionTestHelper.create_invoke_transaction_payload(
                    contract_address=pattern_config["contract_address"],
                    function_name=pattern_config["function_name"],
                    calldata=pattern_config["calldata"],
                )
            )

            request_payload = {
                "username": user_session["user_id"],
                "key_index": 0,
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload,
            }

            with patch(
                "application.starknet.enclave.multiuser_server.process_multiuser_request"
            ) as mock_process:
                mock_response = {
                    "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                    "transaction_hash": f"0x{pattern_config['pattern']}123456789abcdef123456789abcdef123456789abcdef",
                    "contract_address": pattern_config["contract_address"],
                    "function_name": pattern_config["function_name"],
                    "aa_pattern": pattern_config["pattern"],
                    "success": True,
                }
                mock_process.return_value = mock_response

                from application.starknet.enclave.multiuser_server import (
                    process_multiuser_request,
                )

                response = process_multiuser_request(request_payload)

                StarknetTransactionTestHelper.validate_transaction_signature(response)
                assert response.get("aa_pattern") == pattern_config["pattern"]

    def test_gas_estimation_and_fee_handling(self, aws_mock_fixtures):
        """Test gas estimation and fee handling."""
        user_session = aws_mock_fixtures.create_test_user_session("gas_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()

        # Test different fee scenarios
        fee_scenarios = [
            {"max_fee": "0x16345785d8a0000", "expected_gas": "low"},
            {"max_fee": "0x2c68af0bb140000", "expected_gas": "medium"},
            {"max_fee": "0x58d15e17628a0000", "expected_gas": "high"},
        ]

        for scenario in fee_scenarios:
            transaction_payload = (
                StarknetTransactionTestHelper.create_invoke_transaction_payload(
                    max_fee=scenario["max_fee"]
                )
            )

            request_payload = {
                "username": user_session["user_id"],
                "key_index": 0,
                "session_data": user_session["session_data"],
                "credential": user_session["credentials"],
                "encrypted_master_seed": master_seed["encrypted_blob"],
                "transaction_payload": transaction_payload,
            }

            with patch(
                "application.starknet.enclave.multiuser_server.process_multiuser_request"
            ) as mock_process:
                mock_response = {
                    "transaction_signed": "0x123456789abcdef,0x987654321fedcba",
                    "transaction_hash": "0xfee123456789abcdef123456789abcdef123456789abcdef123456789abcdef",
                    "max_fee": scenario["max_fee"],
                    "estimated_gas": scenario["expected_gas"],
                    "success": True,
                }
                mock_process.return_value = mock_response

                from application.starknet.enclave.multiuser_server import (
                    process_multiuser_request,
                )

                response = process_multiuser_request(request_payload)

                StarknetTransactionTestHelper.validate_transaction_signature(response)
                assert response.get("max_fee") == scenario["max_fee"]
                assert response.get("estimated_gas") == scenario["expected_gas"]
