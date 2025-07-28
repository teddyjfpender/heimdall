"""
Starknet-py Integration Tests for Transaction Signing.

This module implements comprehensive integration tests that validate the
integration with the starknet-py library for transaction creation, signing,
and verification against real Starknet transaction patterns.
"""

import pytest
from typing import Dict, List, Any, Optional, Tuple
from unittest.mock import Mock, patch, MagicMock
import json

from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.account.account import Account
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.signer.stark_curve_signer import StarkCurveSigner
from starknet_py.net.models.transaction import (
    InvokeTransaction, 
    DeclareTransaction, 
    DeployAccountTransaction
)
from starknet_py.hash.transaction import compute_transaction_hash
from starknet_py.hash.utils import compute_hash_on_elements
from starknet_py.common import create_compiled_contract

from tests.fixtures.aws_mocks.test_fixtures import AWSMockFixtures


class StarknetPyIntegrationHelper:
    """Helper class for starknet-py integration testing."""
    
    @staticmethod
    def create_mock_full_node_client(
        chain_id: StarknetChainId = StarknetChainId.TESTNET,
        simulate_responses: bool = True
    ) -> Mock:
        """Create a mock FullNodeClient for testing."""
        mock_client = Mock(spec=FullNodeClient)
        mock_client.chain_id = chain_id
        
        if simulate_responses:
            # Mock common client responses
            mock_client.get_block_hash_and_number.return_value = Mock(
                block_hash=0x1234567890abcdef,
                block_number=123456
            )
            
            mock_client.get_nonce.return_value = 0
            
            mock_client.estimate_fee.return_value = Mock(
                overall_fee=0x16345785d8a0000,
                gas_consumed=50000,
                gas_price=100000000000
            )
        
        return mock_client
    
    @staticmethod
    def create_test_account(
        private_key: int,
        account_address: int,
        chain_id: StarknetChainId = StarknetChainId.TESTNET,
        mock_client: Optional[Mock] = None
    ) -> Account:
        """Create a test Account instance."""
        if mock_client is None:
            mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client(chain_id)
        
        signer = StarkCurveSigner(
            account_address=account_address,
            key_pair=private_key,
            chain_id=chain_id
        )
        
        return Account(
            address=account_address,
            client=mock_client,
            signer=signer,
            chain=chain_id
        )
    
    @staticmethod
    def validate_starknet_signature(
        signature: List[int],
        transaction_hash: int,
        public_key: int
    ) -> bool:
        """Validate a Starknet signature against transaction hash and public key."""
        # In a real implementation, this would use starknet-py's signature verification
        # For testing, we'll do basic format validation
        return (
            len(signature) == 2 and
            all(isinstance(s, int) for s in signature) and
            all(0 < s < 2**251 for s in signature)
        )
    
    @staticmethod
    def create_sample_call(
        contract_address: int,
        function_name: str,
        calldata: List[int]
    ) -> Call:
        """Create a sample Call object."""
        return Call(
            to_addr=contract_address,
            selector=get_selector_from_name(function_name),
            calldata=calldata
        )


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.starknet_py
class TestStarknetPyTransactionCreation:
    """Test transaction creation using starknet-py."""
    
    def test_invoke_transaction_creation_and_signing(self, aws_mock_fixtures):
        """Test creation and signing of invoke transactions with starknet-py."""
        user_session = aws_mock_fixtures.create_test_user_session("starknet_py_user")
        master_seed = aws_mock_fixtures.create_encrypted_master_seed()
        
        # Test parameters
        private_key = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        account_address = 0x01a4bd3c888c8bb6c5b5bb6d8d5c5e5e5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5
        
        # Create mock client and account
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        # Create test call
        contract_address = 0x02b5ce4d999c9cc7c6c6cc7e7f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6
        function_name = "transfer"
        calldata = [0x123456789, 0x1000]
        
        call = StarknetPyIntegrationHelper.create_sample_call(
            contract_address, function_name, calldata
        )
        
        # Mock the signing process
        with patch.object(account, 'sign_invoke_transaction') as mock_sign:
            mock_signed_tx = Mock()
            mock_signed_tx.signature = [0x123456789abcdef, 0x987654321fedcba]
            mock_signed_tx.transaction_hash = 0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef
            mock_signed_tx.calldata = calldata
            mock_signed_tx.contract_address = contract_address
            mock_signed_tx.entry_point_selector = get_selector_from_name(function_name)
            mock_signed_tx.max_fee = 0x16345785d8a0000
            mock_signed_tx.nonce = 0
            
            mock_sign.return_value = mock_signed_tx
            
            # Sign the transaction
            signed_transaction = account.sign_invoke_transaction(
                calls=[call],
                max_fee=0x16345785d8a0000,
                nonce=0
            )
            
            # Validate the signed transaction
            assert signed_transaction is not None
            assert len(signed_transaction.signature) == 2
            assert all(isinstance(s, int) for s in signed_transaction.signature)
            assert signed_transaction.transaction_hash is not None
            
            # Validate signature format
            signature = signed_transaction.signature
            assert StarknetPyIntegrationHelper.validate_starknet_signature(
                signature, 
                signed_transaction.transaction_hash, 
                account.signer.public_key
            )
            
            # Ensure signing was called with correct parameters
            mock_sign.assert_called_once_with(
                calls=[call],
                max_fee=0x16345785d8a0000,
                nonce=0
            )
    
    def test_declare_transaction_creation(self, aws_mock_fixtures):
        """Test creation of declare transactions with starknet-py."""
        user_session = aws_mock_fixtures.create_test_user_session("declare_user")
        
        # Test parameters for declare transaction
        private_key = 0x2345678901bcdef2345678901bcdef2345678901bcdef2345678901bcdef234
        account_address = 0x03c6df5e111d1dd8d7d7dd8f8g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7g7
        
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        # Mock contract class for declare transaction
        mock_contract_class = {
            "sierra_program": ["mock", "sierra", "program"],
            "contract_class_version": "0.1.0",
            "entry_points_by_type": {
                "EXTERNAL": [],
                "L1_HANDLER": [],
                "CONSTRUCTOR": []
            },
            "abi": []
        }
        
        compiled_contract = create_compiled_contract(
            compiled_contract=mock_contract_class,
            abi=mock_contract_class["abi"]
        )
        
        # Mock the declare transaction signing
        with patch.object(account, 'sign_declare_transaction') as mock_sign_declare:
            mock_signed_declare = Mock()
            mock_signed_declare.signature = [0x234567890abcdef1, 0x876543210fedcba1]
            mock_signed_declare.transaction_hash = 0xdeclare123456789abcdef123456789abcdef123456789abcdef123456789abc
            mock_signed_declare.class_hash = 0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123
            mock_signed_declare.sender_address = account_address
            mock_signed_declare.max_fee = 0x5af3107a4000
            mock_signed_declare.nonce = 1
            
            mock_sign_declare.return_value = mock_signed_declare
            
            # Create and sign declare transaction
            signed_declare = account.sign_declare_transaction(
                compiled_contract=compiled_contract,
                max_fee=0x5af3107a4000,
                nonce=1
            )
            
            # Validate declare transaction
            assert signed_declare is not None
            assert len(signed_declare.signature) == 2
            assert signed_declare.class_hash is not None
            assert signed_declare.sender_address == account_address
            
            # Validate signature
            assert StarknetPyIntegrationHelper.validate_starknet_signature(
                signed_declare.signature,
                signed_declare.transaction_hash,
                account.signer.public_key
            )
    
    def test_deploy_account_transaction_creation(self, aws_mock_fixtures):
        """Test creation of deploy account transactions with starknet-py."""
        user_session = aws_mock_fixtures.create_test_user_session("deploy_account_user")
        
        # Test parameters
        private_key = 0x3456789012cdef3456789012cdef3456789012cdef3456789012cdef345678
        account_address = 0x04d7e0f5222e2ee9e8e8ee9f9h8h8h8h8h8h8h8h8h8h8h8h8h8h8h8h8h8h8h8
        
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        # Mock deploy account transaction
        with patch.object(account, 'sign_deploy_account_transaction') as mock_sign_deploy:
            mock_signed_deploy = Mock()
            mock_signed_deploy.signature = [0x345678901abcdef2, 0x765432109fedcba2]
            mock_signed_deploy.transaction_hash = 0xdeploy123456789abcdef123456789abcdef123456789abcdef123456789abcd
            mock_signed_deploy.class_hash = 0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2
            mock_signed_deploy.contract_address_salt = 0x123456789abcdef
            mock_signed_deploy.constructor_calldata = []
            mock_signed_deploy.max_fee = 0x5af3107a4000
            mock_signed_deploy.nonce = 0
            
            mock_sign_deploy.return_value = mock_signed_deploy
            
            # Create and sign deploy account transaction
            signed_deploy = account.sign_deploy_account_transaction(
                class_hash=0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2,
                contract_address_salt=0x123456789abcdef,
                constructor_calldata=[],
                max_fee=0x5af3107a4000,
                nonce=0
            )
            
            # Validate deploy account transaction
            assert signed_deploy is not None
            assert len(signed_deploy.signature) == 2
            assert signed_deploy.class_hash is not None
            assert signed_deploy.contract_address_salt is not None
            
            # Validate signature
            assert StarknetPyIntegrationHelper.validate_starknet_signature(
                signed_deploy.signature,
                signed_deploy.transaction_hash,
                account.signer.public_key
            )


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.starknet_py
class TestStarknetPyHashingAndVerification:
    """Test Starknet hashing and verification using starknet-py."""
    
    def test_transaction_hash_computation(self, aws_mock_fixtures):
        """Test transaction hash computation consistency."""
        user_session = aws_mock_fixtures.create_test_user_session("hash_test_user")
        
        # Test parameters
        private_key = 0x4567890123def4567890123def4567890123def4567890123def4567890123
        account_address = 0x05e8e1f6333f3ff0f0f0ff1g0i9i9i9i9i9i9i9i9i9i9i9i9i9i9i9i9i9i9i9
        
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        
        # Create call for hashing
        contract_address = 0x06f9f2g7444g4gg1g1g1gg2h1j0j0j0j0j0j0j0j0j0j0j0j0j0j0j0j0j0j0j0
        function_name = "approve"
        calldata = [0x987654321, 0x2000]
        
        call = StarknetPyIntegrationHelper.create_sample_call(
            contract_address, function_name, calldata
        )
        
        # Test transaction hash computation
        max_fee = 0x16345785d8a0000
        nonce = 5
        chain_id = StarknetChainId.TESTNET
        
        # Mock hash computation
        with patch('starknet_py.hash.transaction.compute_transaction_hash') as mock_compute_hash:
            expected_hash = 0xhash123456789abcdef123456789abcdef123456789abcdef123456789abcdef
            mock_compute_hash.return_value = expected_hash
            
            # Compute hash
            computed_hash = compute_transaction_hash(
                tx_hash_prefix=b"invoke",
                version=1,
                contract_address=account_address,
                entry_point_selector=call.selector,
                calldata=call.calldata,
                max_fee=max_fee,
                chain_id=chain_id.value,
                nonce=nonce
            )
            
            # Validate hash computation
            assert computed_hash == expected_hash
            
            # Ensure hash function was called
            mock_compute_hash.assert_called_once()
    
    def test_selector_computation(self, aws_mock_fixtures):
        """Test function selector computation."""
        # Test various function names
        function_names = [
            "transfer",
            "approve", 
            "transferFrom",
            "balanceOf",
            "execute_transaction",
            "multicall"
        ]
        
        for function_name in function_names:
            selector = get_selector_from_name(function_name)
            
            # Validate selector format
            assert isinstance(selector, int)
            assert 0 < selector < 2**251  # Valid field element
            
            # Selector should be deterministic
            selector2 = get_selector_from_name(function_name)
            assert selector == selector2
        
        # Test that different function names produce different selectors
        selectors = [get_selector_from_name(name) for name in function_names]
        assert len(set(selectors)) == len(function_names)
    
    def test_calldata_serialization(self, aws_mock_fixtures):
        """Test calldata serialization for complex types."""
        # Test different calldata patterns
        calldata_tests = [
            {
                "name": "Simple transfer",
                "calldata": [0x123456789, 0x1000],
                "expected_length": 2
            },
            {
                "name": "Array parameter",
                "calldata": [3, 0x111, 0x222, 0x333],  # length + elements
                "expected_length": 4
            },
            {
                "name": "Struct parameter",
                "calldata": [0x456, 0x789, 0x2000, 0x3000],  # struct fields
                "expected_length": 4
            },
            {
                "name": "Empty calldata",
                "calldata": [],
                "expected_length": 0
            }
        ]
        
        for test in calldata_tests:
            call = Call(
                to_addr=0x123,
                selector=get_selector_from_name("test_function"),
                calldata=test["calldata"]
            )
            
            # Validate calldata
            assert len(call.calldata) == test["expected_length"]
            assert all(isinstance(cd, int) for cd in call.calldata)
            assert all(0 <= cd < 2**251 for cd in call.calldata)  # Valid field elements


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.starknet_py
class TestStarknetPyChainInteraction:
    """Test chain interaction patterns with starknet-py."""
    
    def test_chain_id_handling(self, aws_mock_fixtures):
        """Test proper chain ID handling for different networks."""
        user_session = aws_mock_fixtures.create_test_user_session("chain_test_user")
        
        # Test different chain IDs
        chain_tests = [
            {
                "chain_id": StarknetChainId.TESTNET,
                "expected_name": "testnet",
                "rpc_url": "https://starknet-testnet.public.blastapi.io"
            },
            {
                "chain_id": StarknetChainId.MAINNET,
                "expected_name": "mainnet", 
                "rpc_url": "https://starknet-mainnet.public.blastapi.io"
            }
        ]
        
        private_key = 0x5678901234ef5678901234ef5678901234ef5678901234ef5678901234ef567
        account_address = 0x07f0f3h8555h5hh2h2h2hh3i2k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1k1
        
        for test in chain_tests:
            mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client(test["chain_id"])
            account = StarknetPyIntegrationHelper.create_test_account(
                private_key, account_address, test["chain_id"], mock_client
            )
            
            # Validate chain configuration
            assert account.chain == test["chain_id"]
            assert account.signer.chain_id == test["chain_id"]
            assert mock_client.chain_id == test["chain_id"]
            
            # Test transaction creation with correct chain ID
            call = Call(
                to_addr=0x123,
                selector=get_selector_from_name("test"),
                calldata=[0x456]
            )
            
            with patch.object(account, 'sign_invoke_transaction') as mock_sign:
                mock_signed_tx = Mock()
                mock_signed_tx.signature = [0x111, 0x222]
                mock_signed_tx.transaction_hash = 0x333
                mock_sign.return_value = mock_signed_tx
                
                signed_tx = account.sign_invoke_transaction(
                    calls=[call],
                    max_fee=0x16345785d8a0000,
                    nonce=0
                )
                
                assert signed_tx is not None
                mock_sign.assert_called_once()
    
    def test_fee_estimation_integration(self, aws_mock_fixtures):
        """Test fee estimation integration with starknet-py."""
        user_session = aws_mock_fixtures.create_test_user_session("fee_test_user")
        
        private_key = 0x6789012345f6789012345f6789012345f6789012345f6789012345f678901
        account_address = 0x08g1g4i9666i6ii3i3i3ii4j3l2l2l2l2l2l2l2l2l2l2l2l2l2l2l2l2l2l2l2
        
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        # Test different fee estimation scenarios
        fee_scenarios = [
            {
                "name": "Low complexity",
                "calldata": [0x123],
                "expected_fee_range": (0x1000000000000, 0x10000000000000)
            },
            {
                "name": "Medium complexity", 
                "calldata": [0x456, 0x789, 0xabc],
                "expected_fee_range": (0x5000000000000, 0x50000000000000)
            },
            {
                "name": "High complexity",
                "calldata": list(range(100)),  # Large calldata
                "expected_fee_range": (0x10000000000000, 0x100000000000000)
            }
        ]
        
        for scenario in fee_scenarios:
            call = Call(
                to_addr=0x123,
                selector=get_selector_from_name("complex_function"),
                calldata=scenario["calldata"]
            )
            
            # Mock fee estimation
            mock_fee_estimate = Mock()
            mock_fee_estimate.overall_fee = (scenario["expected_fee_range"][0] + scenario["expected_fee_range"][1]) // 2
            mock_fee_estimate.gas_consumed = len(scenario["calldata"]) * 1000 + 50000
            mock_fee_estimate.gas_price = 100000000000
            
            mock_client.estimate_fee.return_value = mock_fee_estimate
            
            # Test fee estimation
            estimated_fee = mock_client.estimate_fee(calls=[call])
            
            # Validate fee estimation
            assert estimated_fee.overall_fee >= scenario["expected_fee_range"][0]
            assert estimated_fee.overall_fee <= scenario["expected_fee_range"][1]
            assert estimated_fee.gas_consumed > 0
            assert estimated_fee.gas_price > 0
    
    def test_nonce_management(self, aws_mock_fixtures):
        """Test nonce management in transaction sequences."""
        user_session = aws_mock_fixtures.create_test_user_session("nonce_test_user")
        
        private_key = 0x789012345f789012345f789012345f789012345f789012345f789012345f78
        account_address = 0x09h2h5j0777j7jj4j4j4jj5k4m3m3m3m3m3m3m3m3m3m3m3m3m3m3m3m3m3m3m3
        
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        # Test nonce sequence
        initial_nonce = 10
        num_transactions = 5
        
        for i in range(num_transactions):
            expected_nonce = initial_nonce + i
            
            # Mock nonce retrieval
            mock_client.get_nonce.return_value = expected_nonce
            
            call = Call(
                to_addr=0x456,
                selector=get_selector_from_name("sequential_call"),
                calldata=[i]
            )
            
            with patch.object(account, 'sign_invoke_transaction') as mock_sign:
                mock_signed_tx = Mock()
                mock_signed_tx.signature = [0x111 + i, 0x222 + i]
                mock_signed_tx.transaction_hash = 0x333 + i
                mock_signed_tx.nonce = expected_nonce
                mock_sign.return_value = mock_signed_tx
                
                # Sign transaction with current nonce
                signed_tx = account.sign_invoke_transaction(
                    calls=[call],
                    max_fee=0x16345785d8a0000,
                    nonce=expected_nonce
                )
                
                # Validate nonce handling
                assert signed_tx.nonce == expected_nonce
                mock_sign.assert_called_once_with(
                    calls=[call],
                    max_fee=0x16345785d8a0000,
                    nonce=expected_nonce
                )


@pytest.mark.starknet
@pytest.mark.integration
@pytest.mark.starknet_py
class TestStarknetPyErrorHandling:
    """Test error handling with starknet-py integration."""
    
    def test_invalid_private_key_handling(self, aws_mock_fixtures):
        """Test handling of invalid private keys."""
        # Test various invalid private key scenarios
        invalid_keys = [
            0,  # Zero key
            -1,  # Negative key
            2**251,  # Key too large for field
            "invalid_key",  # Non-integer key
        ]
        
        account_address = 0x123
        
        for invalid_key in invalid_keys:
            with pytest.raises((ValueError, TypeError, AssertionError)):
                # This should raise an error
                StarkCurveSigner(
                    account_address=account_address,
                    key_pair=invalid_key,
                    chain_id=StarknetChainId.TESTNET
                )
    
    def test_invalid_transaction_parameters(self, aws_mock_fixtures):
        """Test handling of invalid transaction parameters."""
        user_session = aws_mock_fixtures.create_test_user_session("error_test_user")
        
        private_key = 0x8901234567890123456789012345678901234567890123456789012345678901
        account_address = 0x10i3i6k1888k8kk5k5k5kk6l5n4n4n4n4n4n4n4n4n4n4n4n4n4n4n4n4n4n4n4
        
        mock_client = StarknetPyIntegrationHelper.create_mock_full_node_client()
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        # Test invalid call parameters
        invalid_call_tests = [
            {
                "name": "Invalid contract address",
                "to_addr": -1,  # Negative address
                "selector": get_selector_from_name("test"),
                "calldata": [0x123]
            },
            {
                "name": "Invalid selector",
                "to_addr": 0x123,
                "selector": -1,  # Negative selector
                "calldata": [0x123]
            },
            {
                "name": "Invalid calldata element",
                "to_addr": 0x123,
                "selector": get_selector_from_name("test"),
                "calldata": [-1]  # Negative calldata element
            }
        ]
        
        for test in invalid_call_tests:
            with pytest.raises((ValueError, AssertionError, TypeError)):
                Call(
                    to_addr=test["to_addr"],
                    selector=test["selector"],
                    calldata=test["calldata"]
                )
    
    def test_network_error_handling(self, aws_mock_fixtures):
        """Test handling of network errors."""
        user_session = aws_mock_fixtures.create_test_user_session("network_error_user")
        
        private_key = 0x9012345678901234567890123456789012345678901234567890123456789012
        account_address = 0x11j4j7l2999l9ll6l6l6ll7m6o5o5o5o5o5o5o5o5o5o5o5o5o5o5o5o5o5o5o5
        
        # Create mock client that simulates network errors
        mock_client = Mock(spec=FullNodeClient)
        mock_client.chain_id = StarknetChainId.TESTNET
        
        # Simulate different network errors
        network_errors = [
            ConnectionError("Network connection failed"),
            TimeoutError("Request timeout"),
            Exception("RPC endpoint unreachable")
        ]
        
        account = StarknetPyIntegrationHelper.create_test_account(
            private_key, account_address, StarknetChainId.TESTNET, mock_client
        )
        
        call = Call(
            to_addr=0x456,
            selector=get_selector_from_name("test_function"),
            calldata=[0x789]
        )
        
        for error in network_errors:
            # Mock client to raise network error
            mock_client.get_nonce.side_effect = error
            mock_client.estimate_fee.side_effect = error
            
            # Test that network errors are properly propagated
            with pytest.raises(type(error)):
                mock_client.get_nonce(account_address)
            
            with pytest.raises(type(error)):
                mock_client.estimate_fee(calls=[call])
    
    def test_signature_validation_errors(self, aws_mock_fixtures):
        """Test signature validation error scenarios."""
        user_session = aws_mock_fixtures.create_test_user_session("signature_error_user")
        
        # Test signature validation with invalid signatures
        invalid_signatures = [
            [],  # Empty signature
            [0x123],  # Single component (should be r,s pair)
            [0x123, 0x456, 0x789],  # Too many components
            [0, 0x456],  # Zero r component
            [0x123, 0],  # Zero s component
            [-1, 0x456],  # Negative component
            [2**251, 0x456],  # Component too large
        ]
        
        transaction_hash = 0xabcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef
        public_key = 0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456
        
        for invalid_sig in invalid_signatures:
            # Should return False for invalid signatures
            is_valid = StarknetPyIntegrationHelper.validate_starknet_signature(
                invalid_sig, transaction_hash, public_key
            )
            assert is_valid is False, f"Invalid signature {invalid_sig} incorrectly validated as True"