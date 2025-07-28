"""Factory classes for generating Starknet test data.

This module provides factory classes for creating realistic Starknet test data,
including private keys, addresses, transactions, and other Starknet-specific
data structures. All factories use the STARK curve parameters.
"""

import base64
import json
import random
import secrets
import factory
from factory import fuzzy


# Starknet-specific constants
STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001
STARK_ORDER = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
STARK_CURVE_ALPHA = 1
STARK_CURVE_BETA = 0x6F21413EFBE40DE150E596D72F7A8C5609AD26C15C915C1F4CDFCB99CEE9E89


class StarknetPrivateKeyFactory(factory.Factory):
    """Factory for generating Starknet private keys.
    
    Generates valid private keys for the STARK curve, ensuring they're
    within the valid range [1, STARK_ORDER - 1].
    """
    
    class Meta:
        model = str
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Generate a valid STARK curve private key."""
        # Generate random key in valid range
        key_int = secrets.randbelow(STARK_ORDER - 1) + 1
        # Return as hex string with 0x prefix
        return "0x" + format(key_int, '064x')


class StarknetFieldElementFactory(factory.Factory):
    """Factory for generating Starknet field elements.
    
    Creates valid field elements within the STARK prime field.
    """
    
    class Meta:
        model = str
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Generate a valid STARK field element."""
        field_element = secrets.randbelow(STARK_PRIME)
        return "0x" + format(field_element, '063x')


class StarknetAddressFactory(factory.Factory):
    """Factory for generating Starknet contract addresses.
    
    Starknet addresses are field elements, typically derived from
    contract class hash, salt, and constructor arguments.
    """
    
    class Meta:
        model = str
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Generate a valid Starknet contract address."""
        # Starknet addresses are field elements
        address = secrets.randbelow(STARK_PRIME)
        return "0x" + format(address, '063x')


class StarknetTransactionHashFactory(factory.Factory):
    """Factory for generating Starknet transaction hashes."""
    
    class Meta:
        model = str
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Generate a valid Starknet transaction hash."""
        tx_hash = secrets.randbelow(STARK_PRIME)
        return "0x" + format(tx_hash, '063x')


class StarknetInvokeTransactionFactory(factory.Factory):
    """Factory for generating Starknet invoke transactions.
    
    Creates realistic invoke transaction payloads for testing
    Starknet transaction signing functionality.
    """
    
    class Meta:
        model = dict
    
    # Transaction version (Cairo 1.0 uses version 1)
    version = fuzzy.FuzzyChoice([0, 1])
    
    # Contract address to invoke
    contract_address = factory.SubFactory(StarknetAddressFactory)
    
    # Function selector (hash of function name)
    entry_point_selector = factory.SubFactory(StarknetFieldElementFactory)
    
    # Calldata (array of field elements)
    calldata = factory.LazyFunction(
        lambda: [StarknetFieldElementFactory() for _ in range(random.randint(1, 5))]
    )
    
    # Transaction parameters
    max_fee = fuzzy.FuzzyInteger(1000000000000000, 10000000000000000)  # 0.001 to 0.01 ETH in wei
    nonce = fuzzy.FuzzyInteger(0, 1000)
    
    # Chain ID for Starknet networks
    chain_id = fuzzy.FuzzyChoice([
        "SN_MAIN",      # Starknet Mainnet
        "SN_GOERLI",    # Starknet Goerli testnet
        "SN_GOERLI2",   # Starknet Goerli2 testnet
    ])


class StarknetDeclareTransactionFactory(factory.Factory):
    """Factory for generating Starknet declare transactions.
    
    Creates declare transaction payloads for testing contract
    declaration functionality.
    """
    
    class Meta:
        model = dict
    
    version = fuzzy.FuzzyChoice([1, 2])  # Declare transaction versions
    contract_class_hash = factory.SubFactory(StarknetFieldElementFactory)
    sender_address = factory.SubFactory(StarknetAddressFactory)
    max_fee = fuzzy.FuzzyInteger(1000000000000000, 5000000000000000)
    nonce = fuzzy.FuzzyInteger(0, 500)
    chain_id = fuzzy.FuzzyChoice(["SN_MAIN", "SN_GOERLI", "SN_GOERLI2"])


class StarknetDeployTransactionFactory(factory.Factory):
    """Factory for generating Starknet deploy transactions.
    
    Creates deploy transaction payloads for testing contract
    deployment functionality.
    """
    
    class Meta:
        model = dict
    
    version = 1
    contract_address_salt = factory.SubFactory(StarknetFieldElementFactory)
    contract_class_hash = factory.SubFactory(StarknetFieldElementFactory)
    constructor_calldata = factory.LazyFunction(
        lambda: [StarknetFieldElementFactory() for _ in range(random.randint(0, 3))]
    )
    max_fee = fuzzy.FuzzyInteger(2000000000000000, 10000000000000000)
    chain_id = fuzzy.FuzzyChoice(["SN_MAIN", "SN_GOERLI", "SN_GOERLI2"])


class StarknetSignatureFactory(factory.Factory):
    """Factory for generating Starknet ECDSA signatures.
    
    Creates realistic signature components (r, s) for testing
    signature validation and transaction signing.
    """
    
    class Meta:
        model = dict
    
    r = factory.SubFactory(StarknetFieldElementFactory)
    s = factory.SubFactory(StarknetFieldElementFactory)
    
    @factory.lazy_attribute
    def signature_array(self):
        """Return signature as array format [r, s]."""
        return [self.r, self.s]


class StarknetEnclavePayloadFactory(factory.Factory):
    """Factory for generating complete Starknet enclave communication payloads.
    
    Creates realistic payloads for testing enclave communication,
    including AWS credentials, transaction data, and encrypted keys.
    """
    
    class Meta:
        model = dict
    
    credential = factory.SubFactory("tests.factories.AWSCredentialsFactory")
    transaction_payload = factory.SubFactory(StarknetInvokeTransactionFactory)
    encrypted_key = factory.LazyFunction(lambda: base64.b64encode(secrets.token_bytes(64)).decode())
    
    # Starknet-specific fields
    network = fuzzy.FuzzyChoice(["mainnet", "goerli", "goerli2"])
    cairo_version = fuzzy.FuzzyChoice(["0", "1"])


class StarknetLambdaEventFactory(factory.Factory):
    """Base factory for generating Starknet Lambda event payloads."""
    
    class Meta:
        model = dict
    
    operation = fuzzy.FuzzyChoice(['set_key', 'get_key', 'sign_transaction'])


class StarknetSetKeyEventFactory(StarknetLambdaEventFactory):
    """Factory for Starknet set_key Lambda events."""
    
    operation = 'set_key'
    stark_key = factory.SubFactory(StarknetPrivateKeyFactory)


class StarknetGetKeyEventFactory(StarknetLambdaEventFactory):
    """Factory for Starknet get_key Lambda events."""
    
    operation = 'get_key'


class StarknetSignTransactionEventFactory(StarknetLambdaEventFactory):
    """Factory for Starknet sign_transaction Lambda events."""
    
    operation = 'sign_transaction'
    transaction_payload = factory.SubFactory(StarknetInvokeTransactionFactory)


class StarknetSignedTransactionFactory(factory.Factory):
    """Factory for generating signed Starknet transaction responses."""
    
    class Meta:
        model = dict
    
    transaction_hash = factory.SubFactory(StarknetTransactionHashFactory)
    signature = factory.SubFactory(StarknetSignatureFactory)
    
    @factory.lazy_attribute
    def transaction_signed(self):
        """Generate serialized signed transaction."""
        # In Starknet, signed transactions are typically JSON with signature
        return json.dumps({
            "transaction_hash": self.transaction_hash,
            "signature": self.signature.signature_array
        })


class StarknetAccountFactory(factory.Factory):
    """Factory for generating Starknet account data.
    
    Creates complete account information including private key,
    public key, and account address.
    """
    
    class Meta:
        model = dict
    
    private_key = factory.SubFactory(StarknetPrivateKeyFactory)
    account_address = factory.SubFactory(StarknetAddressFactory)
    
    # Account contract information
    class_hash = factory.SubFactory(StarknetFieldElementFactory)
    salt = factory.SubFactory(StarknetFieldElementFactory)
    
    # Account type
    account_type = fuzzy.FuzzyChoice(['OpenZeppelin', 'ArgentX', 'Braavos'])


class StarknetContractFactory(factory.Factory):
    """Factory for generating Starknet contract information."""
    
    class Meta:
        model = dict
    
    contract_address = factory.SubFactory(StarknetAddressFactory)
    class_hash = factory.SubFactory(StarknetFieldElementFactory)
    
    # Contract metadata
    name = factory.Sequence(lambda n: f"TestContract{n}")
    version = fuzzy.FuzzyChoice(['0.1.0', '0.2.0', '1.0.0'])
    cairo_version = fuzzy.FuzzyChoice(['0', '1'])


class StarknetBlockFactory(factory.Factory):
    """Factory for generating Starknet block information."""
    
    class Meta:
        model = dict
    
    block_hash = factory.SubFactory(StarknetFieldElementFactory)
    block_number = fuzzy.FuzzyInteger(1, 1000000)
    parent_hash = factory.SubFactory(StarknetFieldElementFactory)
    timestamp = fuzzy.FuzzyInteger(1640995200, 2000000000)  # 2022-2033 range
    sequencer_address = factory.SubFactory(StarknetAddressFactory)
    transaction_count = fuzzy.FuzzyInteger(0, 500)


# Utility functions for creating complex Starknet test scenarios

def create_complete_starknet_signing_scenario():
    """Create a complete Starknet signing scenario with all required components.
    
    Returns:
        dict: Complete scenario with private key, account, transaction, credentials
    """
    account = StarknetAccountFactory()
    transaction = StarknetInvokeTransactionFactory()
    credentials = factory.build(dict, FACTORY_CLASS="tests.factories.AWSCredentialsFactory")
    
    return {
        'private_key': account.private_key,
        'account': account,
        'transaction': transaction,
        'credentials': credentials,
        'enclave_payload': StarknetEnclavePayloadFactory(
            credential=credentials,
            transaction_payload=transaction
        )
    }


def create_starknet_lambda_test_scenario(operation='sign_transaction'):
    """Create a Starknet Lambda test scenario.
    
    Args:
        operation: Type of operation ('set_key', 'get_key', 'sign_transaction')
        
    Returns:
        dict: Lambda event payload for the specified operation
    """
    if operation == 'set_key':
        return StarknetSetKeyEventFactory()
    elif operation == 'get_key':
        return StarknetGetKeyEventFactory()
    elif operation == 'sign_transaction':
        return StarknetSignTransactionEventFactory()
    else:
        raise ValueError(f"Unknown operation: {operation}")


def create_starknet_error_scenarios():
    """Create various error scenarios for Starknet testing.
    
    Returns:
        dict: Collection of invalid data for error testing
    """
    return {
        'invalid_private_key': '0xinvalid',
        'invalid_address': '0xinvalidaddress',
        'invalid_field_element': '0x' + 'f' * 64,  # Too large for STARK prime
        'out_of_range_private_key': '0x' + format(STARK_ORDER, '064x'),  # Equal to order (invalid)
        'invalid_transaction': {
            'contract_address': 'invalid_address',
            'entry_point_selector': 'invalid_selector',
            'calldata': ['invalid_calldata'],
            'max_fee': -1,  # Invalid negative fee
            'nonce': -1,    # Invalid negative nonce
        },
        'malformed_signature': {
            'r': '0xinvalid',
            's': None
        },
        'empty_payload': {},
        'missing_transaction_fields': {
            'contract_address': StarknetAddressFactory(),
            # Missing required fields like entry_point_selector, calldata
        }
    }


def create_starknet_multi_transaction_scenario():
    """Create a scenario with multiple different transaction types.
    
    Returns:
        dict: Multiple transaction types for comprehensive testing
    """
    return {
        'invoke_transaction': StarknetInvokeTransactionFactory(),
        'declare_transaction': StarknetDeclareTransactionFactory(),
        'deploy_transaction': StarknetDeployTransactionFactory(),
        'account': StarknetAccountFactory(),
        'signatures': [StarknetSignatureFactory() for _ in range(3)]
    }


def create_starknet_performance_test_data(count=100):
    """Create large datasets for Starknet performance testing.
    
    Args:
        count: Number of each type of test data to create
        
    Returns:
        dict: Large datasets for performance testing
    """
    return {
        'private_keys': StarknetPrivateKeyFactory.create_batch(count),
        'addresses': StarknetAddressFactory.create_batch(count),
        'transactions': StarknetInvokeTransactionFactory.create_batch(count),
        'signatures': StarknetSignatureFactory.create_batch(count),
        'accounts': StarknetAccountFactory.create_batch(count // 10)  # Fewer accounts
    }


def create_starknet_cross_network_scenario():
    """Create test data for different Starknet networks.
    
    Returns:
        dict: Test data for mainnet, goerli, and goerli2 networks
    """
    networks = ["SN_MAIN", "SN_GOERLI", "SN_GOERLI2"]
    scenarios = {}
    
    for network in networks:
        scenarios[network.lower().replace('sn_', '')] = {
            'transaction': StarknetInvokeTransactionFactory(chain_id=network),
            'account': StarknetAccountFactory(),
            'contract': StarknetContractFactory()
        }
    
    return scenarios


# Validation utilities for generated test data

def validate_stark_field_element(value):
    """Validate that a value is a valid STARK field element.
    
    Args:
        value: String or int representation of field element
        
    Returns:
        bool: True if valid field element
    """
    try:
        if isinstance(value, str):
            if value.startswith('0x'):
                int_value = int(value, 16)
            else:
                int_value = int(value)
        elif isinstance(value, int):
            int_value = value
        else:
            return False
            
        return 0 <= int_value < STARK_PRIME
    except (ValueError, TypeError):
        return False


def validate_stark_private_key(key):
    """Validate that a key is a valid STARK private key.
    
    Args:
        key: String representation of private key
        
    Returns:
        bool: True if valid private key
    """
    try:
        if isinstance(key, str) and key.startswith('0x'):
            int_key = int(key, 16)
            return 1 <= int_key < STARK_ORDER
        return False
    except ValueError:
        return False


def validate_starknet_transaction(transaction):
    """Validate basic structure of a Starknet transaction.
    
    Args:
        transaction: Transaction dictionary
        
    Returns:
        bool: True if transaction has required fields
    """
    required_fields = ['contract_address', 'entry_point_selector', 'calldata', 'max_fee', 'nonce']
    return all(field in transaction for field in required_fields)