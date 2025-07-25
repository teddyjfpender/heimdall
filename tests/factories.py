"""Factory classes for generating test data."""

import base64
import json
import random
import factory
from factory import fuzzy
import web3

# TODO: change from Eth to Starknet
class EthereumPrivateKeyFactory(factory.Factory):
    """Factory for generating Ethereum private keys."""
    
    class Meta:
        model = str
    
    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        """Generate a valid secp256k1 private key."""
        key_bytes = random.randbytes(32)
        # Ensure key is in valid range (1 to n-1 where n is the order of secp256k1)
        while int.from_bytes(key_bytes, 'big') >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141:
            key_bytes = random.randbytes(32)
        return "0x" + key_bytes.hex()


# TODO: change from Eth to Starknet
class EthereumAddressFactory(factory.Factory):
    """Factory for generating Ethereum addresses."""
    
    class Meta:
        model = str
    
    @classmethod  
    def _create(cls, model_class, *args, **kwargs):
        """Generate a valid Ethereum address."""
        address_bytes = random.randbytes(20)
        return "0x" + address_bytes.hex()


# TODO: change from Eth to Starknet
class TransactionPayloadFactory(factory.Factory):
    """Factory for generating Ethereum transaction payloads."""
    
    class Meta:
        model = dict
    
    value = fuzzy.FuzzyFloat(0.001, 10.0)  # ETH amount
    to = factory.SubFactory(EthereumAddressFactory)
    nonce = fuzzy.FuzzyInteger(0, 1000)
    type = 2  # EIP-1559 transaction
    chainId = fuzzy.FuzzyChoice([1, 4, 5, 137])  # Mainnet, Rinkeby, Goerli, Polygon
    gas = fuzzy.FuzzyInteger(21000, 500000)
    maxFeePerGas = fuzzy.FuzzyInteger(20000000000, 200000000000)  # 20-200 Gwei
    maxPriorityFeePerGas = fuzzy.FuzzyInteger(1000000000, 10000000000)  # 1-10 Gwei


# TODO: change from Eth to Starknet
class LegacyTransactionPayloadFactory(factory.Factory):
    """Factory for generating legacy Ethereum transactions."""
    
    class Meta:
        model = dict
    
    value = fuzzy.FuzzyFloat(0.001, 5.0)
    to = factory.SubFactory(EthereumAddressFactory)
    nonce = fuzzy.FuzzyInteger(0, 500)
    gas = fuzzy.FuzzyInteger(21000, 300000)
    gasPrice = fuzzy.FuzzyInteger(20000000000, 100000000000)  # 20-100 Gwei
    chainId = fuzzy.FuzzyChoice([1, 4, 5])


class AWSCredentialsFactory(factory.Factory):
    """Factory for generating AWS credential payloads."""
    
    class Meta:
        model = dict
    
    access_key_id = factory.Sequence(lambda n: f"AKIA{n:016d}")
    secret_access_key = factory.LazyFunction(lambda: base64.b64encode(random.randbytes(30)).decode())
    token = factory.LazyFunction(lambda: base64.b64encode(random.randbytes(100)).decode())


class EnclavePayloadFactory(factory.Factory):
    """Factory for generating complete enclave communication payloads."""
    
    class Meta:
        model = dict
    
    credential = factory.SubFactory(AWSCredentialsFactory)
    transaction_payload = factory.SubFactory(TransactionPayloadFactory)
    encrypted_key = factory.LazyFunction(lambda: base64.b64encode(random.randbytes(64)).decode())


class LambdaEventFactory(factory.Factory):
    """Factory for generating Lambda event payloads."""
    
    class Meta:
        model = dict
    
    operation = fuzzy.FuzzyChoice(['set_key', 'get_key', 'sign_transaction'])

# TODO: change from Eth to Starknet
class SetKeyEventFactory(LambdaEventFactory):
    """Factory for set_key Lambda events."""
    
    operation = 'set_key'
    eth_key = factory.SubFactory(EthereumPrivateKeyFactory)


class GetKeyEventFactory(LambdaEventFactory):
    """Factory for get_key Lambda events."""
    
    operation = 'get_key'


class SignTransactionEventFactory(LambdaEventFactory):
    """Factory for sign_transaction Lambda events."""
    
    operation = 'sign_transaction'
    transaction_payload = factory.SubFactory(TransactionPayloadFactory)


class KMSResponseFactory(factory.Factory):
    """Factory for generating mock KMS responses."""
    
    class Meta:
        model = dict
    
    CiphertextBlob = factory.LazyFunction(lambda: base64.b64encode(random.randbytes(256)).decode())
    KeyId = factory.Sequence(lambda n: f"arn:aws:kms:us-east-1:123456789012:key/{n:08d}-1234-5678-9abc-{n:012d}")


class SecretsManagerResponseFactory(factory.Factory):
    """Factory for generating mock Secrets Manager responses."""
    
    class Meta:
        model = dict
    
    SecretString = factory.LazyFunction(lambda: base64.b64encode(random.randbytes(32)).decode())
    Name = factory.Sequence(lambda n: f"test-secret-{n}")
    ARN = factory.LazyAttribute(
        lambda obj: f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{obj.Name}"
    )


class SignedTransactionFactory(factory.Factory):
    """Factory for generating signed transaction responses."""
    
    class Meta:
        model = dict
    
    transaction_signed = factory.LazyFunction(
        lambda: "0x" + random.randbytes(100).hex()
    )
    transaction_hash = factory.LazyFunction(
        lambda: "0x" + random.randbytes(32).hex()
    )


class EC2InstanceFactory(factory.Factory):
    """Factory for generating EC2 instance data."""
    
    class Meta:
        model = dict
    
    InstanceId = factory.Sequence(lambda n: f"i-{n:017x}")
    InstanceType = fuzzy.FuzzyChoice(['m5.large', 'm5.xlarge', 'm5.2xlarge', 'c5.large'])
    State = factory.Dict({
        'Name': fuzzy.FuzzyChoice(['pending', 'running', 'stopping', 'stopped'])
    })
    PrivateIpAddress = factory.LazyFunction(
        lambda: f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
    )
    PublicIpAddress = factory.LazyFunction(
        lambda: f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    )


class VPCConfigFactory(factory.Factory):
    """Factory for generating VPC configuration data."""
    
    class Meta:
        model = dict
    
    VpcId = factory.Sequence(lambda n: f"vpc-{n:017x}")
    CidrBlock = "10.0.0.0/16"
    State = "available"


class SecurityGroupFactory(factory.Factory):
    """Factory for generating Security Group data."""
    
    class Meta:
        model = dict
    
    GroupId = factory.Sequence(lambda n: f"sg-{n:017x}")
    GroupName = factory.Sequence(lambda n: f"test-sg-{n}")
    Description = "Test security group"
    VpcId = factory.SubFactory(VPCConfigFactory)


class LoadBalancerFactory(factory.Factory):
    """Factory for generating Load Balancer data."""
    
    class Meta:
        model = dict
    
    LoadBalancerArn = factory.Sequence(
        lambda n: f"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/test-lb-{n}/{'0123456789abcdef'}"
    )
    DNSName = factory.Sequence(lambda n: f"test-lb-{n}.us-east-1.elb.amazonaws.com")
    State = factory.Dict({'Code': 'active'})
    Type = 'application'
    Scheme = 'internet-facing'


class AutoScalingGroupFactory(factory.Factory):
    """Factory for generating Auto Scaling Group data."""
    
    class Meta:
        model = dict
    
    AutoScalingGroupName = factory.Sequence(lambda n: f"test-asg-{n}")
    MinSize = 1
    MaxSize = 3
    DesiredCapacity = 2
    DefaultCooldown = 300
    HealthCheckType = 'EC2'
    HealthCheckGracePeriod = 300


# Utility functions for creating complex test scenarios

# TODO: change from Eth to Starknet
def create_complete_signing_scenario():
    """Create a complete signing scenario with all required components."""
    private_key = EthereumPrivateKeyFactory()
    transaction = TransactionPayloadFactory()
    credentials = AWSCredentialsFactory()
    
    return {
        'private_key': private_key,
        'transaction': transaction,
        'credentials': credentials,
        'enclave_payload': EnclavePayloadFactory(
            credential=credentials,
            transaction_payload=transaction
        )
    }


def create_lambda_test_scenario(operation='sign_transaction'):
    """Create a Lambda test scenario."""
    if operation == 'set_key':
        return SetKeyEventFactory()
    elif operation == 'get_key':
        return GetKeyEventFactory()
    elif operation == 'sign_transaction':
        return SignTransactionEventFactory()
    else:
        raise ValueError(f"Unknown operation: {operation}")


def create_aws_infrastructure_scenario():
    """Create AWS infrastructure test data."""
    return {
        'vpc': VPCConfigFactory(),
        'security_group': SecurityGroupFactory(),
        'instances': EC2InstanceFactory.create_batch(3),
        'load_balancer': LoadBalancerFactory(),
        'auto_scaling_group': AutoScalingGroupFactory()
    }


def create_error_scenarios():
    """Create various error scenarios for testing."""
    return {
        'invalid_private_key': '0xinvalid',
        'invalid_address': '0xinvalidaddress',
        'invalid_transaction': {
            'value': -1,  # Invalid negative value
            'to': 'invalid_address',
            'nonce': -1,
            'gas': 0
        },
        'malformed_credentials': {
            'access_key_id': '',
            'secret_access_key': None,
            'token': 123  # Should be string
        },
        'empty_payload': {},
        'missing_fields': {
            'credential': AWSCredentialsFactory(),
            # Missing transaction_payload and encrypted_key
        }
    }