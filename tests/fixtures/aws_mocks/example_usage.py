"""
Example usage of AWS service mocks for comprehensive testing.

This file demonstrates various patterns and use cases for the AWS service mocks,
showing how to test different scenarios including error conditions, performance,
and integration testing.
"""

import pytest
import base64
import json
import time
from typing import Dict, Any

# Import the AWS mocks
from . import (
    aws_test_environment,
    create_comprehensive_test_setup,
    quick_aws_test_setup,
    create_integrated_test_scenario,
    assert_starknet_key_format,
    assert_aws_arn_format,
    StarknetIntegrationHelper,
    TestScenarioBuilder
)


class TestAWSServiceMocks:
    """Example tests demonstrating AWS service mock usage."""
    
    def test_basic_kms_operations(self):
        """Test basic KMS operations with mocks."""
        # Quick setup for KMS only
        setup = quick_aws_test_setup(["kms"])
        kms = setup["kms"]
        
        # Create a key
        key_result = kms.create_key(description="Test encryption key")
        key_id = key_result["KeyMetadata"]["KeyId"]
        
        # Verify key ARN format
        key_arn = key_result["KeyMetadata"]["Arn"]
        assert_aws_arn_format(key_arn, "kms")
        
        # Test encryption/decryption
        plaintext = b"Hello, World!"
        encrypt_result = kms.encrypt(key_id, plaintext)
        
        assert "CiphertextBlob" in encrypt_result
        assert "KeyId" in encrypt_result
        
        # Decrypt the data
        decrypt_result = kms.decrypt(encrypt_result["CiphertextBlob"])
        assert decrypt_result["Plaintext"] == plaintext
        
        # Test with encryption context
        context = {"purpose": "test", "application": "starknet"}
        encrypt_with_context = kms.encrypt(key_id, plaintext, context)
        decrypt_with_context = kms.decrypt(encrypt_with_context["CiphertextBlob"], context)
        assert decrypt_with_context["Plaintext"] == plaintext
    
    def test_secrets_manager_operations(self):
        """Test Secrets Manager operations with mocks."""
        setup = quick_aws_test_setup(["secrets_manager"])
        secrets = setup["secrets_manager"]
        
        # Create a secret with JSON data
        secret_data = {
            "username": "testuser",
            "password": "testpass123",
            "database": "testdb"
        }
        
        create_result = secrets.create_secret(
            "test/database/credentials",
            secret_data,
            description="Test database credentials"
        )
        
        assert "ARN" in create_result
        assert "Name" in create_result
        assert_aws_arn_format(create_result["ARN"], "secretsmanager")
        
        # Retrieve the secret
        get_result = secrets.get_secret_value("test/database/credentials")
        retrieved_data = json.loads(get_result["SecretString"])
        
        assert retrieved_data == secret_data
        assert get_result["Name"] == "test/database/credentials"
        
        # Test secret versioning
        updated_data = secret_data.copy()
        updated_data["password"] = "newpassword456"
        
        put_result = secrets.put_secret_value("test/database/credentials", updated_data)
        assert "VersionId" in put_result
        
        # Get the updated version
        updated_result = secrets.get_secret_value("test/database/credentials")
        updated_retrieved = json.loads(updated_result["SecretString"])
        assert updated_retrieved["password"] == "newpassword456"
    
    def test_nitro_enclave_operations(self):
        """Test Nitro Enclave operations with mocks."""
        setup = quick_aws_test_setup(["nitro_enclave"])
        enclave = setup["nitro_enclave"]
        
        # Create an enclave
        enclave_config = enclave.create_enclave(
            "/app/test_enclave.eif",
            cpu_count=2,
            memory_mib=512,
            debug_mode=True
        )
        
        enclave_id = enclave_config["EnclaveID"]
        assert enclave_config["State"] == "RUNNING"
        assert enclave_config["CPUCount"] == 2
        assert enclave_config["MemoryMiB"] == 512
        
        # Generate attestation document
        user_data = b"test_attestation_data"
        attestation_doc = enclave.generate_attestation_document(enclave_id, user_data)
        
        assert isinstance(attestation_doc, bytes)
        assert len(attestation_doc) > 0
        
        # Verify attestation document
        verification_result = enclave.verify_attestation_document(attestation_doc)
        assert verification_result["valid"] is True
        assert "module_id" in verification_result
        assert "pcrs" in verification_result
        
        # Test VSOCK connection
        cid = enclave_config["EnclaveCID"]
        connection = enclave.create_vsock_connection(cid, 5000)
        connection.connect()
        
        test_message = b"Hello, enclave!"
        bytes_sent = connection.send(test_message)
        assert bytes_sent == len(test_message)
        
        connection.close()
    
    def test_integrated_scenario(self):
        """Test integrated scenario with all services working together."""
        with aws_test_environment() as env:
            kms = env.get_kms_service()
            secrets = env.get_secrets_manager_service()
            enclave = env.get_nitro_enclave_service()
            
            # Create master key for encryption
            master_key = kms.create_key(description="Master encryption key")
            master_key_id = master_key["KeyMetadata"]["KeyId"]
            
            # Create master seed
            master_seed = secrets.test_master_seed
            
            # Encrypt master seed with KMS
            encrypted_seed = kms.encrypt(master_key_id, master_seed)
            
            # Store encrypted seed in Secrets Manager
            secret_result = secrets.create_secret(
                "starknet/master-seed",
                encrypted_seed["CiphertextBlob"],
                description="Encrypted Starknet master seed"
            )
            
            # Simulate enclave retrieving and decrypting the seed
            retrieved_secret = secrets.get_secret_value("starknet/master-seed")
            ciphertext = retrieved_secret["SecretString"]
            
            # Decrypt using KMS
            decrypted_result = kms.decrypt(ciphertext)
            decrypted_seed = decrypted_result["Plaintext"]
            
            # Verify the round-trip worked
            assert decrypted_seed == master_seed
            
            # Test kmstool simulation
            credentials = env.create_test_credentials("test-user")
            kmstool_result = enclave.simulate_kmstool_call(
                "decrypt", 
                ciphertext, 
                credentials
            )
            
            assert kmstool_result["success"] is True
            assert kmstool_result["plaintext"] is not None
    
    def test_starknet_scenario_builder(self):
        """Test using the scenario builder for Starknet-specific testing."""
        env = create_integrated_test_scenario("starknet_multiuser")
        
        with env:
            builder = TestScenarioBuilder(env)
            scenario = (builder
                       .with_encrypted_master_seed()
                       .with_user_sessions(["alice", "bob", "charlie"])
                       .with_enclave_attestation()
                       .build())
            
            # Verify master seed setup
            assert "master_seed" in scenario
            assert "key_id" in scenario["master_seed"]
            assert "secret_name" in scenario["master_seed"]
            
            # Verify user sessions
            assert "users" in scenario
            assert len(scenario["users"]) == 3
            for user_id in ["alice", "bob", "charlie"]:
                assert user_id in scenario["users"]
                assert "key_id" in scenario["users"][user_id]
                assert "secret_name" in scenario["users"][user_id]
            
            # Verify attestation
            assert "attestation" in scenario
            assert "enclave_id" in scenario["attestation"]
            assert "document" in scenario["attestation"]
    
    def test_error_simulation(self):
        """Test error simulation capabilities."""
        setup = quick_aws_test_setup()
        kms = setup["kms"]
        secrets = setup["secrets_manager"]
        enclave = setup["nitro_enclave"]
        
        # Create test resources
        key = kms.create_key(description="Test key for errors")
        key_id = key["KeyMetadata"]["KeyId"]
        
        secret = secrets.create_secret("test/error-secret", "test-value")
        secret_name = secret["Name"]
        
        # Test KMS errors
        kms.simulate_error("access_denied", key_id)
        
        with pytest.raises(Exception):  # Should raise AccessDeniedError
            kms.encrypt(key_id, b"test data")
        
        # Test Secrets Manager errors
        secrets.simulate_error("access_denied", secret_name)
        
        with pytest.raises(Exception):  # Should raise AccessDeniedError
            secrets.get_secret_value(secret_name)
        
        # Test Enclave errors
        enclave_id = list(enclave.enclaves.keys())[0]
        enclave.simulate_error("enclave_crashed", enclave_id)
        
        # Verify enclave state changed
        enclave_info = enclave.describe_enclave(enclave_id)
        assert enclave_info["State"] == "CRASHED"
    
    def test_performance_patterns(self):
        """Test performance and load patterns."""
        setup = quick_aws_test_setup()
        kms = setup["kms"]
        
        # Create test key
        key = kms.create_key(description="Performance test key")
        key_id = key["KeyMetadata"]["KeyId"]
        
        # Test batch operations
        plaintexts = [f"test_data_{i}".encode() for i in range(10)]
        ciphertexts = []
        
        start_time = time.time()
        for plaintext in plaintexts:
            result = kms.encrypt(key_id, plaintext)
            ciphertexts.append(result["CiphertextBlob"])
        encrypt_time = time.time() - start_time
        
        # Decrypt all
        start_time = time.time()
        decrypted_data = []
        for ciphertext in ciphertexts:
            result = kms.decrypt(ciphertext)
            decrypted_data.append(result["Plaintext"])
        decrypt_time = time.time() - start_time
        
        # Verify all data is correct
        assert len(decrypted_data) == len(plaintexts)
        for original, decrypted in zip(plaintexts, decrypted_data):
            assert original == decrypted
        
        # Performance should be reasonable (adjust thresholds as needed)
        assert encrypt_time < 5.0  # Should complete in under 5 seconds
        assert decrypt_time < 5.0
    
    def test_realistic_starknet_workflow(self):
        """Test a realistic Starknet key derivation workflow."""
        with aws_test_environment() as env:
            # Setup Starknet integration helper
            starknet_helper = StarknetIntegrationHelper(env)
            starknet_helper.patch_aws_multiuser_integration()
            starknet_helper.patch_subprocess_kmstool()
            starknet_helper.start_patches()
            
            try:
                kms = env.get_kms_service()
                secrets = env.get_secrets_manager_service()
                
                # Create master seed encryption key
                master_key = kms.create_key(description="Starknet master seed key")
                master_key_id = master_key["KeyMetadata"]["KeyId"]
                
                # Create and encrypt master seed
                master_seed = secrets.test_master_seed
                encrypted_seed = kms.encrypt(master_key_id, master_seed)
                
                # Store in secrets manager
                secrets.create_secret(
                    "starknet/encrypted-master-seed",
                    encrypted_seed["CiphertextBlob"]
                )
                
                # Simulate user key derivation
                user_credentials = env.create_test_credentials("starknet-user")
                
                # This would normally call the actual key derivation functions
                # but our mocks will handle the KMS decryption
                retrieved_secret = secrets.get_secret_value("starknet/encrypted-master-seed")
                decrypted_seed = kms.decrypt(retrieved_secret["SecretString"])
                
                # Verify we got back the original master seed
                assert decrypted_seed["Plaintext"] == master_seed
                
                # The decrypted seed would be used for Starknet key derivation
                assert_starknet_key_format(decrypted_seed["Plaintext"])
                
            finally:
                starknet_helper.stop_patches()


# Additional example for pytest fixtures usage
@pytest.fixture
def starknet_test_environment():
    """Example pytest fixture using the AWS mocks."""
    with aws_test_environment() as env:
        # Set up Starknet-specific test data
        builder = TestScenarioBuilder(env)
        scenario = (builder
                   .with_encrypted_master_seed()
                   .with_user_sessions(["test-user"])
                   .build())
        
        yield {
            "env": env,
            "scenario": scenario,
            "kms": env.get_kms_service(),
            "secrets": env.get_secrets_manager_service(),
            "enclave": env.get_nitro_enclave_service()
        }


def test_with_fixture(starknet_test_environment):
    """Example test using the custom fixture."""
    test_env = starknet_test_environment
    kms = test_env["kms"]
    scenario = test_env["scenario"]
    
    # Use the pre-configured scenario
    master_seed_info = scenario["master_seed"]
    key_id = master_seed_info["key_id"]
    
    # Test key operations
    test_data = b"test_encryption_data"
    encrypted = kms.encrypt(key_id, test_data)
    decrypted = kms.decrypt(encrypted["CiphertextBlob"])
    
    assert decrypted["Plaintext"] == test_data


if __name__ == "__main__":
    # Example of running tests programmatically
    test_instance = TestAWSServiceMocks()
    
    print("Running AWS service mock examples...")
    
    try:
        print("✓ Testing basic KMS operations...")
        test_instance.test_basic_kms_operations()
        
        print("✓ Testing Secrets Manager operations...")
        test_instance.test_secrets_manager_operations()
        
        print("✓ Testing Nitro Enclave operations...")
        test_instance.test_nitro_enclave_operations()
        
        print("✓ Testing integrated scenario...")
        test_instance.test_integrated_scenario()
        
        print("✓ Testing Starknet scenario builder...")
        test_instance.test_starknet_scenario_builder()
        
        print("✓ Testing error simulation...")
        test_instance.test_error_simulation()
        
        print("✓ Testing performance patterns...")
        test_instance.test_performance_patterns()
        
        print("✓ Testing realistic Starknet workflow...")
        test_instance.test_realistic_starknet_workflow()
        
        print("\n🎉 All AWS service mock examples passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        raise