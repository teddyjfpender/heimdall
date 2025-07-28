"""
AWS service mocks for local testing.

This package provides comprehensive mocks for AWS services to enable
local testing without actual AWS dependencies.
"""

# Core service mocks
from .kms_mock import MockKMSService, create_kms_mock
from .secrets_manager_mock import MockSecretsManagerService, create_secrets_manager_mock
from .nitro_enclave_mock import MockNitroEnclaveService, create_nitro_enclave_mock

# Test environment and fixtures
from .test_environment import TestEnvironmentManager, aws_test_environment, create_integrated_test_scenario
from .test_fixtures import AWSMockFixtures

# Integration helpers
from .integration_helpers import (
    StarknetIntegrationHelper,
    UniversalAWSMockPatcher,
    TestScenarioBuilder,
    create_comprehensive_test_setup,
    quick_aws_test_setup,
    assert_starknet_key_format,
    assert_aws_arn_format,
    patch_application_imports
)

__all__ = [
    # Core service mocks
    'MockKMSService',
    'MockSecretsManagerService', 
    'MockNitroEnclaveService',
    'create_kms_mock',
    'create_secrets_manager_mock',
    'create_nitro_enclave_mock',
    
    # Test environment and fixtures
    'TestEnvironmentManager',
    'AWSMockFixtures',
    'aws_test_environment',
    'create_integrated_test_scenario',
    
    # Integration helpers
    'StarknetIntegrationHelper',
    'UniversalAWSMockPatcher', 
    'TestScenarioBuilder',
    'create_comprehensive_test_setup',
    'quick_aws_test_setup',
    'assert_starknet_key_format',
    'assert_aws_arn_format',
    'patch_application_imports'
]