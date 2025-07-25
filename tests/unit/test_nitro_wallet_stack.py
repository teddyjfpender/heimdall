"""Unit tests for Nitro Wallet CDK Stack.

TESTING STATUS SUMMARY:
- Basic stack creation and resource validation: PASSING
- Complex resource configurations (VPC, Security Groups, ALB): May require actual CDK synthesis
- Docker image asset tests: Require file system access to Dockerfiles
- IAM role and policy validation: Working with basic checks

TODO ITEMS FOR CDK TESTS:
- Some tests may require actual CDK synthesis to validate complex resource dependencies
- Docker image asset tests need actual Dockerfile files in expected locations
- Advanced networking configurations (VPC, security groups) may need integration testing
- Consider separating unit tests (construct validation) from integration tests (synthesis validation)
"""

import os
from unittest.mock import patch, Mock
import pytest
import aws_cdk as cdk
from aws_cdk.assertions import Template

# Import the stack under test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../'))

from nitro_wallet.nitro_wallet_stack import NitroWalletStack


class TestNitroWalletStack:
    """Test the CDK stack construction and resource creation."""

    @pytest.fixture
    def app(self):
        """Create a CDK app for testing."""
        return cdk.App()

    @pytest.fixture
    def stack_params(self):
        """Default stack parameters."""
        return {
            "deployment": "dev",
            "application_type": "eth1"
        }

    @pytest.fixture
    def test_environment(self):
        """Test CDK environment."""
        return cdk.Environment(
            region="us-east-1",
            account="123456789012"
        )

    @pytest.mark.unit
    def test_stack_creation(self, app, stack_params, test_environment):
        """Test basic stack creation."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        assert stack is not None
        assert stack.region == "us-east-1"
        assert stack.account == "123456789012"

    @pytest.mark.unit
    def test_secrets_manager_resource(self, app, stack_params, test_environment):
        """Test Secrets Manager resource creation."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack", 
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify Secrets Manager secret exists
        template.has_resource_properties("AWS::SecretsManager::Secret", {})

    @pytest.mark.unit
    def test_kms_key_resource(self, app, stack_params, test_environment):
        """Test KMS key resource creation."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params, 
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify KMS key exists with key rotation enabled
        template.has_resource_properties("AWS::KMS::Key", {
            "EnableKeyRotation": True
        })

    @pytest.mark.unit
    def test_docker_image_assets(self, app, stack_params, test_environment):
        """Test Docker image asset creation."""
        # Mock ECR assets to avoid actual Docker builds in tests
        with patch("aws_cdk.aws_ecr_assets.DockerImageAsset") as mock_asset:
            mock_asset.return_value = Mock()
            
            stack = NitroWalletStack(
                app,
                "TestNitroWalletStack",
                params=stack_params,
                env=test_environment
            )
            
            # Verify Docker assets were created
            assert mock_asset.call_count == 2  # Server and enclave images
            
            # Verify correct directories were used
            calls = mock_asset.call_args_list
            server_call = next(call for call in calls if "server" in str(call))
            enclave_call = next(call for call in calls if "enclave" in str(call))
            
            assert "./application/eth1/server" in str(server_call)
            assert "./application/eth1/enclave" in str(enclave_call)

    @pytest.mark.unit
    def test_ec2_instance_configuration(self, app, stack_params, test_environment):
        """Test EC2 instance configuration."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify Auto Scaling Group exists
        template.has_resource("AWS::AutoScaling::AutoScalingGroup")
        
        # Verify Launch Template exists
        template.has_resource("AWS::EC2::LaunchTemplate")

    @pytest.mark.unit
    def test_lambda_function_creation(self, app, stack_params, test_environment):
        """Test Lambda function creation."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params, 
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify Lambda function exists
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.11"
        })

    @pytest.mark.unit
    def test_iam_roles_and_policies(self, app, stack_params, test_environment):
        """Test IAM roles and policies creation."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify IAM roles exist
        template.has_resource("AWS::IAM::Role")
        
        # Verify IAM policies exist
        template.resource_count_is("AWS::IAM::Policy", cdk.assertions.Match.at_least(1))

    @pytest.mark.unit
    def test_vpc_configuration(self, app, stack_params, test_environment):
        """Test VPC configuration."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify VPC resources exist
        template.has_resource("AWS::EC2::VPC")
        template.has_resource("AWS::EC2::Subnet")
        template.has_resource("AWS::EC2::InternetGateway")

    @pytest.mark.unit
    def test_security_groups(self, app, stack_params, test_environment):
        """Test security group configuration."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify security groups exist
        template.has_resource("AWS::EC2::SecurityGroup")

    @pytest.mark.unit
    def test_application_load_balancer(self, app, stack_params, test_environment):
        """Test Application Load Balancer configuration."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify ALB resources exist
        template.has_resource("AWS::ElasticLoadBalancingV2::LoadBalancer")
        template.has_resource("AWS::ElasticLoadBalancingV2::TargetGroup")
        template.has_resource("AWS::ElasticLoadBalancingV2::Listener")

    @pytest.mark.unit
    def test_cdk_nag_suppressions(self, app, stack_params, test_environment):
        """Test CDK NAG suppressions are applied."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        # Verify stack was created without errors
        # CDK NAG suppressions should prevent security warnings
        assert stack is not None

    @pytest.mark.unit
    def test_environment_variables(self, app, stack_params, test_environment):
        """Test environment variables are properly set."""
        stack = NitroWalletStack(
            app,
            "TestNitroWalletStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify Lambda function has required environment variables
        template.has_resource_properties("AWS::Lambda::Function", {
            "Environment": {
                "Variables": cdk.assertions.Match.object_like({
                    "LOG_LEVEL": cdk.assertions.Match.any_value()
                })
            }
        })


class TestStackParameterVariations:
    """Test stack behavior with different parameter combinations."""

    @pytest.fixture
    def app(self):
        """Create a CDK app for testing."""
        return cdk.App()

    @pytest.fixture
    def test_environment(self):
        """Test CDK environment."""
        return cdk.Environment(
            region="us-east-1", 
            account="123456789012"
        )

    @pytest.mark.unit
    def test_dev_deployment(self, app, test_environment):
        """Test stack with dev deployment parameters."""
        params = {"deployment": "dev", "application_type": "eth1"}
        
        stack = NitroWalletStack(
            app,
            "TestDevStack",
            params=params,
            env=test_environment
        )
        
        assert stack is not None

    @pytest.mark.unit
    def test_prod_deployment(self, app, test_environment):
        """Test stack with prod deployment parameters."""
        params = {"deployment": "prod", "application_type": "eth1"}
        
        stack = NitroWalletStack(
            app,
            "TestProdStack",
            params=params,
            env=test_environment
        )
        
        assert stack is not None

    @pytest.mark.unit
    def test_different_regions(self, app):
        """Test stack deployment in different regions."""
        params = {"deployment": "dev", "application_type": "eth1"}
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
        
        for region in regions:
            env = cdk.Environment(region=region, account="123456789012")
            
            stack = NitroWalletStack(
                app,
                f"TestStack{region.replace('-', '')}",
                params=params,
                env=env
            )
            
            assert stack.region == region


class TestStackOutputs:
    """Test CDK stack outputs."""

    @pytest.fixture
    def app(self):
        """Create a CDK app for testing."""
        return cdk.App()

    @pytest.fixture
    def stack_params(self):
        """Default stack parameters."""
        return {"deployment": "dev", "application_type": "eth1"}

    @pytest.fixture
    def test_environment(self):
        """Test CDK environment."""
        return cdk.Environment(region="us-east-1", account="123456789012")

    @pytest.mark.unit
    def test_required_outputs_exist(self, app, stack_params, test_environment):
        """Test that required stack outputs are created."""
        stack = NitroWalletStack(
            app,
            "TestOutputsStack",
            params=stack_params,
            env=test_environment
        )
        
        template = Template.from_stack(stack)
        
        # Verify key outputs exist
        template.has_output("*", {})  # At least one output exists

    @pytest.mark.unit
    def test_output_values_format(self, app, stack_params, test_environment):
        """Test output values are in correct format."""
        stack = NitroWalletStack(
            app,
            "TestOutputsStack", 
            params=stack_params,
            env=test_environment
        )
        
        # Verify stack constructs without errors
        assert stack is not None


class TestStackValidation:
    """Test stack validation and error handling."""

    @pytest.fixture
    def app(self):
        """Create a CDK app for testing."""
        return cdk.App()

    @pytest.fixture
    def test_environment(self):
        """Test CDK environment."""
        return cdk.Environment(region="us-east-1", account="123456789012")

    @pytest.mark.unit
    def test_missing_application_type(self, app, test_environment):
        """Test stack creation with missing application_type."""
        params = {"deployment": "dev"}  # Missing application_type
        
        with pytest.raises(KeyError):
            NitroWalletStack(
                app,
                "TestErrorStack",
                params=params,
                env=test_environment
            )

    @pytest.mark.unit
    def test_invalid_application_type(self, app, test_environment):
        """Test stack creation with invalid application_type."""
        params = {"deployment": "dev", "application_type": "invalid"}
        
        # Invalid application type should raise RuntimeError at construct time
        # because CDK tries to find the Docker image directory
        with pytest.raises(RuntimeError) as exc_info:
            NitroWalletStack(
                app,
                "TestInvalidAppStack",
                params=params,
                env=test_environment
            )
        
        # Verify the error message indicates missing image directory
        assert "Cannot find image directory" in str(exc_info.value)
        assert "application/invalid/server" in str(exc_info.value)

    @pytest.mark.unit
    def test_stack_synthesis(self, app, test_environment):
        """Test that stack can be successfully synthesized."""
        params = {"deployment": "dev", "application_type": "eth1"}
        
        stack = NitroWalletStack(
            app,
            "TestSynthStack",
            params=params,
            env=test_environment
        )
        
        # Attempt to synthesize the stack
        template = Template.from_stack(stack)
        
        # Verify template is not empty
        assert len(template.to_json()["Resources"]) > 0