#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0
import aws_cdk
from aws_cdk import (
    Stack,
    Fn,
    Duration,
    CfnOutput,
    aws_ec2,
    aws_iam,
    aws_ecr_assets,
    aws_secretsmanager,
    aws_lambda,
    aws_autoscaling,
    aws_elasticloadbalancingv2,
    aws_kms,
)
from cdk_nag import NagSuppressions, NagPackSuppression
from constructs import Construct


class NitroWalletStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        params = kwargs.pop("params")
        super().__init__(scope, construct_id, **kwargs)

        # Force application type to starknet since we've removed other applications
        application_type = "starknet"

        # Master seed secret for multi-user key derivation
        master_seed_secret = aws_secretsmanager.Secret(
            self, 
            "MasterSeedSecret",
            description="Master seed for Starknet multi-user key derivation"
        )

        # Legacy encrypted key secret for backward compatibility
        encrypted_key = aws_secretsmanager.Secret(self, "SecretsManager")

        # Key to encrypt master seed and stored private keys
        encryption_key = aws_kms.Key(self, "EncryptionKey", enable_key_rotation=True)
        encryption_key.apply_removal_policy(aws_cdk.RemovalPolicy.DESTROY)

        signing_server_image = aws_ecr_assets.DockerImageAsset(
            self,
            "StarknetSigningServerImage",
            directory="./application/starknet/server",
            platform=aws_ecr_assets.Platform.LINUX_AMD64,
            build_args={"REGION_ARG": self.region},
        )

        signing_enclave_image = aws_ecr_assets.DockerImageAsset(
            self,
            "StarknetSigningEnclaveImage",
            directory="./application/starknet/enclave",
            platform=aws_ecr_assets.Platform.LINUX_AMD64,
            build_args={"REGION_ARG": self.region},
        )

        vpc = aws_ec2.Vpc(
            self,
            "VPC",
            nat_gateways=1,
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="public", subnet_type=aws_ec2.SubnetType.PUBLIC
                ),
                aws_ec2.SubnetConfiguration(
                    name="private", subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
            ],
            enable_dns_support=True,
            enable_dns_hostnames=True,
        )

        aws_ec2.InterfaceVpcEndpoint(
            self,
            "KMSEndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.KMS,
            private_dns_enabled=True,
        )
        aws_ec2.InterfaceVpcEndpoint(
            self,
            "SecretsManagerEndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            private_dns_enabled=True,
        )

        aws_ec2.InterfaceVpcEndpoint(
            self,
            "SSMEndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.SSM,
            private_dns_enabled=True,
        )

        aws_ec2.InterfaceVpcEndpoint(
            self,
            "ECREndpoint",
            vpc=vpc,
            subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR,
            private_dns_enabled=True,
        )

        nitro_instance_sg = aws_ec2.SecurityGroup(
            self,
            "Nitro",
            vpc=vpc,
            allow_all_outbound=True,
            description="Private SG for NitroWallet EC2 instance",
        )

        # external members (nlb) can run a health check on the EC2 instance 443 port
        nitro_instance_sg.add_ingress_rule(
            aws_ec2.Peer.ipv4(vpc.vpc_cidr_block), aws_ec2.Port.tcp(443)
        )

        # all members of the sg can access each others https ports (443)
        nitro_instance_sg.add_ingress_rule(nitro_instance_sg, aws_ec2.Port.tcp(443))

        # AMI
        amzn_linux = aws_ec2.MachineImage.latest_amazon_linux2()

        # Instance Role and SSM Managed Policy
        role = aws_iam.Role(
            self,
            "InstanceSSM",
            assumed_by=aws_iam.ServicePrincipal("ec2.amazonaws.com"),
        )
        role.add_managed_policy(
            aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AmazonEC2RoleforSSM"
            )
        )

        block_device = aws_ec2.BlockDevice(
            device_name="/dev/xvda",
            volume=aws_ec2.BlockDeviceVolume(
                ebs_device=aws_ec2.EbsDeviceProps(
                    volume_size=32,
                    volume_type=aws_ec2.EbsDeviceVolumeType.GP2,
                    encrypted=True,
                    delete_on_termination=True
                    if params.get("deployment") == "dev"
                    else False,
                )
            ),
        )

        mappings = {
            "__DEV_MODE__": params["deployment"],
            "__SIGNING_SERVER_IMAGE_URI__": signing_server_image.image_uri,
            "__SIGNING_ENCLAVE_IMAGE_URI__": signing_enclave_image.image_uri,
            "__REGION__": self.region,
        }

        with open("./application/starknet/user_data/user_data.sh") as f:
            user_data_raw = Fn.sub(f.read(), mappings)

        signing_enclave_image.repository.grant_pull(role)
        signing_server_image.repository.grant_pull(role)
        encrypted_key.grant_read(role)
        master_seed_secret.grant_read(role)

        nitro_launch_template = aws_ec2.LaunchTemplate(
            self,
            "NitroEC2LauchTemplate",
            instance_type=aws_ec2.InstanceType("m6i.xlarge"),
            user_data=aws_ec2.UserData.custom(user_data_raw),
            nitro_enclave_enabled=True,
            machine_image=amzn_linux,
            block_devices=[block_device],
            role=role,
            security_group=nitro_instance_sg,
            http_put_response_hop_limit=3
        )

        nitro_nlb = aws_elasticloadbalancingv2.NetworkLoadBalancer(
            self,
            "NitroEC2NetworkLoadBalancer",
            internet_facing=False,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
        )

        nitro_asg = aws_autoscaling.AutoScalingGroup(
            self,
            "NitroEC2AutoScalingGroup",
            max_capacity=2,
            min_capacity=2,
            launch_template=nitro_launch_template,
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            update_policy=aws_autoscaling.UpdatePolicy.rolling_update(),
        )

        nitro_nlb.add_listener(
            "HTTPSListener",
            port=443,
            protocol=aws_elasticloadbalancingv2.Protocol.TCP,
            default_target_groups=[
                aws_elasticloadbalancingv2.NetworkTargetGroup(
                    self,
                    "NitroEC2AutoScalingGroupTarget",
                    targets=[nitro_asg],
                    protocol=aws_elasticloadbalancingv2.Protocol.TCP,
                    port=443,
                    vpc=vpc,
                )
            ],
        )

        invoke_lambda = aws_lambda.Function(
            self,
            "StarknetInvokeLambda",
            code=aws_lambda.Code.from_asset(
                path="application/starknet/lambda"
            ),
            handler="lambda_function.lambda_handler",
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            timeout=Duration.minutes(2),
            memory_size=256,
            environment={
                "LOG_LEVEL": "DEBUG",
                "NITRO_INSTANCE_PRIVATE_DNS": nitro_nlb.load_balancer_dns_name,
                "SECRET_ARN": encrypted_key.secret_full_arn,
                "MASTER_SEED_SECRET_ID": master_seed_secret.secret_full_arn,
                "KEY_ARN": encryption_key.key_arn,
            },
            vpc=vpc,
            vpc_subnets=aws_ec2.SubnetSelection(
                subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[nitro_instance_sg],
        )

        encrypted_key.grant_write(invoke_lambda)
        master_seed_secret.grant_write(invoke_lambda)
        encryption_key.grant_encrypt(invoke_lambda)
        
        # if dev case, lambda is allowed to read secrets for testing
        if params.get("deployment") == "dev":
            encrypted_key.grant_read(invoke_lambda)
            master_seed_secret.grant_read(invoke_lambda)

        CfnOutput(
            self,
            "EC2 Instance Role ARN",
            value=role.role_arn,
            description="EC2 Instance Role ARN",
        )

        CfnOutput(
            self,
            "Lambda Execution Role ARN",
            value=invoke_lambda.role.role_arn,
            description="Lambda Execution Role ARN",
        )

        CfnOutput(
            self,
            "ASG Group Name",
            value=nitro_asg.auto_scaling_group_name,
            description="ASG Group Name",
        )

        CfnOutput(
            self, "KMS Key ID", value=encryption_key.key_id, description="KMS Key ID"
        )

        CfnOutput(
            self,
            "Master Seed Secret ARN",
            value=master_seed_secret.secret_full_arn,
            description="Master Seed Secret ARN for multi-user key derivation",
        )

        NagSuppressions.add_resource_suppressions(
            construct=self,
            suppressions=[
                NagPackSuppression(
                    id="AwsSolutions-VPC7",
                    reason="No VPC Flow Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-ELB2",
                    reason="No ELB Access Log required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM5",
                    reason="Permission to read CF stack is restrictive enough",
                ),
                NagPackSuppression(
                    id="AwsSolutions-IAM4",
                    reason="AmazonSSMManagedInstanceCore is a restrictive role",
                ),
                NagPackSuppression(
                    id="AwsSolutions-AS3",
                    reason="No Auto Scaling Group notifications required for PoC-grade deployment",
                ),
                NagPackSuppression(
                    id="AwsSolutions-EC23",
                    reason="Intrinsic functions referenced for cleaner private link creation",
                ),
                NagPackSuppression(
                    id="AwsSolutions-SMG4",
                    reason="Private key cannot be rotated",
                ),
            ],
            apply_to_children=True,
        )
