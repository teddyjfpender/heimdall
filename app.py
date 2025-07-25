#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import os
from aws_cdk import App, Environment, Aspects

from nitro_wallet.nitro_wallet_stack import NitroWalletStack
import cdk_nag

prefix = os.getenv("CDK_PREFIX", "dev")
# Default to starknet since we've removed other application types
application_type = os.getenv("CDK_APPLICATION_TYPE", "starknet")

app = App()

# Only Starknet application is supported now
NitroWalletStack(
    app,
    f"{prefix}NitroWalletStarknet",
    params={"deployment": "dev", "application_type": "starknet"},
    env=Environment(
        region=os.environ.get("CDK_DEPLOY_REGION"),
        account=os.environ.get("CDK_DEPLOY_ACCOUNT")
    ),
)

Aspects.of(app).add(cdk_nag.AwsSolutionsChecks())
app.synth()
