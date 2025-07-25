#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import logging
import os
import ssl
from http import client

import boto3

ssl_context = ssl.SSLContext()
ssl_context.verify_mode = ssl.CERT_NONE


LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger("starknet_tx_manager_controller")
_logger.setLevel(LOG_LEVEL)
_logger.addHandler(handler)
_logger.propagate = False

# Initialize clients lazily to avoid region errors during import
def get_kms_client():
    return boto3.client("kms")

def get_secrets_client():
    return boto3.client("secretsmanager")

# For backward compatibility with existing code
client_kms = None
client_secrets_manager = None

try:
    client_kms = get_kms_client()
    client_secrets_manager = get_secrets_client()
except Exception:
    # Will be initialized when first used
    pass


def lambda_handler(event, context):
    """
    Starknet transaction handler
    
    Example requests:
    {
      "operation": "set_key",
      "starknet_key": "0x123abc..."
    }

    {
      "operation": "get_key"
    }

    {
      "operation": "sign_transaction",
      "transaction_payload": {
        "contract_address": "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        "function_name": "transfer",
        "calldata": ["0x123...", "1000", "0"],
        "max_fee": "0x1000000000000",
        "nonce": 0,
        "chain_id": "testnet",
        "rpc_url": "https://starknet-testnet.public.blastapi.io"
      }
    }

    """
    nitro_instance_private_dns = os.getenv("NITRO_INSTANCE_PRIVATE_DNS")
    secret_id = os.getenv("SECRET_ARN")
    key_id = os.getenv("KEY_ARN")

    if not (nitro_instance_private_dns and secret_id and key_id):
        _logger.fatal(
            "NITRO_INSTANCE_PRIVATE_DNS, SECRET_ARN and KEY_ARN environment variables need to be set"
        )
        return None

    operation = event.get("operation")
    if not operation:
        _logger.fatal("request needs to define operation")
        return None

    if operation == "set_key":
        key_plaintext = event.get("starknet_key")
        
        # Validate Starknet private key format
        if not key_plaintext:
            raise Exception("starknet_key is required for set_key operation")
        
        # Ensure key starts with 0x and is valid hex
        if not key_plaintext.startswith("0x"):
            key_plaintext = "0x" + key_plaintext
        
        try:
            # Validate it's a valid hex string for Starknet private key
            key_int = int(key_plaintext, 16)
            
            # Validate it's within the STARK curve order (must be in range [1, STARK_ORDER-1])
            STARK_ORDER = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
            if not (1 <= key_int < STARK_ORDER):
                raise Exception("Invalid Starknet private key format. Key must be within STARK curve order.")
        except ValueError:
            raise Exception("Invalid Starknet private key format. Must be a valid hexadecimal string.")

        try:
            kms_client = client_kms or get_kms_client()
            response = kms_client.encrypt(
                KeyId=key_id, Plaintext=key_plaintext.encode()
            )
        except Exception as e:
            raise Exception(
                "exception happened sending encryption request to KMS: {}".format(e)
            )

        _logger.debug("response: {}".format(response))
        response_b64 = base64.standard_b64encode(response["CiphertextBlob"]).decode()

        try:
            secrets_client = client_secrets_manager or get_secrets_client()
            response = secrets_client.update_secret(
                SecretId=secret_id,
                # rely on the AWS managed key for std. storage
                SecretString=response_b64,
            )
        except Exception as e:
            raise Exception("exception happened updating secret: {}".format(e))

        return response

    elif operation == "get_key":
        try:
            secrets_client = client_secrets_manager or get_secrets_client()
            response = secrets_client.get_secret_value(SecretId=secret_id)
        except Exception as e:
            raise Exception(
                "exception happened reading secret from secrets manager: {}".format(e)
            )

        return response["SecretString"]

    # sign_transaction

    elif operation == "sign_transaction":
        transaction_payload = event.get("transaction_payload")

        if not transaction_payload:
            raise Exception(
                "sign_transaction requires transaction_payload"
            )

        # Validate required Starknet transaction parameters
        required_fields = ["contract_address", "function_name"]
        for field in required_fields:
            if field not in transaction_payload:
                raise Exception(f"Missing required field: {field}")

        # Set defaults for optional parameters
        if "calldata" not in transaction_payload:
            transaction_payload["calldata"] = []
        if "max_fee" not in transaction_payload:
            transaction_payload["max_fee"] = "0x1000000000000"  # Default max fee
        if "nonce" not in transaction_payload:
            transaction_payload["nonce"] = 0
        if "chain_id" not in transaction_payload:
            transaction_payload["chain_id"] = "testnet"
        if "rpc_url" not in transaction_payload:
            transaction_payload["rpc_url"] = "https://starknet-testnet.public.blastapi.io"

        # Validate contract address format
        contract_address = transaction_payload["contract_address"]
        if not contract_address.startswith("0x"):
            transaction_payload["contract_address"] = "0x" + contract_address

        try:
            int(transaction_payload["contract_address"], 16)
        except ValueError:
            raise Exception("Invalid contract_address format. Must be a valid hexadecimal string.")

        https_nitro_client = client.HTTPSConnection(
            "{}:{}".format(nitro_instance_private_dns, 443), context=ssl_context
        )

        try:
            https_nitro_client.request(
                "POST",
                "/",
                body=json.dumps(
                    {"transaction_payload": transaction_payload, "secret_id": secret_id}
                ),
            )
            response = https_nitro_client.getresponse()
        except Exception as e:
            raise Exception(
                "exception happened sending signing request to Nitro Enclave: {}".format(
                    e
                )
            )

        _logger.debug("response: {} {}".format(response.status, response.reason))

        response_raw = response.read()

        _logger.debug("response data: {}".format(response_raw))
        response_parsed = json.loads(response_raw)

        return response_parsed

    else:
        _logger.fatal("operation: {} not supported right now".format(operation))
        return None