#!/usr/bin/env python3
"""
Multi-user Starknet signing server for AWS Nitro Enclaves.

This server extends the original single-user server to support multiple users
with deterministic key derivation from a master seed stored in AWS KMS.
"""

import base64
import json
import os
import socket
import subprocess
import time
from typing import Dict, Any, Optional

from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.account.account import Account
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.signer.stark_curve_signer import StarkCurveSigner

# Import our multi-user key derivation system
from aws_multiuser_integration import (
    StarknetMultiUserAWSManager,
    AWSIntegrationError,
    KMSDecryptionError,
    MasterSeedError,
    UserSessionError,
    log_user_key_access,
    validate_enclave_environment,
    performance_monitor,
    extract_user_context_from_request
)


def kms_call(credential: Dict[str, str], ciphertext: str) -> str:
    """
    Call KMS to decrypt ciphertext - maintains compatibility with original implementation.
    
    Args:
        credential: AWS credentials
        ciphertext: Encrypted data
        
    Returns:
        str: Base64 encoded plaintext
    """
    aws_access_key_id = credential["access_key_id"]
    aws_secret_access_key = credential["secret_access_key"]
    aws_session_token = credential["token"]

    subprocess_args = [
        "/app/kmstool_enclave_cli",
        "decrypt",
        "--region",
        os.getenv("REGION"),
        "--proxy-port",
        "8000",
        "--aws-access-key-id",
        aws_access_key_id,
        "--aws-secret-access-key",
        aws_secret_access_key,
        "--aws-session-token",
        aws_session_token,
        "--ciphertext",
        ciphertext,
    ]

    print("subprocess args: {}".format(subprocess_args))

    proc = subprocess.Popen(subprocess_args, stdout=subprocess.PIPE)

    # returns b64 encoded plaintext
    result_b64 = proc.communicate()[0].decode()
    plaintext_b64 = result_b64.split(":")[1].strip()

    return plaintext_b64


def process_single_user_request(payload_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a single-user request (backward compatibility).
    
    Args:
        payload_json: Request payload
        
    Returns:
        Dict[str, Any]: Response data
    """
    credential = payload_json["credential"]
    transaction_dict = payload_json["transaction_payload"]
    key_encrypted = payload_json["encrypted_key"]

    response_plaintext = None
    key_plaintext = None

    try:
        key_b64 = kms_call(credential, key_encrypted)
    except Exception as e:
        msg = "exception happened calling kms binary: {}".format(e)
        print(msg)
        return {"error": msg, "success": False}

    try:
        key_plaintext = base64.standard_b64decode(key_b64).decode()

        # Validate private key format
        if not key_plaintext.startswith("0x"):
            key_plaintext = "0x" + key_plaintext
        private_key_int = int(key_plaintext, 16)

        # Parse Starknet transaction parameters
        contract_address = transaction_dict["contract_address"]
        if not contract_address.startswith("0x"):
            contract_address = "0x" + contract_address
        contract_address_int = int(contract_address, 16)
        
        function_name = transaction_dict["function_name"]
        calldata = transaction_dict.get("calldata", [])
        
        # Handle max_fee - can be string or int
        max_fee = transaction_dict.get("max_fee", "0x1000000000000")
        if isinstance(max_fee, str):
            max_fee = int(max_fee, 16) if max_fee.startswith("0x") else int(max_fee)
        
        nonce = transaction_dict.get("nonce", 0)
        chain_id = transaction_dict.get("chain_id", StarknetChainId.TESTNET)
        
        # Convert string chain_id to StarknetChainId enum if needed  
        if isinstance(chain_id, str):
            chain_id_map = {
                "mainnet": StarknetChainId.MAINNET,
                "testnet": StarknetChainId.TESTNET,
                "testnet2": StarknetChainId.TESTNET2
            }
            chain_id = chain_id_map.get(chain_id.lower(), StarknetChainId.TESTNET)

        # Create signer from private key
        signer = StarkCurveSigner(
            account_address=contract_address_int,
            key_pair=private_key_int,
            chain_id=chain_id
        )

        # Create the call object
        call = Call(
            to_addr=contract_address_int,
            selector=get_selector_from_name(function_name),
            calldata=calldata
        )

        # Create client (using provided RPC endpoint or default)
        rpc_url = transaction_dict.get("rpc_url", "https://starknet-testnet.public.blastapi.io")
        client = FullNodeClient(node_url=rpc_url)

        # Create account
        account = Account(
            address=contract_address_int,
            client=client,
            signer=signer,
            chain=chain_id
        )

        # Sign the transaction
        signed_transaction = account.sign_invoke_transaction(
            calls=[call],
            max_fee=max_fee,
            nonce=nonce
        )

        response_plaintext = {
            "transaction_signed": hex(signed_transaction.signature[0]) + "," + hex(signed_transaction.signature[1]),
            "transaction_hash": hex(signed_transaction.transaction_hash),
            "contract_address": hex(contract_address_int),
            "function_name": function_name,
            "calldata": calldata,
            "max_fee": hex(max_fee),
            "nonce": nonce,
            "success": True
        }

    except Exception as e:
        msg = "exception happened signing the Starknet transaction: {}".format(e)
        print(msg)
        response_plaintext = {"error": msg, "success": False}

    finally:
        # Secure memory cleanup - overwrite sensitive data
        if key_plaintext:
            # Overwrite the key in memory before deletion
            key_plaintext = "0" * len(key_plaintext)
            del key_plaintext
        if 'private_key_int' in locals():
            private_key_int = 0
            del private_key_int

    return response_plaintext


def process_multiuser_request(payload_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a multi-user request with key derivation.
    
    Args:
        payload_json: Request payload with user context
        
    Returns:
        Dict[str, Any]: Response data
    """
    start_time = time.time()
    
    try:
        # Extract user context
        username, key_index, session_data = extract_user_context_from_request(payload_json)
        
        # Log access attempt
        log_user_key_access(username, key_index, "transaction_signing", False)
        
        # Get credentials and master seed
        credential = payload_json["credential"]
        encrypted_master_seed = payload_json["encrypted_master_seed"]
        transaction_dict = payload_json["transaction_payload"]
        
        # Initialize multi-user manager
        manager = StarknetMultiUserAWSManager()
        
        # Load master seed
        manager.load_master_seed(credential, encrypted_master_seed)
        
        # Process the user transaction request
        user_response = manager.process_user_transaction_request(
            username, transaction_dict, session_data, key_index
        )
        
        if not user_response.get('success', False):
            return user_response
        
        # Extract key material for transaction signing
        private_key_int = user_response['private_key_int']
        account_address_int = user_response['account_address_int']
        
        # Parse Starknet transaction parameters
        contract_address = transaction_dict.get("contract_address")
        if contract_address:
            if not contract_address.startswith("0x"):
                contract_address = "0x" + contract_address
            contract_address_int = int(contract_address, 16)
        else:
            # Use derived account address if no contract address specified
            contract_address_int = account_address_int
        
        function_name = transaction_dict["function_name"]
        calldata = transaction_dict.get("calldata", [])
        
        # Handle max_fee - can be string or int
        max_fee = transaction_dict.get("max_fee", "0x1000000000000")
        if isinstance(max_fee, str):
            max_fee = int(max_fee, 16) if max_fee.startswith("0x") else int(max_fee)
        
        nonce = transaction_dict.get("nonce", 0)
        chain_id = transaction_dict.get("chain_id", StarknetChainId.TESTNET)
        
        # Convert string chain_id to StarknetChainId enum if needed  
        if isinstance(chain_id, str):
            chain_id_map = {
                "mainnet": StarknetChainId.MAINNET,
                "testnet": StarknetChainId.TESTNET,
                "testnet2": StarknetChainId.TESTNET2
            }
            chain_id = chain_id_map.get(chain_id.lower(), StarknetChainId.TESTNET)

        # Create signer from derived private key
        signer = StarkCurveSigner(
            account_address=account_address_int,
            key_pair=private_key_int,
            chain_id=chain_id
        )

        # Create the call object
        call = Call(
            to_addr=contract_address_int,
            selector=get_selector_from_name(function_name),
            calldata=calldata
        )

        # Create client (using provided RPC endpoint or default)
        rpc_url = transaction_dict.get("rpc_url", "https://starknet-testnet.public.blastapi.io")
        client = FullNodeClient(node_url=rpc_url)

        # Create account
        account = Account(
            address=account_address_int,
            client=client,
            signer=signer,
            chain=chain_id
        )

        # Sign the transaction
        signed_transaction = account.sign_invoke_transaction(
            calls=[call],
            max_fee=max_fee,
            nonce=nonce
        )

        # Record performance metrics
        duration = time.time() - start_time
        performance_monitor.record_key_derivation(duration)
        
        # Log successful access
        log_user_key_access(username, key_index, "transaction_signing", True, 
                          session_data.get('session_id') if session_data else None)

        response_plaintext = {
            "transaction_signed": hex(signed_transaction.signature[0]) + "," + hex(signed_transaction.signature[1]),
            "transaction_hash": hex(signed_transaction.transaction_hash),
            "contract_address": hex(contract_address_int),
            "account_address": hex(account_address_int),
            "function_name": function_name,
            "calldata": calldata,
            "max_fee": hex(max_fee),
            "nonce": nonce,
            "username": username,
            "key_index": key_index,
            "success": True
        }

    except UserSessionError as e:
        performance_monitor.record_failure()
        msg = f"User session error: {e}"
        print(msg)
        response_plaintext = {"error": msg, "success": False}
        
    except (AWSIntegrationError, KMSDecryptionError, MasterSeedError) as e:
        performance_monitor.record_failure()
        msg = f"AWS integration error: {e}"
        print(msg)
        response_plaintext = {"error": msg, "success": False}
        
    except Exception as e:
        performance_monitor.record_failure()
        msg = f"Exception happened signing the Starknet transaction: {e}"
        print(msg)
        response_plaintext = {"error": msg, "success": False}

    finally:
        # Secure memory cleanup - overwrite sensitive data
        if 'private_key_int' in locals():
            private_key_int = 0
            del private_key_int
        if 'manager' in locals():
            del manager

    return response_plaintext


def process_account_info_request(payload_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process a request for account information (without transaction signing).
    
    Args:
        payload_json: Request payload
        
    Returns:
        Dict[str, Any]: Account information
    """
    try:
        # Extract user context
        username, key_index, session_data = extract_user_context_from_request(payload_json)
        
        # Get credentials and master seed
        credential = payload_json["credential"]
        encrypted_master_seed = payload_json["encrypted_master_seed"]
        
        # Initialize multi-user manager
        manager = StarknetMultiUserAWSManager()
        
        # Load master seed
        manager.load_master_seed(credential, encrypted_master_seed)
        
        # Get account info
        return manager.get_user_account_info(username, session_data, key_index)
        
    except Exception as e:
        msg = f"Exception getting account info: {e}"
        print(msg)
        return {"error": msg, "success": False}


def determine_request_type(payload_json: Dict[str, Any]) -> str:
    """
    Determine the type of request being processed.
    
    Args:
        payload_json: Request payload
        
    Returns:
        str: Request type ('single_user', 'multiuser_transaction', 'account_info')
    """
    # Check for multi-user indicators
    if 'username' in payload_json:
        if 'transaction_payload' in payload_json:
            return 'multiuser_transaction'
        else:
            return 'account_info'
    
    # Check for single-user (legacy) format
    if 'encrypted_key' in payload_json and 'transaction_payload' in payload_json:
        return 'single_user'
    
    return 'unknown'


def main():
    """Main server loop supporting both single-user and multi-user requests."""
    print("Starting Starknet multi-user signing server...")
    
    # Validate enclave environment
    if not validate_enclave_environment():
        print("WARNING: Not running in verified Nitro Enclave environment")
    
    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    try:
        # Listen for connection from any CID
        cid = socket.VMADDR_CID_ANY

        # The port should match the client running in parent EC2 instance
        port = 5000

        # Bind the socket to CID and port
        s.bind((cid, port))

        # Listen for connection from client
        s.listen()
        
        print(f"Server listening on CID {cid}, port {port}")

        while True:
            c = None
            try:
                c, addr = s.accept()
                print(f"Connection accepted from {addr}")

                # Get payload sent from parent instance
                payload = c.recv(8192)  # Increased buffer size for multi-user payloads
                payload_json = json.loads(payload.decode())
                print("Payload received (credentials redacted)")

                # Determine request type and route accordingly
                request_type = determine_request_type(payload_json)
                print(f"Processing request type: {request_type}")
                
                if request_type == 'single_user':
                    response_plaintext = process_single_user_request(payload_json)
                elif request_type == 'multiuser_transaction':
                    response_plaintext = process_multiuser_request(payload_json)
                elif request_type == 'account_info':
                    response_plaintext = process_account_info_request(payload_json)
                else:
                    response_plaintext = {
                        "error": f"Unknown request type: {request_type}",
                        "success": False
                    }

                # Send response
                print("Response sent (content redacted for security)")
                c.send(str.encode(json.dumps(response_plaintext)))

            except json.JSONDecodeError as e:
                error_msg = f"JSON decode error: {e}"
                print(error_msg)
                if c:
                    try:
                        c.send(str.encode(json.dumps({"error": error_msg, "success": False})))
                    except:
                        pass
                        
            except Exception as e:
                error_msg = f"Unexpected error in main loop: {e}"
                print(error_msg)
                if c:
                    try:
                        c.send(str.encode(json.dumps({"error": error_msg, "success": False})))
                    except:
                        pass  # Connection might be closed
            finally:
                if c:
                    try:
                        c.close()
                    except:
                        pass  # Connection might already be closed

    except Exception as e:
        print(f"Fatal error in server: {e}")
    finally:
        try:
            s.close()
        except:
            pass
        
        # Print performance summary on shutdown
        print("Performance Summary:")
        print(json.dumps(performance_monitor.get_summary(), indent=2))


if __name__ == "__main__":
    main()