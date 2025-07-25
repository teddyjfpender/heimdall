#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import base64
import json
import os
import socket
import subprocess

from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.account.account import Account
from starknet_py.net.client_models import Call
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.signer.stark_curve_signer import StarkCurveSigner


def kms_call(credential, ciphertext):
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


def main():
    print("Starting Starknet signing server...")

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

        while True:
            c = None
            try:
                c, addr = s.accept()

                # Get AWS credential sent from parent instance
                payload = c.recv(4096)
                payload_json = json.loads(payload.decode())
                print("payload json received (credentials redacted)")

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
                    response_plaintext = {"error": msg}

                else:
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

                print("response sent (content redacted for security)")

                c.send(str.encode(json.dumps(response_plaintext)))

            except Exception as e:
                error_msg = "Unexpected error in main loop: {}".format(e)
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
        print("Fatal error in server: {}".format(e))
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    main()