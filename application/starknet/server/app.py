#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

import json
import logging
import os
import socket
import ssl
from http import client
from http.server import BaseHTTPRequestHandler, HTTPServer

import boto3

secrets_manager_client = boto3.client(
    service_name="secretsmanager", region_name=os.getenv("REGION", "us-east-1")
)


class S(BaseHTTPRequestHandler):
    def _set_response(self, http_status=200):
        self.send_response(http_status)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        logging.info(
            "POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
            str(self.path),
            str(self.headers),
            post_data.decode("utf-8"),
        )
        payload = json.loads(post_data.decode("utf-8"))

        if not (payload.get("transaction_payload") and payload.get("secret_id")):
            self._set_response(404)
            self.wfile.write(
                "transaction_payload or secret_id are missing".encode("utf-8")
            )
            return

        # Validate Starknet transaction payload
        transaction_payload = payload["transaction_payload"]
        required_fields = ["contract_address", "function_name"]
        
        for field in required_fields:
            if field not in transaction_payload:
                self._set_response(400)
                self.wfile.write(
                    f"Missing required field in transaction_payload: {field}".encode("utf-8")
                )
                return

        plaintext_json = call_enclave(16, 5000, payload)

        self._set_response()
        self.wfile.write(plaintext_json.encode("utf-8"))


def get_encrypted_key(secret_id):
    try:
        encrypted_key = secrets_manager_client.get_secret_value(SecretId=secret_id)
    except Exception as e:
        raise e

    return encrypted_key["SecretString"]


def get_imds_token():
    http_ec2_client = client.HTTPConnection("169.254.169.254")
    headers = {
        "X-aws-ec2-metadata-token-ttl-seconds": "21600"  # Token valid for 6 hours
    }
    http_ec2_client.request("PUT", "/latest/api/token", headers=headers)
    token_response = http_ec2_client.getresponse()
    return token_response.read().decode()


def get_aws_session_token():
    try:
        token = get_imds_token()

        http_ec2_client = client.HTTPConnection("169.254.169.254")
        headers = {"X-aws-ec2-metadata-token": token}

        # Get instance profile name
        http_ec2_client.request(
            "GET",
            "/latest/meta-data/iam/security-credentials/",
            headers=headers
        )
        r = http_ec2_client.getresponse()
        instance_profile_name = r.read().decode()

        # Get credentials
        http_ec2_client.request(
            "GET",
            f"/latest/meta-data/iam/security-credentials/{instance_profile_name}",
            headers=headers
        )
        r = http_ec2_client.getresponse()
        response = json.loads(r.read())
        return {
            "access_key_id": response["AccessKeyId"],
            "secret_access_key": response["SecretAccessKey"],
            "token": response["Token"],
        }

    except Exception as e:
        raise Exception(f"Failed to retrieve instance credentials: {str(e)}")
    finally:
        if 'http_ec2_client' in locals():
            http_ec2_client.close()


def call_enclave(cid, port, enclave_payload):
    secret_id = enclave_payload["secret_id"]
    encrypted_key = get_encrypted_key(secret_id)

    payload = {}
    # Get EC2 instance metadata
    payload["credential"] = get_aws_session_token()
    payload["transaction_payload"] = enclave_payload["transaction_payload"]
    payload["encrypted_key"] = encrypted_key

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((cid, port))

    # Send AWS credential to the server running in enclave
    s.send(str.encode(json.dumps(payload)))

    # receive data from the server
    payload_processed = s.recv(1024).decode()
    print("payload_processed: {}".format(payload_processed))

    # close the connection
    s.close()

    return payload_processed


def run(server_class=HTTPServer, handler_class=S, port=443):
    logging.basicConfig(level=logging.INFO)
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)
    logging.info("Starting Starknet httpd server...\n")
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile="/etc/pki/tls/certs/localhost.crt",
        ssl_version=ssl.PROTOCOL_TLS,
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info("Stopping Starknet httpd server...\n")


if __name__ == "__main__":
    run()