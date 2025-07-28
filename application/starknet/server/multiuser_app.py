#!/usr/bin/env python3
"""
Multi-user Starknet application server for AWS Nitro Enclaves.

This server extends the original application to support multiple users
with deterministic key derivation. It manages user sessions and routes
requests to the appropriate enclave operations.
"""

import json
import logging
import os
import socket
import ssl
import time
import uuid
from http import client
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, Optional

import boto3

# AWS clients
secrets_manager_client = boto3.client(
    service_name="secretsmanager", 
    region_name=os.getenv("REGION", "us-east-1")
)

# Configuration
MASTER_SEED_SECRET_ID = os.getenv("MASTER_SEED_SECRET_ID", "starknet-master-seed")
DEFAULT_SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour


class MultiUserRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for multi-user Starknet operations."""
    
    def _set_response(self, http_status: int = 200):
        """Set HTTP response headers."""
        self.send_response(http_status)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def _validate_multiuser_payload(self, payload: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate multi-user request payload.
        
        Args:
            payload: Request payload to validate
            
        Returns:
            tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Check for required fields
        required_fields = ["username", "operation"]
        for field in required_fields:
            if field not in payload:
                return False, f"Missing required field: {field}"
        
        # Validate username
        username = payload["username"]
        if not isinstance(username, str) or not username.strip():
            return False, "Invalid username"
        
        if len(username) > 255:
            return False, "Username too long (max 255 characters)"
        
        # Validate operation type
        operation = payload["operation"]
        valid_operations = ["sign_transaction", "get_account_info", "derive_key"]
        if operation not in valid_operations:
            return False, f"Invalid operation. Must be one of: {valid_operations}"
        
        # Validate transaction payload if signing transaction
        if operation == "sign_transaction":
            if "transaction_payload" not in payload:
                return False, "Missing transaction_payload for sign_transaction operation"
            
            transaction_payload = payload["transaction_payload"]
            required_tx_fields = ["contract_address", "function_name"]
            
            for field in required_tx_fields:
                if field not in transaction_payload:
                    return False, f"Missing required transaction field: {field}"
        
        return True, None

    def _create_user_session(self, username: str) -> Dict[str, Any]:
        """
        Create a new user session.
        
        Args:
            username: Username for the session
            
        Returns:
            Dict[str, Any]: Session data
        """
        return {
            "session_id": str(uuid.uuid4()),
            "username": username,
            "timestamp": int(time.time()),
            "expires_at": int(time.time()) + DEFAULT_SESSION_TIMEOUT,
            "ip_address": self.client_address[0]
        }

    def _validate_session(self, session_data: Optional[Dict[str, Any]]) -> bool:
        """
        Validate user session.
        
        Args:
            session_data: Session data to validate
            
        Returns:
            bool: True if session is valid
        """
        if session_data is None:
            return False
        
        # Check if session_data is an empty dictionary
        if not session_data:
            return False
        
        current_time = int(time.time())
        expires_at = session_data.get("expires_at", 0)
        
        return current_time < expires_at

    def do_POST(self):
        """Handle POST requests for multi-user operations."""
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        
        try:
            payload = json.loads(post_data.decode("utf-8"))
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error: {e}")
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid JSON payload"}).encode("utf-8"))
            return

        logging.info(
            "POST request,\nPath: %s\nHeaders:\n%s\nOperation: %s\nUsername: %s",
            str(self.path),
            str(self.headers),
            payload.get("operation", "unknown"),
            payload.get("username", "unknown")
        )

        # Validate payload
        is_valid, error_msg = self._validate_multiuser_payload(payload)
        if not is_valid:
            self._set_response(400)
            self.wfile.write(json.dumps({"error": error_msg}).encode("utf-8"))
            return

        # Route based on operation type
        operation = payload["operation"]
        
        try:
            if operation == "sign_transaction":
                response = self._handle_sign_transaction(payload)
            elif operation == "get_account_info":
                response = self._handle_get_account_info(payload)
            elif operation == "derive_key":
                response = self._handle_derive_key(payload)
            else:
                response = {"error": f"Unsupported operation: {operation}", "success": False}
            
            self._set_response(200 if response.get("success", False) else 400)
            self.wfile.write(json.dumps(response).encode("utf-8"))
            
        except Exception as e:
            logging.error(f"Error processing {operation}: {e}")
            self._set_response(500)
            self.wfile.write(json.dumps({
                "error": f"Internal server error: {str(e)}",
                "success": False
            }).encode("utf-8"))

    def _handle_sign_transaction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle transaction signing request.
        
        Args:
            payload: Request payload
            
        Returns:
            Dict[str, Any]: Response data
        """
        username = payload["username"]
        transaction_payload = payload["transaction_payload"]
        key_index = payload.get("key_index", 0)
        
        # Create session for this request
        session_data = self._create_user_session(username)
        
        # Prepare enclave payload
        enclave_payload = {
            "username": username,
            "key_index": key_index,
            "operation": "sign_transaction",
            "transaction_payload": transaction_payload,
            "session_data": session_data
        }
        
        return call_enclave_multiuser(16, 5000, enclave_payload)

    def _handle_get_account_info(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle account information request.
        
        Args:
            payload: Request payload
            
        Returns:
            Dict[str, Any]: Account information
        """
        username = payload["username"]
        key_index = payload.get("key_index", 0)
        
        # Create session for this request
        session_data = self._create_user_session(username)
        
        # Prepare enclave payload
        enclave_payload = {
            "username": username,
            "key_index": key_index,
            "operation": "get_account_info",
            "session_data": session_data
        }
        
        return call_enclave_multiuser(16, 5000, enclave_payload)

    def _handle_derive_key(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle key derivation request (returns only public information).
        
        Args:
            payload: Request payload
            
        Returns:
            Dict[str, Any]: Public key information
        """
        username = payload["username"]
        key_index = payload.get("key_index", 0)
        
        # Create session for this request
        session_data = self._create_user_session(username)
        
        # Prepare enclave payload
        enclave_payload = {
            "username": username,
            "key_index": key_index,
            "operation": "derive_key",
            "session_data": session_data
        }
        
        return call_enclave_multiuser(16, 5000, enclave_payload)

    def do_GET(self):
        """Handle GET requests for system information."""
        if self.path == "/health":
            self._set_response(200)
            self.wfile.write(json.dumps({
                "status": "healthy",
                "service": "starknet-multiuser",
                "timestamp": int(time.time())
            }).encode("utf-8"))
        
        elif self.path == "/metrics":
            # Return basic metrics (implement as needed)
            self._set_response(200)
            self.wfile.write(json.dumps({
                "active_sessions": 0,  # Implement session tracking
                "total_requests": 0,   # Implement request counting
                "uptime_seconds": 0    # Implement uptime tracking
            }).encode("utf-8"))
        
        else:
            self._set_response(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode("utf-8"))


def get_encrypted_master_seed() -> str:
    """
    Get the encrypted master seed from AWS Secrets Manager.
    
    Returns:
        str: Encrypted master seed
        
    Raises:
        Exception: If secret retrieval fails
    """
    try:
        response = secrets_manager_client.get_secret_value(SecretId=MASTER_SEED_SECRET_ID)
        return response["SecretString"]
    except Exception as e:
        logging.error(f"Failed to get master seed: {e}")
        raise e


def get_imds_token() -> str:
    """Get IMDS token for EC2 metadata access."""
    http_ec2_client = client.HTTPConnection("169.254.169.254")
    headers = {
        "X-aws-ec2-metadata-token-ttl-seconds": "21600"  # Token valid for 6 hours
    }
    http_ec2_client.request("PUT", "/latest/api/token", headers=headers)
    token_response = http_ec2_client.getresponse()
    return token_response.read().decode()


def get_aws_session_token() -> Dict[str, str]:
    """
    Get AWS session token from EC2 instance metadata.
    
    Returns:
        Dict[str, str]: AWS credentials
    """
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


def call_enclave_multiuser(cid: int, port: int, enclave_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Call the multi-user enclave with a request.
    
    Args:
        cid: Connection ID for vsock
        port: Port number
        enclave_payload: Payload to send to enclave
        
    Returns:
        Dict[str, Any]: Response from enclave
    """
    try:
        # Get encrypted master seed
        encrypted_master_seed = get_encrypted_master_seed()
        
        # Prepare full payload
        payload = {
            "credential": get_aws_session_token(),
            "encrypted_master_seed": encrypted_master_seed,
            **enclave_payload
        }

        # Create a vsock socket object
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

        # Connect to the server
        s.connect((cid, port))

        # Send payload to the server running in enclave
        payload_json = json.dumps(payload)
        s.send(payload_json.encode())

        # Receive data from the server
        response_data = s.recv(8192).decode()  # Increased buffer size
        response = json.loads(response_data)
        
        logging.info(f"Enclave response received for user: {enclave_payload.get('username', 'unknown')}")

        # Close the connection
        s.close()

        return response
        
    except Exception as e:
        logging.error(f"Enclave communication error: {e}")
        return {
            "error": f"Enclave communication failed: {str(e)}",
            "success": False
        }


def call_enclave_legacy(cid: int, port: int, enclave_payload: Dict[str, Any]) -> str:
    """
    Call enclave with legacy single-user format (for backward compatibility).
    
    Args:
        cid: Connection ID
        port: Port number
        enclave_payload: Legacy payload format
        
    Returns:
        str: Response JSON string
    """
    secret_id = enclave_payload["secret_id"]
    
    try:
        encrypted_key = secrets_manager_client.get_secret_value(SecretId=secret_id)["SecretString"]
    except Exception as e:
        return json.dumps({"error": f"Failed to get secret: {e}", "success": False})

    payload = {
        "credential": get_aws_session_token(),
        "transaction_payload": enclave_payload["transaction_payload"],
        "encrypted_key": encrypted_key
    }

    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Connect to the server
    s.connect((cid, port))

    # Send AWS credential to the server running in enclave
    s.send(str.encode(json.dumps(payload)))

    # receive data from the server
    payload_processed = s.recv(1024).decode()
    logging.info("Legacy payload processed")

    # close the connection
    s.close()

    return payload_processed


class LegacyRequestHandler(BaseHTTPRequestHandler):
    """Legacy HTTP request handler for backward compatibility."""
    
    def _set_response(self, http_status: int = 200):
        self.send_response(http_status)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def do_POST(self):
        """Handle legacy POST requests."""
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        
        logging.info(
            "Legacy POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n",
            str(self.path),
            str(self.headers),
            post_data.decode("utf-8"),
        )
        
        try:
            payload = json.loads(post_data.decode("utf-8"))
        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b"Invalid JSON")
            return

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

        plaintext_json = call_enclave_legacy(16, 5000, payload)

        self._set_response()
        self.wfile.write(plaintext_json.encode("utf-8"))


def run_server(
    server_class=HTTPServer, 
    handler_class=MultiUserRequestHandler, 
    port: int = 443,
    legacy_mode: bool = False
):
    """
    Run the HTTP server.
    
    Args:
        server_class: HTTP server class
        handler_class: Request handler class
        port: Port to listen on
        legacy_mode: Whether to run in legacy compatibility mode
    """
    logging.basicConfig(level=logging.INFO)
    server_address = ("0.0.0.0", port)
    
    if legacy_mode:
        handler_class = LegacyRequestHandler
        logging.info("Starting Starknet legacy httpd server...")
    else:
        logging.info("Starting Starknet multi-user httpd server...")
    
    httpd = server_class(server_address, handler_class)
    
    # Set up SSL
    try:
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            server_side=True,
            certfile="/etc/pki/tls/certs/localhost.crt",
            ssl_version=ssl.PROTOCOL_TLS,
        )
    except Exception as e:
        logging.warning(f"SSL setup failed: {e}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    
    httpd.server_close()
    logging.info("Stopping Starknet httpd server...")


if __name__ == "__main__":
    # Check if running in legacy mode
    legacy_mode = os.getenv("LEGACY_MODE", "false").lower() == "true"
    port = int(os.getenv("PORT", "443"))
    
    run_server(port=port, legacy_mode=legacy_mode)