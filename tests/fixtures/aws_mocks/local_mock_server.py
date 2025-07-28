"""
Comprehensive local mock server for AWS services.

This module provides a unified mock server that simulates all AWS services
needed for local development and testing, eliminating the need for actual
AWS resources or even LocalStack in some scenarios.
"""

import asyncio
import base64
import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class KMSKey:
    """KMS Key representation."""
    key_id: str
    arn: str
    description: str
    key_usage: str = "ENCRYPT_DECRYPT"
    key_spec: str = "SYMMETRIC_DEFAULT"
    creation_date: datetime = None
    enabled: bool = True
    
    def __post_init__(self):
        if self.creation_date is None:
            self.creation_date = datetime.utcnow()


@dataclass
class Secret:
    """Secrets Manager Secret representation."""
    name: str
    arn: str
    secret_string: str
    description: str = ""
    version_id: str = None
    creation_date: datetime = None
    last_changed_date: datetime = None
    
    def __post_init__(self):
        if self.version_id is None:
            self.version_id = str(uuid.uuid4())
        if self.creation_date is None:
            self.creation_date = datetime.utcnow()
        if self.last_changed_date is None:
            self.last_changed_date = datetime.utcnow()


class MockAWSService:
    """Base class for AWS service mocks."""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.region = "us-east-1"


class MockKMSService(MockAWSService):
    """Mock KMS service implementation."""
    
    def __init__(self):
        super().__init__("kms")
        self.keys: Dict[str, KMSKey] = {}
        self.aliases: Dict[str, str] = {}
        self.encryption_cache: Dict[str, bytes] = {}
    
    def create_key(self, description: str = "", key_usage: str = "ENCRYPT_DECRYPT") -> Dict[str, Any]:
        """Create a new KMS key."""
        key_id = str(uuid.uuid4())
        arn = f"arn:aws:kms:{self.region}:000000000000:key/{key_id}"
        
        key = KMSKey(
            key_id=key_id,
            arn=arn,
            description=description,
            key_usage=key_usage
        )
        
        self.keys[key_id] = key
        
        return {
            "KeyMetadata": {
                "KeyId": key_id,
                "Arn": arn,
                "Description": description,
                "KeyUsage": key_usage,
                "KeySpec": "SYMMETRIC_DEFAULT",
                "CreationDate": key.creation_date.isoformat(),
                "Enabled": True
            }
        }
    
    def create_alias(self, alias_name: str, target_key_id: str) -> Dict[str, Any]:
        """Create an alias for a KMS key."""
        if target_key_id not in self.keys:
            raise HTTPException(status_code=404, detail="Key not found")
        
        self.aliases[alias_name] = target_key_id
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    
    def encrypt(self, key_id: str, plaintext: str, encryption_context: Optional[Dict] = None) -> Dict[str, Any]:
        """Encrypt data with a KMS key."""
        # Resolve alias if needed
        actual_key_id = self.aliases.get(key_id, key_id)
        
        if actual_key_id not in self.keys:
            raise HTTPException(status_code=404, detail="Key not found")
        
        # Simple encryption simulation - just base64 encode with key ID
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode()
        else:
            plaintext_bytes = plaintext
        
        # Create a simple "encrypted" format: key_id:base64_data
        encrypted_data = f"{actual_key_id}:{base64.b64encode(plaintext_bytes).decode()}"
        ciphertext_blob = base64.b64encode(encrypted_data.encode()).decode()
        
        return {
            "CiphertextBlob": ciphertext_blob,
            "KeyId": self.keys[actual_key_id].arn,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
        }
    
    def decrypt(self, ciphertext_blob: str, encryption_context: Optional[Dict] = None) -> Dict[str, Any]:
        """Decrypt data with KMS."""
        try:
            # Decode the "encrypted" data
            encrypted_data = base64.b64decode(ciphertext_blob).decode()
            key_id, b64_data = encrypted_data.split(":", 1)
            plaintext_bytes = base64.b64decode(b64_data)
            
            if key_id not in self.keys:
                raise HTTPException(status_code=404, detail="Key not found")
            
            return {
                "Plaintext": plaintext_bytes,
                "KeyId": self.keys[key_id].arn,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT"
            }
        
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid ciphertext: {str(e)}")
    
    def describe_key(self, key_id: str) -> Dict[str, Any]:
        """Describe a KMS key."""
        actual_key_id = self.aliases.get(key_id, key_id)
        
        if actual_key_id not in self.keys:
            raise HTTPException(status_code=404, detail="Key not found")
        
        key = self.keys[actual_key_id]
        return {
            "KeyMetadata": {
                "KeyId": key.key_id,
                "Arn": key.arn,
                "Description": key.description,
                "KeyUsage": key.key_usage,
                "KeySpec": key.key_spec,
                "CreationDate": key.creation_date.isoformat(),
                "Enabled": key.enabled
            }
        }
    
    def list_keys(self) -> Dict[str, Any]:
        """List all KMS keys."""
        return {
            "Keys": [
                {
                    "KeyId": key.key_id,
                    "KeyArn": key.arn
                }
                for key in self.keys.values()
            ]
        }


class MockSecretsManagerService(MockAWSService):
    """Mock Secrets Manager service implementation."""
    
    def __init__(self):
        super().__init__("secretsmanager")
        self.secrets: Dict[str, Secret] = {}
    
    def create_secret(self, name: str, secret_string: str, description: str = "") -> Dict[str, Any]:
        """Create a new secret."""
        arn = f"arn:aws:secretsmanager:{self.region}:000000000000:secret:{name}-AbCdEf"
        
        secret = Secret(
            name=name,
            arn=arn,
            secret_string=secret_string,
            description=description
        )
        
        self.secrets[name] = secret
        
        return {
            "ARN": arn,
            "Name": name,
            "VersionId": secret.version_id
        }
    
    def get_secret_value(self, secret_id: str, version_id: Optional[str] = None) -> Dict[str, Any]:
        """Get a secret value."""
        if secret_id not in self.secrets:
            raise HTTPException(status_code=404, detail="Secret not found")
        
        secret = self.secrets[secret_id]
        
        return {
            "ARN": secret.arn,
            "Name": secret.name,
            "VersionId": secret.version_id,
            "SecretString": secret.secret_string,
            "CreatedDate": secret.creation_date.isoformat()
        }
    
    def put_secret_value(self, secret_id: str, secret_string: str) -> Dict[str, Any]:
        """Update a secret value."""
        if secret_id not in self.secrets:
            raise HTTPException(status_code=404, detail="Secret not found")
        
        secret = self.secrets[secret_id]
        secret.secret_string = secret_string
        secret.version_id = str(uuid.uuid4())
        secret.last_changed_date = datetime.utcnow()
        
        return {
            "ARN": secret.arn,
            "Name": secret.name,
            "VersionId": secret.version_id
        }
    
    def list_secrets(self) -> Dict[str, Any]:
        """List all secrets."""
        return {
            "SecretList": [
                {
                    "ARN": secret.arn,
                    "Name": secret.name,
                    "Description": secret.description,
                    "CreatedDate": secret.creation_date.isoformat(),
                    "LastChangedDate": secret.last_changed_date.isoformat()
                }
                for secret in self.secrets.values()
            ]
        }


class LocalMockServer:
    """Unified local mock server for AWS services."""
    
    def __init__(self):
        self.app = FastAPI(
            title="Local AWS Mock Server",
            description="Mock server for AWS services (KMS, Secrets Manager, etc.)",
            version="1.0.0"
        )
        
        self.kms = MockKMSService()
        self.secrets_manager = MockSecretsManagerService()
        
        self._setup_routes()
        self._initialize_test_data()
    
    def _setup_routes(self):
        """Set up API routes."""
        
        # Health check
        @self.app.get("/health")
        async def health_check():
            return {
                "status": "healthy",
                "services": {
                    "kms": "available",
                    "secretsmanager": "available"
                },
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # KMS routes
        @self.app.post("/kms/create-key")
        async def create_key(request: Request):
            body = await request.json()
            return self.kms.create_key(
                description=body.get("Description", ""),
                key_usage=body.get("KeyUsage", "ENCRYPT_DECRYPT")
            )
        
        @self.app.post("/kms/create-alias")
        async def create_alias(request: Request):
            body = await request.json()
            return self.kms.create_alias(
                alias_name=body["AliasName"],
                target_key_id=body["TargetKeyId"]
            )
        
        @self.app.post("/kms/encrypt")
        async def encrypt(request: Request):
            body = await request.json()
            return self.kms.encrypt(
                key_id=body["KeyId"],
                plaintext=body["Plaintext"],
                encryption_context=body.get("EncryptionContext")
            )
        
        @self.app.post("/kms/decrypt")
        async def decrypt(request: Request):
            body = await request.json()
            return self.kms.decrypt(
                ciphertext_blob=body["CiphertextBlob"],
                encryption_context=body.get("EncryptionContext")
            )
        
        @self.app.post("/kms/describe-key")
        async def describe_key(request: Request):
            body = await request.json()
            return self.kms.describe_key(body["KeyId"])
        
        @self.app.post("/kms/list-keys")
        async def list_keys():
            return self.kms.list_keys()
        
        # Secrets Manager routes
        @self.app.post("/secretsmanager/create-secret")
        async def create_secret(request: Request):
            body = await request.json()
            return self.secrets_manager.create_secret(
                name=body["Name"],
                secret_string=body["SecretString"],
                description=body.get("Description", "")
            )
        
        @self.app.post("/secretsmanager/get-secret-value")
        async def get_secret_value(request: Request):
            body = await request.json()
            return self.secrets_manager.get_secret_value(
                secret_id=body["SecretId"],
                version_id=body.get("VersionId")
            )
        
        @self.app.post("/secretsmanager/put-secret-value")
        async def put_secret_value(request: Request):
            body = await request.json()
            return self.secrets_manager.put_secret_value(
                secret_id=body["SecretId"],
                secret_string=body["SecretString"]
            )
        
        @self.app.post("/secretsmanager/list-secrets")
        async def list_secrets():
            return self.secrets_manager.list_secrets()
        
        # AWS-style error handling
        @self.app.exception_handler(HTTPException)
        async def aws_exception_handler(request: Request, exc: HTTPException):
            error_code = "UnknownError"
            if exc.status_code == 404:
                error_code = "ResourceNotFoundException"
            elif exc.status_code == 400:
                error_code = "ValidationException"
            elif exc.status_code == 403:
                error_code = "AccessDeniedException"
            
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "__type": error_code,
                    "message": exc.detail
                }
            )
    
    def _initialize_test_data(self):
        """Initialize test data for development."""
        logger.info("Initializing test data...")
        
        # Create test KMS keys
        master_key = self.kms.create_key("Starknet master seed encryption key")
        master_key_id = master_key["KeyMetadata"]["KeyId"]
        self.kms.create_alias("alias/starknet-master-seed", master_key_id)
        
        alice_key = self.kms.create_key("Key for user alice")
        alice_key_id = alice_key["KeyMetadata"]["KeyId"]
        self.kms.create_alias("alias/user-alice", alice_key_id)
        
        bob_key = self.kms.create_key("Key for user bob")
        bob_key_id = bob_key["KeyMetadata"]["KeyId"]
        self.kms.create_alias("alias/user-bob", bob_key_id)
        
        # Create encrypted master seed
        master_seed = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        encrypted_master = self.kms.encrypt(master_key_id, master_seed)
        
        self.secrets_manager.create_secret(
            "starknet/encrypted-master-seed",
            encrypted_master["CiphertextBlob"],
            "Encrypted Starknet master seed"
        )
        
        # Create user sessions
        alice_session = {
            "user_id": "alice",
            "session_token": "test_session_alice_123",
            "permissions": ["starknet:sign", "starknet:derive_key"],
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "kms_key_id": alice_key_id
        }
        
        self.secrets_manager.create_secret(
            "users/alice/session",
            json.dumps(alice_session),
            "Session data for user alice"
        )
        
        bob_session = {
            "user_id": "bob",
            "session_token": "test_session_bob_456",
            "permissions": ["starknet:sign"],
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat(),
            "kms_key_id": bob_key_id
        }
        
        self.secrets_manager.create_secret(
            "users/bob/session",
            json.dumps(bob_session),
            "Session data for user bob"
        )
        
        # Create encrypted private keys
        alice_private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        encrypted_alice = self.kms.encrypt(alice_key_id, alice_private_key)
        
        self.secrets_manager.create_secret(
            "users/alice/private-key",
            encrypted_alice["CiphertextBlob"],
            "Encrypted private key for alice"
        )
        
        bob_private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        encrypted_bob = self.kms.encrypt(bob_key_id, bob_private_key)
        
        self.secrets_manager.create_secret(
            "users/bob/private-key",
            encrypted_bob["CiphertextBlob"],
            "Encrypted private key for bob"
        )
        
        logger.info("Test data initialization completed")
    
    def run(self, host: str = "0.0.0.0", port: int = 4567):
        """Run the mock server."""
        logger.info(f"Starting Local AWS Mock Server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port, log_level="info")


async def start_mock_server_async(host: str = "0.0.0.0", port: int = 4567):
    """Start mock server asynchronously."""
    server = LocalMockServer()
    config = uvicorn.Config(server.app, host=host, port=port, log_level="info")
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


if __name__ == "__main__":
    server = LocalMockServer()
    server.run()