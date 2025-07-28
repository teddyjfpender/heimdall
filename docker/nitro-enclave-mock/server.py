#!/usr/bin/env python3
"""
Mock Nitro Enclave Server for local development and testing.

This server simulates the behavior of an AWS Nitro Enclave for Starknet
transaction signing without requiring actual enclave infrastructure.
"""

import base64
import json
import logging
import os
import time
from typing import Dict, Any, Optional

import boto3
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starknet_py.hash.selector import get_selector_from_name
from starknet_py.net.signer.stark_curve_signer import StarkCurveSigner
from starknet_py.net.models.chains import StarknetChainId

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if os.getenv("LOG_LEVEL") == "DEBUG" else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Mock Nitro Enclave Server",
    description="Mock server simulating AWS Nitro Enclave for Starknet signing",
    version="1.0.0"
)

# Mock AWS clients pointing to LocalStack
def get_aws_client(service_name: str):
    """Get AWS client configured for LocalStack."""
    return boto3.client(
        service_name,
        endpoint_url=os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566"),
        region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY", "test")
    )

kms_client = get_aws_client("kms")
secrets_client = get_aws_client("secretsmanager")


class TransactionPayload(BaseModel):
    """Starknet transaction payload model."""
    version: int = Field(default=1)
    contract_address: str
    entry_point_selector: Optional[str] = None
    function_name: Optional[str] = None
    calldata: list = Field(default_factory=list)
    max_fee: str
    nonce: int
    chain_id: str = Field(default="SN_GOERLI")


class SigningRequest(BaseModel):
    """Request model for transaction signing."""
    credential: Dict[str, str]
    transaction_payload: TransactionPayload
    encrypted_key: Optional[str] = None
    secret_id: Optional[str] = None
    user_id: Optional[str] = None
    network: str = Field(default="goerli")
    cairo_version: str = Field(default="1")


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str
    timestamp: str
    services: Dict[str, str]


class SigningResponse(BaseModel):
    """Transaction signing response model."""
    signature: Dict[str, str]
    transaction_hash: str
    status: str
    timestamp: str


def mock_kms_decrypt(encrypted_data: str) -> str:
    """
    Mock KMS decryption that returns predictable test keys.
    In a real enclave, this would call the actual KMS service.
    """
    try:
        # Try to decrypt using LocalStack KMS first
        response = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_data))
        return response['Plaintext'].decode('utf-8')
    except Exception as e:
        logger.warning(f"KMS decrypt failed, using mock data: {e}")
        
        # Fallback to mock decryption for testing
        mock_keys = {
            "mock_encrypted_starknet_key_blob": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "mock_encrypted_key_blob": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        }
        
        return mock_keys.get(encrypted_data, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")


def get_master_seed() -> str:
    """Get the decrypted master seed from Secrets Manager and KMS."""
    try:
        # Get encrypted master seed from Secrets Manager
        response = secrets_client.get_secret_value(SecretId="starknet/encrypted-master-seed")
        encrypted_seed = response['SecretString']
        
        # Decrypt with KMS
        decrypt_response = kms_client.decrypt(CiphertextBlob=base64.b64decode(encrypted_seed))
        return decrypt_response['Plaintext'].decode('utf-8')
    
    except Exception as e:
        logger.warning(f"Failed to get master seed, using fallback: {e}")
        return "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"


def derive_user_key(master_seed: str, user_id: str, derivation_path: str = "") -> str:
    """
    Derive a user-specific private key from the master seed.
    This is a simplified version - production would use proper HKDF.
    """
    import hashlib
    
    # Simple key derivation for testing
    combined = f"{master_seed}:{user_id}:{derivation_path}"
    derived_hash = hashlib.sha256(combined.encode()).hexdigest()
    return f"0x{derived_hash}"


def sign_starknet_transaction(private_key: str, transaction: TransactionPayload) -> Dict[str, str]:
    """Sign a Starknet transaction using the private key."""
    try:
        # Remove '0x' prefix if present
        if private_key.startswith('0x'):
            private_key = private_key[2:]
        
        private_key_int = int(private_key, 16)
        signer = StarkCurveSigner(account_address="0x0", private_key=private_key_int, chain_id=StarknetChainId.GOERLI)
        
        # Convert transaction to signable format
        tx_hash = calculate_transaction_hash(transaction)
        
        # Sign the transaction hash
        signature = signer.sign_message(tx_hash)
        
        return {
            "r": hex(signature.r),
            "s": hex(signature.s),
            "recovery_id": "0"  # Starknet doesn't use recovery ID like Ethereum
        }
    
    except Exception as e:
        logger.error(f"Transaction signing failed: {e}")
        # Return mock signature for testing
        return {
            "r": "0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef123",
            "s": "0x456789abcdef123456789abcdef123456789abcdef123456789abcdef123456",
            "recovery_id": "0"
        }


def calculate_transaction_hash(transaction: TransactionPayload) -> int:
    """
    Calculate Starknet transaction hash.
    This is a simplified version for testing purposes.
    """
    import hashlib
    
    # Simplified hash calculation
    tx_data = {
        "version": transaction.version,
        "contract_address": transaction.contract_address,
        "entry_point_selector": transaction.entry_point_selector,
        "calldata": transaction.calldata,
        "max_fee": transaction.max_fee,
        "nonce": transaction.nonce,
        "chain_id": transaction.chain_id
    }
    
    tx_json = json.dumps(tx_data, sort_keys=True)
    tx_hash = hashlib.sha256(tx_json.encode()).hexdigest()
    return int(tx_hash, 16) % (2**251 + 17 * 2**192 + 1)  # Starknet field prime


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    services = {}
    
    # Check LocalStack KMS
    try:
        kms_client.list_keys()
        services["kms"] = "healthy"
    except Exception:
        services["kms"] = "unhealthy"
    
    # Check LocalStack Secrets Manager
    try:
        secrets_client.list_secrets()
        services["secrets_manager"] = "healthy"
    except Exception:
        services["secrets_manager"] = "unhealthy"
    
    return HealthResponse(
        status="healthy",
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        services=services
    )


@app.post("/sign", response_model=SigningResponse)
async def sign_transaction(request: SigningRequest):
    """Sign a Starknet transaction."""
    try:
        logger.info(f"Received signing request for user: {request.user_id}")
        
        # Get private key for signing
        if request.secret_id:
            # Get private key from Secrets Manager
            try:
                secret_response = secrets_client.get_secret_value(SecretId=request.secret_id)
                encrypted_key = secret_response['SecretString']
                private_key = mock_kms_decrypt(encrypted_key)
            except Exception as e:
                logger.warning(f"Failed to get secret {request.secret_id}: {e}")
                private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        
        elif request.encrypted_key:
            # Decrypt provided encrypted key
            private_key = mock_kms_decrypt(request.encrypted_key)
        
        elif request.user_id:
            # Derive key from master seed
            master_seed = get_master_seed()
            private_key = derive_user_key(master_seed, request.user_id)
        
        else:
            # Use default test key
            private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        
        # Handle function name to selector conversion if needed
        if request.transaction_payload.function_name and not request.transaction_payload.entry_point_selector:
            request.transaction_payload.entry_point_selector = hex(get_selector_from_name(request.transaction_payload.function_name))
        
        # Sign the transaction
        signature = sign_starknet_transaction(private_key, request.transaction_payload)
        
        # Calculate transaction hash
        tx_hash = calculate_transaction_hash(request.transaction_payload)
        
        logger.info(f"Successfully signed transaction for user: {request.user_id}")
        
        return SigningResponse(
            signature=signature,
            transaction_hash=hex(tx_hash),
            status="success",
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        )
    
    except Exception as e:
        logger.error(f"Transaction signing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")


@app.post("/derive-key")
async def derive_key(request: Request):
    """Derive a new key for a user."""
    try:
        body = await request.json()
        user_id = body.get("user_id")
        derivation_path = body.get("derivation_path", "")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="user_id is required")
        
        master_seed = get_master_seed()
        derived_key = derive_user_key(master_seed, user_id, derivation_path)
        
        logger.info(f"Derived key for user: {user_id}")
        
        return {
            "derived_key": derived_key,
            "user_id": user_id,
            "derivation_path": derivation_path,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }
    
    except Exception as e:
        logger.error(f"Key derivation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Key derivation failed: {str(e)}")


@app.get("/attestation")
async def get_attestation():
    """Mock attestation endpoint."""
    return {
        "attestation_doc": "mock_attestation_document_base64",
        "pcrs": {
            "PCR0": "mock_pcr0_value",
            "PCR1": "mock_pcr1_value",
            "PCR2": "mock_pcr2_value"
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "enclave_id": "mock_enclave_id"
    }


@app.get("/metrics")
async def get_metrics():
    """Mock metrics endpoint."""
    return {
        "transactions_signed": 100,
        "keys_derived": 25,
        "uptime_seconds": 3600,
        "memory_usage_mb": 128,
        "cpu_usage_percent": 15.5
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {str(exc)}"}
    )


if __name__ == "__main__":
    logger.info("Starting Mock Nitro Enclave Server...")
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8001,
        log_level="debug" if os.getenv("LOG_LEVEL") == "DEBUG" else "info",
        reload=os.getenv("MOCK_MODE") == "true"
    )