"""
Comprehensive AWS Nitro Enclave mock for local testing.

This module provides a realistic Nitro Enclave mock that simulates enclave behavior
including attestation, VSOCK communication, PCR measurements, and environment validation.
"""

import base64
import hashlib
import json
import secrets
import socket
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union, Tuple
from unittest.mock import Mock, patch, MagicMock
import subprocess
import os


class NitroEnclaveError(Exception):
    """Base exception for Nitro Enclave mock errors."""
    pass


class AttestationError(NitroEnclaveError):
    """Simulates Nitro Enclave attestation errors."""
    pass


class VSockError(NitroEnclaveError):
    """Simulates VSOCK communication errors."""
    pass


class EnclaveEnvironmentError(NitroEnclaveError):
    """Simulates enclave environment validation errors."""
    pass


class MockPCRMeasurement:
    """Represents a mock Platform Configuration Register (PCR) measurement."""
    
    def __init__(self, pcr_index: int, measurement: Optional[str] = None):
        self.pcr_index = pcr_index
        self.measurement = measurement or self._generate_realistic_pcr()
        self.hash_algorithm = "SHA384"
        
    def _generate_realistic_pcr(self) -> str:
        """Generate a realistic PCR measurement."""
        # Simulate different PCR values for different components
        if self.pcr_index == 0:
            # PCR0 typically contains enclave image hash
            data = f"enclave_image_hash_{secrets.token_hex(16)}"
        elif self.pcr_index == 1:
            # PCR1 typically contains Linux kernel hash
            data = f"kernel_hash_{secrets.token_hex(16)}"
        elif self.pcr_index == 2:
            # PCR2 typically contains application hash
            data = f"application_hash_{secrets.token_hex(16)}"
        else:
            data = f"pcr_{self.pcr_index}_{secrets.token_hex(16)}"
            
        return hashlib.sha384(data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert PCR to dictionary representation."""
        return {
            "PCR": self.pcr_index,
            "HashAlgorithm": self.hash_algorithm,
            "Digest": self.measurement
        }


class MockAttestationDocument:
    """Represents a mock Nitro Enclave attestation document."""
    
    def __init__(self, enclave_id: str, user_data: Optional[bytes] = None):
        self.enclave_id = enclave_id
        self.user_data = user_data or b""
        self.timestamp = datetime.now(timezone.utc)
        self.nonce = secrets.token_bytes(32)
        self.pcrs = self._generate_pcr_measurements()
        self.public_key = self._generate_public_key()
        self.certificate = self._generate_certificate()
        
    def _generate_pcr_measurements(self) -> Dict[int, MockPCRMeasurement]:
        """Generate realistic PCR measurements."""
        pcrs = {}
        # Generate PCRs 0-15 as commonly used in Nitro Enclaves
        for i in range(16):
            pcrs[i] = MockPCRMeasurement(i)
        return pcrs
    
    def _generate_public_key(self) -> str:
        """Generate a mock public key."""
        # Generate a realistic-looking public key
        key_data = secrets.token_bytes(65)  # Uncompressed secp256r1 key
        return base64.b64encode(key_data).decode()
    
    def _generate_certificate(self) -> str:
        """Generate a mock certificate chain."""
        # Mock certificate data
        cert_data = {
            "issuer": "AWS Nitro Enclaves",
            "subject": f"enclave-{self.enclave_id}",
            "serial": secrets.token_hex(16),
            "not_before": self.timestamp.isoformat(),
            "not_after": (self.timestamp.replace(year=self.timestamp.year + 1)).isoformat()
        }
        return base64.b64encode(json.dumps(cert_data).encode()).decode()
    
    def to_cbor(self) -> bytes:
        """Convert attestation document to CBOR format (mocked)."""
        # In real implementation, this would use CBOR encoding
        document = {
            "module_id": f"i-{secrets.token_hex(8)}-enc{secrets.token_hex(8)}",
            "timestamp": int(self.timestamp.timestamp() * 1000),
            "digest": "SHA384",
            "pcrs": {str(k): v.measurement for k, v in self.pcrs.items()},
            "certificate": self.certificate,
            "cabundle": [self.certificate],  # Simplified bundle
            "public_key": self.public_key,
            "user_data": base64.b64encode(self.user_data).decode() if self.user_data else None,
            "nonce": base64.b64encode(self.nonce).decode()
        }
        
        # Mock CBOR encoding with JSON + base64
        json_data = json.dumps(document, sort_keys=True)
        return base64.b64encode(json_data.encode())
    
    def verify_pcr(self, pcr_index: int, expected_value: str) -> bool:
        """Verify a PCR measurement."""
        if pcr_index not in self.pcrs:
            return False
        return self.pcrs[pcr_index].measurement == expected_value


class MockVSockConnection:
    """Mock VSOCK connection for enclave communication."""
    
    def __init__(self, cid: int, port: int):
        self.cid = cid
        self.port = port
        self.connected = False
        self.data_buffer = b""
        self.closed = False
        
    def connect(self) -> None:
        """Mock connection establishment."""
        if self.closed:
            raise VSockError("Connection is closed")
        self.connected = True
        
    def send(self, data: bytes) -> int:
        """Mock sending data over VSOCK."""
        if not self.connected or self.closed:
            raise VSockError("Not connected")
        # In real implementation, this would send to the enclave
        return len(data)
    
    def recv(self, buffer_size: int) -> bytes:
        """Mock receiving data from VSOCK."""
        if not self.connected or self.closed:
            raise VSockError("Not connected")
        
        # Return mock data
        if self.data_buffer:
            data = self.data_buffer[:buffer_size]
            self.data_buffer = self.data_buffer[buffer_size:]
            return data
        return b""
    
    def close(self) -> None:
        """Close VSOCK connection."""
        self.connected = False
        self.closed = True
    
    def set_mock_response(self, data: bytes) -> None:
        """Set mock response data for testing."""
        self.data_buffer = data


class MockNitroEnclaveService:
    """
    Comprehensive AWS Nitro Enclave service mock.
    
    This mock provides realistic Nitro Enclave behavior for testing, including:
    - Enclave lifecycle management
    - Attestation document generation and validation
    - VSOCK communication simulation
    - PCR measurement handling
    - Environment validation
    - KMS tool integration
    """
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.enclaves: Dict[str, Dict[str, Any]] = {}
        self.attestation_documents: Dict[str, MockAttestationDocument] = {}
        self.vsock_connections: Dict[Tuple[int, int], MockVSockConnection] = {}
        self.environment_variables = self._default_environment()
        self.performance_metrics = {}
        self._setup_default_enclave()
    
    def _default_environment(self) -> Dict[str, str]:
        """Set up default enclave environment variables."""
        return {
            "AWS_REGION": self.region,
            "NITRO_CLI_TIMEOUT": "30",
            "ENCLAVE_CPU_COUNT": "2",
            "ENCLAVE_MEMORY_MIB": "512",
            "NSM_DEVICE_PATH": "/dev/nsm",
            "VSOCK_CID": "16",
            "VSOCK_PORT": "5000",
            "LOG_LEVEL": "INFO"
        }
    
    def _setup_default_enclave(self) -> None:
        """Set up a default test enclave."""
        enclave_id = "test-enclave-12345"
        self.enclaves[enclave_id] = {
            "enclave_id": enclave_id,
            "state": "RUNNING",
            "cpu_count": 2,
            "memory_mib": 512,
            "created_at": datetime.now(timezone.utc),
            "flags": ["DEBUG_MODE"]
        }
        
        # Create attestation document
        self.attestation_documents[enclave_id] = MockAttestationDocument(enclave_id)
    
    def create_enclave(self, 
                      image_path: str,
                      cpu_count: int = 2,
                      memory_mib: int = 512,
                      debug_mode: bool = True,
                      enclave_cid: Optional[int] = None) -> Dict[str, Any]:
        """Create a new enclave."""
        enclave_id = f"enclave-{secrets.token_hex(8)}"
        
        enclave_config = {
            "enclave_id": enclave_id,
            "image_path": image_path,
            "state": "STARTING",
            "cpu_count": cpu_count,
            "memory_mib": memory_mib,
            "created_at": datetime.now(timezone.utc),
            "enclave_cid": enclave_cid or secrets.randbelow(1000) + 16,
            "flags": ["DEBUG_MODE"] if debug_mode else []
        }
        
        self.enclaves[enclave_id] = enclave_config
        
        # Create attestation document
        self.attestation_documents[enclave_id] = MockAttestationDocument(enclave_id)
        
        # Simulate startup time
        time.sleep(0.1)
        enclave_config["state"] = "RUNNING"
        
        return {
            "EnclaveID": enclave_id,
            "State": "RUNNING",
            "CPUCount": cpu_count,
            "MemoryMiB": memory_mib,
            "EnclaveCID": enclave_config["enclave_cid"]
        }
    
    def describe_enclave(self, enclave_id: str) -> Dict[str, Any]:
        """Describe an enclave."""
        if enclave_id not in self.enclaves:
            raise NitroEnclaveError(f"Enclave '{enclave_id}' not found")
        
        enclave = self.enclaves[enclave_id]
        return {
            "EnclaveID": enclave_id,
            "State": enclave["state"],
            "CPUCount": enclave["cpu_count"],
            "MemoryMiB": enclave["memory_mib"],
            "CreatedAt": enclave["created_at"].isoformat(),
            "EnclaveCID": enclave.get("enclave_cid"),
            "Flags": enclave.get("flags", [])
        }
    
    def terminate_enclave(self, enclave_id: str) -> Dict[str, Any]:
        """Terminate an enclave."""
        if enclave_id not in self.enclaves:
            raise NitroEnclaveError(f"Enclave '{enclave_id}' not found")
        
        self.enclaves[enclave_id]["state"] = "TERMINATING"
        
        # Clean up resources
        if enclave_id in self.attestation_documents:
            del self.attestation_documents[enclave_id]
        
        # Simulate termination time
        time.sleep(0.1)
        self.enclaves[enclave_id]["state"] = "TERMINATED"
        
        return {
            "EnclaveID": enclave_id,
            "State": "TERMINATED"
        }
    
    def generate_attestation_document(self, 
                                    enclave_id: str,
                                    user_data: Optional[bytes] = None,
                                    nonce: Optional[bytes] = None) -> bytes:
        """Generate an attestation document for the enclave."""
        if enclave_id not in self.enclaves:
            raise AttestationError(f"Enclave '{enclave_id}' not found")
        
        if self.enclaves[enclave_id]["state"] != "RUNNING":
            raise AttestationError(f"Enclave '{enclave_id}' is not running")
        
        # Get existing or create new attestation document
        if enclave_id in self.attestation_documents:
            doc = self.attestation_documents[enclave_id]
            if user_data:
                doc.user_data = user_data
            if nonce:
                doc.nonce = nonce
        else:
            doc = MockAttestationDocument(enclave_id, user_data)
            self.attestation_documents[enclave_id] = doc
        
        return doc.to_cbor()
    
    def verify_attestation_document(self, 
                                  attestation_doc: bytes,
                                  expected_pcrs: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
        """Verify an attestation document."""
        try:
            # Decode mock CBOR (JSON + base64)
            json_data = base64.b64decode(attestation_doc).decode()
            document = json.loads(json_data)
            
            # Basic validation
            required_fields = ["module_id", "timestamp", "digest", "pcrs", "certificate"]
            for field in required_fields:
                if field not in document:
                    raise AttestationError(f"Missing required field: {field}")
            
            # Verify PCRs if provided
            if expected_pcrs:
                doc_pcrs = document["pcrs"]
                for pcr_index, expected_value in expected_pcrs.items():
                    if str(pcr_index) not in doc_pcrs:
                        raise AttestationError(f"PCR {pcr_index} not found in document")
                    if doc_pcrs[str(pcr_index)] != expected_value:
                        raise AttestationError(f"PCR {pcr_index} verification failed")
            
            return {
                "valid": True,
                "module_id": document["module_id"],
                "timestamp": document["timestamp"],
                "pcrs": document["pcrs"],
                "user_data": document.get("user_data")
            }
            
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise AttestationError(f"Invalid attestation document: {e}")
    
    def create_vsock_connection(self, cid: int, port: int) -> MockVSockConnection:
        """Create a VSOCK connection to an enclave."""
        connection = MockVSockConnection(cid, port)
        self.vsock_connections[(cid, port)] = connection
        return connection
    
    def get_vsock_connection(self, cid: int, port: int) -> Optional[MockVSockConnection]:
        """Get existing VSOCK connection."""
        return self.vsock_connections.get((cid, port))
    
    def close_vsock_connection(self, cid: int, port: int) -> None:
        """Close VSOCK connection."""
        if (cid, port) in self.vsock_connections:
            self.vsock_connections[(cid, port)].close()
            del self.vsock_connections[(cid, port)]
    
    def validate_enclave_environment(self) -> Dict[str, Any]:
        """Validate the enclave environment."""
        validation_results = {
            "valid": True,
            "checks": {},
            "warnings": []
        }
        
        # Check NSM device
        nsm_path = self.environment_variables.get("NSM_DEVICE_PATH", "/dev/nsm")
        validation_results["checks"]["nsm_device"] = {
            "path": nsm_path,
            "accessible": True  # Mock as accessible
        }
        
        # Check VSOCK configuration
        vsock_cid = self.environment_variables.get("VSOCK_CID", "16")
        vsock_port = self.environment_variables.get("VSOCK_PORT", "5000")
        validation_results["checks"]["vsock"] = {
            "cid": int(vsock_cid),
            "port": int(vsock_port),
            "available": True
        }
        
        # Check memory and CPU
        validation_results["checks"]["resources"] = {
            "cpu_count": 2,
            "memory_mib": 512,
            "sufficient": True
        }
        
        return validation_results
    
    def get_enclave_metrics(self, enclave_id: str) -> Dict[str, Any]:
        """Get performance metrics for an enclave."""
        if enclave_id not in self.enclaves:
            raise NitroEnclaveError(f"Enclave '{enclave_id}' not found")
        
        # Mock performance metrics
        return {
            "cpu_utilization": secrets.randbelow(80) + 10,  # 10-90%
            "memory_usage_mib": secrets.randbelow(256) + 128,  # 128-384 MiB
            "network_rx_bytes": secrets.randbelow(1000000),
            "network_tx_bytes": secrets.randbelow(1000000),
            "uptime_seconds": int(time.time() - self.enclaves[enclave_id]["created_at"].timestamp())
        }
    
    def simulate_kmstool_call(self, 
                             operation: str,
                             ciphertext: Optional[str] = None,
                             credentials: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Simulate kmstool_enclave_cli call."""
        if operation != "decrypt":
            raise NitroEnclaveError(f"Unsupported operation: {operation}")
        
        if not ciphertext:
            raise NitroEnclaveError("Ciphertext is required for decrypt operation")
        
        if not credentials:
            raise NitroEnclaveError("AWS credentials are required")
        
        # Mock successful decryption
        # In real implementation, this would call actual KMS
        test_key = secrets.token_bytes(32)  # 32-byte key
        encoded_key = base64.standard_b64encode(test_key).decode()
        
        return {
            "success": True,
            "plaintext": test_key,
            "plaintext_b64": encoded_key,
            "key_id": "mock-key-id",
            "algorithm": "SYMMETRIC_DEFAULT"
        }
    
    def set_environment_variable(self, key: str, value: str) -> None:
        """Set an environment variable for the enclave."""
        self.environment_variables[key] = value
    
    def get_environment_variable(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get an environment variable value."""
        return self.environment_variables.get(key, default)
    
    def simulate_error(self, error_type: str, enclave_id: Optional[str] = None) -> None:
        """Simulate various error conditions for testing."""
        if error_type == "enclave_not_found" and enclave_id:
            if enclave_id in self.enclaves:
                del self.enclaves[enclave_id]
        elif error_type == "enclave_crashed" and enclave_id:
            if enclave_id in self.enclaves:
                self.enclaves[enclave_id]["state"] = "CRASHED"
        elif error_type == "attestation_failure":
            # This will be handled by attestation operations
            pass
        elif error_type == "vsock_connection_failed":
            # Clear all VSOCK connections
            for conn in self.vsock_connections.values():
                conn.close()
            self.vsock_connections.clear()


class MockNitroEnclavePatches:
    """Helper class for patching Nitro Enclave related functionality."""
    
    def __init__(self, mock_service: MockNitroEnclaveService):
        self.mock_service = mock_service
        self.patches = []
    
    def patch_subprocess_popen(self):
        """Patch subprocess.Popen for kmstool_enclave_cli calls."""
        def mock_popen(*args, **kwargs):
            # Extract command arguments
            if args and len(args[0]) > 1:
                cmd_args = args[0]
                if "kmstool_enclave_cli" in cmd_args[0] and "decrypt" in cmd_args:
                    # Find ciphertext argument
                    ciphertext = None
                    credentials = {}
                    
                    for i, arg in enumerate(cmd_args):
                        if arg == "--ciphertext" and i + 1 < len(cmd_args):
                            ciphertext = cmd_args[i + 1]
                        elif arg == "--aws-access-key-id" and i + 1 < len(cmd_args):
                            credentials["access_key_id"] = cmd_args[i + 1]
                        elif arg == "--aws-secret-access-key" and i + 1 < len(cmd_args):
                            credentials["secret_access_key"] = cmd_args[i + 1]
                        elif arg == "--aws-session-token" and i + 1 < len(cmd_args):
                            credentials["token"] = cmd_args[i + 1]
                    
                    # Simulate kmstool call
                    try:
                        result = self.mock_service.simulate_kmstool_call(
                            "decrypt", ciphertext, credentials
                        )
                        
                        mock_process = Mock()
                        mock_process.returncode = 0
                        mock_process.communicate.return_value = (
                            f"PLAINTEXT:{result['plaintext_b64']}".encode(),
                            b""
                        )
                        return mock_process
                        
                    except Exception as e:
                        mock_process = Mock()
                        mock_process.returncode = 1
                        mock_process.communicate.return_value = (
                            b"",
                            f"KMS decryption failed: {str(e)}".encode()
                        )
                        return mock_process
            
            # Default mock for other subprocess calls
            mock_process = Mock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"", b"")
            return mock_process
        
        patch_obj = patch('subprocess.Popen', side_effect=mock_popen)
        self.patches.append(patch_obj)
        return patch_obj
    
    def patch_socket_vsock(self):
        """Patch socket operations for VSOCK communication."""
        def mock_socket(family, type_, proto=0):
            if family == socket.AF_VSOCK:
                mock_sock = Mock()
                # Configure VSOCK socket behavior
                mock_sock.bind.return_value = None
                mock_sock.listen.return_value = None
                mock_sock.connect.return_value = None
                mock_sock.send.return_value = 1024
                mock_sock.recv.return_value = b"mock_response"
                mock_sock.close.return_value = None
                return mock_sock
            
            # Return regular socket for other families
            return socket.socket(family, type_, proto)
        
        patch_obj = patch('socket.socket', side_effect=mock_socket)
        self.patches.append(patch_obj)
        return patch_obj
    
    def patch_environment_checks(self):
        """Patch environment validation functions."""
        def mock_path_exists(path: str) -> bool:
            # Mock NSM device and other paths as existing
            if "/dev/nsm" in path or "/app/kmstool_enclave_cli" in path:
                return True
            return os.path.exists(path)
        
        patch_obj = patch('os.path.exists', side_effect=mock_path_exists)
        self.patches.append(patch_obj)
        return patch_obj
    
    def start_all_patches(self):
        """Start all patches."""
        for patch_obj in self.patches:
            patch_obj.start()
    
    def stop_all_patches(self):
        """Stop all patches."""
        for patch_obj in self.patches:
            patch_obj.stop()
    
    def __enter__(self):
        self.start_all_patches()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_all_patches()


def create_nitro_enclave_mock(region: str = "us-east-1") -> MockNitroEnclaveService:
    """Create a configured Nitro Enclave mock for testing."""
    mock_service = MockNitroEnclaveService(region)
    
    # Add additional test enclaves
    starknet_enclave = mock_service.create_enclave(
        "/app/starknet_enclave.eif",
        cpu_count=4,
        memory_mib=1024,
        debug_mode=True
    )
    
    # Store test data as service attributes for easy access
    mock_service.test_enclave_id = starknet_enclave["EnclaveID"]
    mock_service.test_enclave_cid = starknet_enclave["EnclaveCID"]
    
    return mock_service


# Integration helpers
def patch_nitro_enclave_environment(mock_service: MockNitroEnclaveService):
    """Patch the entire Nitro Enclave environment for testing."""
    patches = MockNitroEnclavePatches(mock_service)
    patches.patch_subprocess_popen()
    patches.patch_socket_vsock()
    patches.patch_environment_checks()
    
    return patches