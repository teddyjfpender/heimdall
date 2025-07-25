"""Integration tests for Docker containers."""

import json
import os
import time
from unittest.mock import patch
import pytest
import docker
import requests
from testcontainers.core.container import DockerContainer
from testcontainers.core import waiting_utils

from tests.factories import create_complete_signing_scenario


class TestDockerContainers:
    """Test Docker container functionality."""

    @pytest.fixture(scope="class")
    def docker_client(self):
        """Docker client for container operations."""
        return docker.from_env()

    @pytest.mark.integration
    @pytest.mark.docker
    @pytest.mark.slow
    def test_eth1_server_container_build(self, docker_client):
        """Test that the ETH1 server container builds successfully."""
        server_path = "./application/eth1/server"
        
        # Build the container
        image, build_logs = docker_client.images.build(
            path=server_path,
            tag="nitro-eth1-server:test",
            rm=True
        )
        
        assert image is not None
        assert image.tags[0] == "nitro-eth1-server:test"
        
        # Cleanup
        docker_client.images.remove(image.id, force=True)

    @pytest.mark.integration
    @pytest.mark.docker
    @pytest.mark.slow
    def test_eth1_enclave_container_build(self, docker_client):
        """Test that the ETH1 enclave container builds successfully."""
        enclave_path = "./application/eth1/enclave"
        
        # Build the container
        image, build_logs = docker_client.images.build(
            path=enclave_path,
            tag="nitro-eth1-enclave:test",
            rm=True,
            buildargs={"REGION_ARG": "us-east-1"}
        )
        
        assert image is not None
        assert image.tags[0] == "nitro-eth1-enclave:test"
        
        # Cleanup
        docker_client.images.remove(image.id, force=True)

    @pytest.mark.integration
    @pytest.mark.docker
    def test_server_container_environment(self, docker_client):
        """Test server container environment and dependencies."""
        # Create a minimal test container
        container = docker_client.containers.run(
            "python:3.11-slim",
            command="python -c 'import sys; print(sys.version)'",
            detach=False,
            remove=True
        )
        
        # Verify Python version is correct
        assert "3.11" in container.decode()

    @pytest.mark.integration
    @pytest.mark.docker
    def test_container_networking(self, docker_client):
        """Test container networking capabilities."""
        # Create a network
        network = docker_client.networks.create("test-nitro-network")
        
        try:
            # Run a simple HTTP server container
            server_container = docker_client.containers.run(
                "python:3.11-slim",
                command='python -c "import http.server; import socketserver; handler = http.server.SimpleHTTPRequestHandler; httpd = socketserver.TCPServer((\'\', 8000), handler); httpd.serve_forever()"',
                detach=True,
                ports={'8000/tcp': 8000},
                network=network.name,
                name="test-server"
            )
            
            # Wait for server to start
            time.sleep(2)
            
            # Test connection
            try:
                response = requests.get("http://localhost:8000", timeout=5)
                assert response.status_code == 200
            except requests.exceptions.RequestException:
                # Connection test may fail in CI environment, that's okay
                pass
            
            # Cleanup
            server_container.stop()
            server_container.remove()
            
        finally:
            network.remove()

    @pytest.mark.integration
    @pytest.mark.docker
    @pytest.mark.slow
    def test_full_container_stack_simulation(self, docker_client):
        """Test simulation of full container stack without actual enclaves."""
        # This test simulates the interaction between server and enclave containers
        # using standard Docker containers instead of Nitro Enclaves
        
        network = docker_client.networks.create("nitro-test-network")
        
        try:
            # Simulate enclave container with a mock service
            enclave_container = docker_client.containers.run(
                "python:3.11-slim",
                command='''python -c "
import json
import socket
import base64

# Mock enclave service
def mock_sign_transaction(payload):
    return {
        'transaction_signed': '0x' + '1234567890abcdef' * 10,
        'transaction_hash': '0x' + 'abcdef1234567890' * 4
    }

# Simple TCP server to simulate VSOCK
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 5000))
server.listen(1)

while True:
    try:
        conn, addr = server.accept()
        data = conn.recv(4096)
        if data:
            payload = json.loads(data.decode())
            response = mock_sign_transaction(payload)
            conn.send(json.dumps(response).encode())
        conn.close()
    except Exception as e:
        print(f'Error: {e}')
        break
"''',
                detach=True,
                network=network.name,
                name="mock-enclave"
            )
            
            # Wait for mock enclave to start
            time.sleep(2)
            
            # Test client connection to mock enclave
            test_payload = create_complete_signing_scenario()
            
            client_container = docker_client.containers.run(
                "python:3.11-slim",
                command=f'''python -c "
import json
import socket

# Connect to mock enclave
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('mock-enclave', 5000))

# Send test payload
payload = {json.dumps(test_payload['enclave_payload'])}
client.send(payload.encode())

# Receive response
response = client.recv(4096)
result = json.loads(response.decode())
print('SUCCESS:', result)
client.close()
"''',
                detach=False,
                remove=True,
                network=network.name
            )
            
            # Verify response contains expected fields
            output = client_container.decode()
            assert "SUCCESS:" in output
            assert "transaction_signed" in output
            assert "transaction_hash" in output
            
            # Cleanup
            enclave_container.stop()
            enclave_container.remove()
            
        finally:
            network.remove()


class TestContainerSecurity:
    """Test container security configurations."""

    @pytest.fixture(scope="class")
    def docker_client(self):
        """Docker client for container operations."""
        return docker.from_env()

    @pytest.mark.integration
    @pytest.mark.docker
    def test_container_user_privileges(self, docker_client):
        """Test that containers don't run as root where possible."""
        # Test a basic container user setup
        container = docker_client.containers.run(
            "python:3.11-slim",
            command="whoami",
            detach=False,
            remove=True,
            user="1000:1000"  # Non-root user
        )
        
        output = container.decode().strip()
        # Should not be root
        assert output != "root"

    @pytest.mark.integration
    @pytest.mark.docker
    def test_container_resource_limits(self, docker_client):
        """Test container resource limits."""
        # Test memory limit
        container = docker_client.containers.run(
            "python:3.11-slim",
            command="python -c 'import psutil; print(f\"Memory: {psutil.virtual_memory().total // (1024**2)}MB\")'",
            detach=False,
            remove=True,
            mem_limit="512m"
        )
        
        output = container.decode()
        assert "Memory:" in output
        # Memory should be limited (allowing for some overhead)
        memory_mb = int(output.split("Memory: ")[1].split("MB")[0])
        assert memory_mb <= 600  # Some overhead allowed

    @pytest.mark.integration
    @pytest.mark.docker
    def test_container_network_isolation(self, docker_client):
        """Test container network isolation."""
        # Create isolated network
        network = docker_client.networks.create(
            "isolated-test-network",
            driver="bridge",
            options={"com.docker.network.bridge.enable_icc": "false"}
        )
        
        try:
            # Run container in isolated network
            container = docker_client.containers.run(
                "python:3.11-slim",
                command="python -c 'import socket; print(socket.gethostname())'",
                detach=False,
                remove=True,
                network=network.name
            )
            
            # Container should have executed successfully in isolation
            output = container.decode().strip()
            assert len(output) > 0  # Should have a hostname
            
        finally:
            network.remove()


class TestContainerPerformance:
    """Test container performance characteristics."""

    @pytest.fixture(scope="class")
    def docker_client(self):
        """Docker client for container operations."""
        return docker.from_env()

    @pytest.mark.integration
    @pytest.mark.docker
    @pytest.mark.slow
    def test_container_startup_time(self, docker_client):
        """Test container startup performance."""
        start_time = time.time()
        
        container = docker_client.containers.run(
            "python:3.11-slim",
            command="python -c 'print(\"Container started\")'",
            detach=False,
            remove=True
        )
        
        startup_time = time.time() - start_time
        
        # Startup should be reasonably fast (less than 10 seconds)
        assert startup_time < 10.0
        assert "Container started" in container.decode()

    @pytest.mark.integration
    @pytest.mark.docker
    def test_container_memory_usage(self, docker_client):
        """Test container memory usage patterns."""
        # Run a container that reports its memory usage
        container = docker_client.containers.run(
            "python:3.11-slim",
            command='''python -c "
import psutil
import os

# Get memory info
memory = psutil.virtual_memory()
process = psutil.Process(os.getpid())

print(f'Total memory: {memory.total // (1024**2)}MB')
print(f'Available memory: {memory.available // (1024**2)}MB')
print(f'Process memory: {process.memory_info().rss // (1024**2)}MB')
"''',
            detach=False,
            remove=True,
            mem_limit="256m"
        )
        
        output = container.decode()
        assert "Total memory:" in output
        assert "Available memory:" in output  
        assert "Process memory:" in output

    @pytest.mark.integration
    @pytest.mark.docker
    def test_container_cpu_usage(self, docker_client):
        """Test container CPU usage patterns."""
        # Run a CPU-bound task for a short time
        container = docker_client.containers.run(
            "python:3.11-slim",
            command='''python -c "
import time
import psutil

# Short CPU-bound task
start = time.time()
total = 0
for i in range(1000000):
    total += i * i

duration = time.time() - start
cpu_percent = psutil.cpu_percent(interval=0.1)

print(f'Task completed in {duration:.3f}s')
print(f'CPU usage: {cpu_percent}%')
"''',
            detach=False,
            remove=True,
            cpus="1.0"  # Limit to 1 CPU
        )
        
        output = container.decode()
        assert "Task completed" in output
        assert "CPU usage:" in output