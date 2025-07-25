# Minimal AWS Nitro Enclave Blockchain Wallet Development Container
FROM mcr.microsoft.com/vscode/devcontainers/python:3.11

# Set environment variables
ENV PYTHONPATH=/workspace
ENV AWS_DEFAULT_REGION=us-east-1

# Create mock kmstool for testing
RUN mkdir -p /app && \
    printf '#!/bin/bash\nif [ "$1" = "decrypt" ]; then\n    echo "PlaintextBlob:$(echo "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" | base64 -w 0)"\nelse\n    echo "Unknown operation: $1" >&2\n    exit 1\nfi\n' > /app/kmstool_enclave_cli && \
    chmod +x /app/kmstool_enclave_cli

# Set up workspace
WORKDIR /workspace

# Switch to vscode user
USER vscode