#!/bin/bash
# DevContainer setup script

set -e

echo "🚀 Setting up AWS Nitro Enclave Blockchain Wallet development environment..."

# Install CDK
echo "📦 Installing AWS CDK..."
npm install -g aws-cdk@2.98.0

# Update pip
echo "🐍 Updating pip..."
pip install --upgrade pip

# Install core requirements
echo "📚 Installing core requirements..."
pip install -r requirements.txt -r requirements-dev.txt

# Install additional testing dependencies (most are now in requirements-dev.txt)
echo "🧪 Installing any additional testing dependencies..."
# Most dependencies are now in requirements-dev.txt, but ensure critical ones are available
pip install web3>=5.23.0 boto3>=1.28.0

# Make mock kmstool executable
echo "🔧 Setting up mock kmstool..."
chmod +x /app/kmstool_enclave_cli

# Make verification script executable
chmod +x .devcontainer/verify-setup.sh

# Setup git safe directory
echo "🔐 Configuring git..."
git config --global --add safe.directory /workspaces/aws-nitro-enclave-blockchain-wallet

# Create test directories
echo "📁 Creating test directories..."
mkdir -p tests/fixtures

# Set environment variables (add to bashrc for persistence)
echo "🌍 Setting environment variables..."
cat >> ~/.bashrc << 'EOF'

# AWS testing environment variables
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing
export AWS_DEFAULT_REGION=us-east-1
export AWS_SECURITY_TOKEN=testing
export AWS_SESSION_TOKEN=testing
EOF

# Also set for current session
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing
export AWS_DEFAULT_REGION=us-east-1
export AWS_SECURITY_TOKEN=testing
export AWS_SESSION_TOKEN=testing

echo "✅ DevContainer setup completed successfully!"
echo ""
echo "🔥 Quick start commands:"
echo "  .devcontainer/verify-setup.sh  # Verify everything is working"
echo "  make test          # Run all tests"
echo "  make test-unit     # Run unit tests only"  
echo "  make setup-dev     # Install pre-commit hooks"
echo "  make lint          # Run linting"
echo "  cdk synth          # Synthesize CDK templates"
echo ""
echo "If you encounter import errors, run the verification script first!"