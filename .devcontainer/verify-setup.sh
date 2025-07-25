#!/bin/bash
# DevContainer setup verification script

echo "🔍 Verifying DevContainer setup..."
echo "================================="

# Check Python version
echo "📍 Python version:"
python --version

# Check pip packages
echo ""
echo "📦 Checking critical packages:"
packages=("web3" "boto3" "pytest" "moto")
for pkg in "${packages[@]}"; do
    if python -c "import $pkg" 2>/dev/null; then
        echo "  ✅ $pkg - installed"
    else
        echo "  ❌ $pkg - missing"
    fi
done

# Check environment variables
echo ""
echo "🌍 Environment variables:"
vars=("AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_DEFAULT_REGION")
for var in "${vars[@]}"; do
    if [ -n "${!var}" ]; then
        echo "  ✅ $var = ${!var}"
    else
        echo "  ❌ $var - not set"
    fi
done

# Check workspace structure
echo ""
echo "📁 Workspace structure:"
if [ -d "/workspaces/aws-nitro-enclave-blockchain-wallet/tests" ]; then
    echo "  ✅ Tests directory exists"
else
    echo "  ❌ Tests directory missing"
fi

if [ -f "/workspaces/aws-nitro-enclave-blockchain-wallet/Makefile" ]; then
    echo "  ✅ Makefile exists"
else
    echo "  ❌ Makefile missing"
fi

# Test basic imports
echo ""
echo "🧪 Testing basic imports:"
cd /workspaces/aws-nitro-enclave-blockchain-wallet

if python -c "import sys; sys.path.insert(0, './tests'); import conftest; print('conftest imports successfully')" 2>/dev/null; then
    echo "  ✅ Test configuration imports"
else
    echo "  ❌ Test configuration has import issues"
fi

echo ""
echo "🎯 Quick test run:"
if make --version >/dev/null 2>&1; then
    echo "  ✅ Make is available"
    echo "  📋 Available test commands:"
    echo "    make test-unit      # Run unit tests"
    echo "    make test           # Run all tests"
    echo "    make test-coverage  # Run with coverage"
else
    echo "  ❌ Make is not available"
fi

echo ""
echo "✅ Setup verification completed!"
echo "Run 'make test-unit' to run the unit tests."