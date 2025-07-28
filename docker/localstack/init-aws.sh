#!/bin/bash

# LocalStack initialization script for Heimdall
# This script sets up the necessary AWS resources for local development

echo "Starting LocalStack initialization for Heimdall..."

# Wait for LocalStack to be ready
echo "Waiting for LocalStack to be ready..."
until curl -s http://localhost:4566/_localstack/health | grep -q '"kms": "available"'; do
    echo "Waiting for LocalStack KMS service..."
    sleep 2
done

# Create KMS key for master seed encryption
echo "Creating KMS key for master seed encryption..."
aws --endpoint-url=http://localhost:4566 kms create-key \
    --region us-east-1 \
    --description "Heimdall Master Seed Encryption Key" \
    --key-usage ENCRYPT_DECRYPT \
    --key-spec SYMMETRIC_DEFAULT > /tmp/kms-key.json

KMS_KEY_ID=$(cat /tmp/kms-key.json | jq -r '.KeyMetadata.KeyId')
echo "Created KMS key: $KMS_KEY_ID"

# Create alias for the KMS key
aws --endpoint-url=http://localhost:4566 kms create-alias \
    --region us-east-1 \
    --alias-name alias/heimdall-master-seed \
    --target-key-id $KMS_KEY_ID

echo "Created KMS key alias: alias/heimdall-master-seed"

# Create master seed secret in Secrets Manager
echo "Creating master seed secret..."
MASTER_SEED=$(openssl rand -hex 32)
aws --endpoint-url=http://localhost:4566 secretsmanager create-secret \
    --region us-east-1 \
    --name heimdall/master-seed \
    --description "Heimdall master seed for key derivation" \
    --secret-string "$MASTER_SEED"

echo "Created master seed secret: heimdall/master-seed"

# Create test user session secrets
echo "Creating test user session secrets..."
for i in {1..5}; do
    TEST_SESSION=$(openssl rand -hex 16)
    aws --endpoint-url=http://localhost:4566 secretsmanager create-secret \
        --region us-east-1 \
        --name "heimdall/test-user-$i/session" \
        --description "Test user $i session data" \
        --secret-string "{\"user_id\":\"test-user-$i\",\"session_token\":\"$TEST_SESSION\",\"expires_at\":\"2025-12-31T23:59:59Z\"}"
done

echo "LocalStack initialization completed successfully!"
echo "Available resources:"
echo "  - KMS Key: $KMS_KEY_ID (alias: alias/heimdall-master-seed)"
echo "  - Master seed secret: heimdall/master-seed"
echo "  - Test user sessions: heimdall/test-user-{1-5}/session"