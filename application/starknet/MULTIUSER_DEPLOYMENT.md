# Multi-User Starknet Key Derivation System - Deployment Guide

This guide provides comprehensive instructions for deploying the multi-user Starknet key derivation system in AWS Nitro Enclaves.

## Overview

The multi-user system extends the original single-user architecture to support deterministic key derivation for multiple users from a single master seed stored in AWS KMS. Each user gets unique, reproducible Starknet private keys based on their username.

## Architecture Components

### 1. Key Derivation System
- **Master Seed**: 32-byte seed stored encrypted in AWS KMS
- **HKDF Implementation**: RFC 5869 compliant key derivation
- **User Isolation**: Cryptographically separated key spaces per user
- **Validation**: Ensures all derived keys are valid for Starknet curve

### 2. AWS Integration Layer
- **KMS Integration**: Secure master seed decryption in enclave
- **Session Management**: User authentication and session validation
- **Performance Monitoring**: Metrics collection and audit logging

### 3. Server Components
- **Enclave Server**: `multiuser_server.py` - Handles key derivation in secure enclave
- **Parent Server**: `multiuser_app.py` - HTTP API for multi-user operations
- **Legacy Support**: Backward compatibility with single-user format

## Prerequisites

### AWS Resources
- AWS KMS key for master seed encryption
- AWS Secrets Manager for master seed storage
- EC2 instance with Nitro Enclave support
- IAM roles with appropriate permissions

### Required Permissions

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": "arn:aws:kms:region:account:key/your-kms-key-id",
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "secretsmanager.region.amazonaws.com"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:region:account:secret:starknet-master-seed-*"
        }
    ]
}
```

## Step-by-Step Deployment

### Step 1: Generate and Store Master Seed

```bash
# Generate a secure master seed
python3 -c "
import secrets
import base64
master_seed = secrets.token_bytes(32)
print('Master seed (base64):', base64.b64encode(master_seed).decode())
print('Master seed (hex):', master_seed.hex())
"

# Store in AWS Secrets Manager
aws secretsmanager create-secret \
    --name "starknet-master-seed" \
    --description "Master seed for Starknet multi-user key derivation" \
    --secret-string "$(echo -n 'your_generated_master_seed_here' | base64)"
```

### Step 2: Update Enclave Configuration

Update the enclave Dockerfile to include the new modules:

```dockerfile
# Add to application/starknet/enclave/Dockerfile
COPY key_derivation.py /app/
COPY aws_multiuser_integration.py /app/
COPY multiuser_server.py /app/

# Set the new server as entrypoint
CMD ["python3", "/app/multiuser_server.py"]
```

### Step 3: Update Requirements

Add to `application/starknet/enclave/requirements.txt`:

```
starknet-py==0.21.0
cryptography>=3.4.8
```

### Step 4: Update Parent EC2 Configuration

Update the server Dockerfile:

```dockerfile
# Add to application/starknet/server/Dockerfile
COPY multiuser_app.py /app/

# Environment variables
ENV MASTER_SEED_SECRET_ID=starknet-master-seed
ENV SESSION_TIMEOUT=3600
ENV LEGACY_MODE=false
```

### Step 5: Deploy Infrastructure

Using the existing CDK:

```python
# Add to nitro_wallet_stack.py
class NitroStarknetMultiUserStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # KMS key for master seed
        kms_key = kms.Key(
            self, "StarknetMasterSeedKey",
            description="KMS key for Starknet master seed encryption",
            key_policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AccountRootPrincipal()],
                        actions=["kms:*"],
                        resources=["*"]
                    )
                ]
            )
        )
        
        # Update existing infrastructure with new permissions
        # ... (add KMS and Secrets Manager permissions to enclave role)
```

### Step 6: Build and Deploy

```bash
# Build enclave image
cd application/starknet/enclave
docker build -t starknet-multiuser-enclave .

# Build and convert to EIF
nitro-cli build-enclave \
    --docker-uri starknet-multiuser-enclave:latest \
    --output-file starknet-multiuser.eif

# Deploy to EC2
scp starknet-multiuser.eif ec2-user@your-instance:/opt/
```

## Configuration Options

### Environment Variables

#### Enclave Environment
- `REGION`: AWS region (default: us-east-1)
- `NITRO_ENCLAVE`: Set to "true" for validation

#### Parent Server Environment
- `MASTER_SEED_SECRET_ID`: Secrets Manager secret ID
- `SESSION_TIMEOUT`: Session timeout in seconds (default: 3600)
- `LEGACY_MODE`: Enable backward compatibility (default: false)
- `PORT`: Server port (default: 443)

### Master Seed Configuration

The master seed must be exactly 32 bytes and stored base64-encoded in AWS Secrets Manager. 

**Security Requirements:**
- Generated using cryptographically secure random number generator
- Never stored in plaintext outside of KMS/Secrets Manager
- Access restricted through IAM policies and enclave attestation

## API Reference

### Multi-User Operations

#### Sign Transaction
```bash
curl -X POST https://your-server/sign \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "operation": "sign_transaction",
    "key_index": 0,
    "transaction_payload": {
      "contract_address": "0x123...",
      "function_name": "transfer",
      "calldata": [1000, 0],
      "max_fee": "0x1000000000000",
      "nonce": 1,
      "chain_id": "testnet"
    }
  }'
```

#### Get Account Info
```bash
curl -X POST https://your-server/account \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "operation": "get_account_info",
    "key_index": 0
  }'
```

#### Derive Key (Public Info Only)
```bash
curl -X POST https://your-server/derive \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice", 
    "operation": "derive_key",
    "key_index": 0
  }'
```

### Response Format

```json
{
  "success": true,
  "username": "alice",
  "key_index": 0,
  "account_address": "0x789...",
  "transaction_hash": "0xabc...",
  "transaction_signed": "0x123...,0x456...",
  "contract_address": "0x123...",
  "function_name": "transfer",
  "calldata": [1000, 0],
  "max_fee": "0x1000000000000",
  "nonce": 1
}
```

## Security Considerations

### 1. Master Seed Protection
- **Storage**: Never store master seed in plaintext
- **Access**: Restrict access through IAM policies and KMS key policies
- **Rotation**: Implement master seed rotation procedures
- **Backup**: Secure backup and recovery procedures

### 2. User Isolation
- **Cryptographic Separation**: HKDF ensures user key spaces are isolated
- **Session Management**: Validate user sessions and prevent cross-user access
- **Audit Logging**: Log all key access operations for security monitoring

### 3. Enclave Security
- **Attestation**: Verify enclave measurements before deployment
- **Memory Protection**: Secure cleanup of sensitive data
- **Network Isolation**: Enclave communicates only via VSOCK

### 4. Key Validation
- **Curve Validation**: All derived keys validated against Starknet curve order
- **Entropy Checking**: Monitor key entropy for quality assurance
- **Deterministic Behavior**: Ensure reproducible key derivation

## Monitoring and Maintenance

### Performance Metrics
- Key derivation rate (keys/second)
- Memory usage patterns
- Error rates and failure analysis
- User session statistics

### Health Checks
```bash
# Server health
curl https://your-server/health

# Performance metrics  
curl https://your-server/metrics
```

### Log Analysis
Monitor logs for:
- Failed key derivations
- Invalid user sessions
- Performance bottlenecks
- Security events

### Backup and Recovery

#### Master Seed Backup
```bash
# Export encrypted master seed (for disaster recovery)
aws secretsmanager get-secret-value \
    --secret-id starknet-master-seed \
    --query 'SecretString' \
    --output text > master-seed-backup.enc
```

#### Key Derivation Testing
```bash
# Test key derivation for critical users
python3 -c "
from key_derivation import create_test_master_seed, StarknetMultiUserKeyManager
import base64

# Use production master seed (securely obtained)
master_seed = base64.b64decode('your_master_seed_here')
manager = StarknetMultiUserKeyManager(master_seed)

# Test critical users
test_users = ['alice', 'bob', 'critical_service']
for user in test_users:
    key, addr = manager.derive_user_key(user)
    print(f'{user}: {hex(addr)}')
"
```

## Troubleshooting

### Common Issues

#### 1. KMS Decryption Failures
- Verify IAM permissions
- Check KMS key policy
- Validate enclave attestation

#### 2. Invalid Key Derivation
- Verify master seed integrity
- Check username format
- Validate curve parameters

#### 3. Performance Issues
- Monitor memory usage
- Check concurrent user limits
- Analyze key derivation patterns

#### 4. Session Validation Errors
- Check session timeout configuration
- Verify timestamp accuracy
- Validate session data format

### Debug Commands

```bash
# Test enclave connectivity
nitro-cli describe-enclaves

# Check server logs
sudo journalctl -u starknet-multiuser -f

# Test key derivation locally (development only)
python3 -m pytest tests/test_multiuser_key_derivation.py -v

# Monitor resource usage
htop
iostat -x 1
```

## Performance Tuning

### Key Derivation Optimization
- Cache frequently accessed user keys
- Implement batched key derivation
- Optimize HKDF implementation

### Memory Management
- Monitor memory usage patterns
- Implement periodic garbage collection
- Set appropriate cache limits

### Concurrent Access
- Tune thread pool sizes
- Implement rate limiting
- Monitor connection patterns

## Migration from Single-User

### Gradual Migration Strategy

1. **Deploy Both Systems**: Run multi-user alongside single-user
2. **User-by-User Migration**: Migrate users gradually
3. **Legacy API Support**: Maintain backward compatibility
4. **Validation**: Compare key derivation results
5. **Cutover**: Switch to multi-user system

### Migration Script Example

```python
#!/usr/bin/env python3
"""
Migration script for single-user to multi-user system.
"""

def migrate_user_from_secrets_manager(username: str, secret_id: str):
    """Migrate a user from individual secret to master seed derivation."""
    
    # Get old key from Secrets Manager
    old_key = get_secret_value(secret_id)
    
    # Derive new key from master seed  
    manager = StarknetMultiUserKeyManager(master_seed)
    new_key, new_address = manager.derive_user_key(username)
    
    print(f"User: {username}")
    print(f"Old key: {hex(old_key)}")
    print(f"New key: {hex(new_key)}")
    print(f"New address: {hex(new_address)}")
    
    return new_key, new_address

# Run migration for all users
users_to_migrate = [
    ("alice", "alice-starknet-key"),
    ("bob", "bob-starknet-key"),
    # ... add all users
]

for username, secret_id in users_to_migrate:
    migrate_user_from_secrets_manager(username, secret_id)
```

## Appendix

### A. Key Derivation Algorithm Details

The system uses HKDF (RFC 5869) with the following parameters:
- **Hash Function**: SHA-256
- **Salt**: SHA-256(f"starknet_user_{username}_{key_index}")
- **Info**: f"starknet_private_key_v1_attempt_{attempt}"
- **Key Length**: 32 bytes

### B. Starknet Curve Parameters

```python
STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001
STARK_ORDER = 0x800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F
```

### C. Testing Checklist

- [ ] Master seed generation and storage
- [ ] KMS integration and permissions
- [ ] Key derivation correctness
- [ ] User isolation validation
- [ ] Concurrent access testing
- [ ] Performance benchmarking
- [ ] Security audit
- [ ] Documentation review

### D. Support and Maintenance

For ongoing support:
1. Monitor system metrics and logs
2. Regular security assessments
3. Performance optimization
4. Master seed rotation procedures
5. Disaster recovery testing

---

For additional support or questions about the multi-user deployment, refer to the main project documentation or contact the development team.