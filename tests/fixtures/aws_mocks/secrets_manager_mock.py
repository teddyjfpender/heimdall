"""
Comprehensive AWS Secrets Manager mock for local testing.

This module provides a realistic Secrets Manager mock that simulates AWS behavior
including secret storage, versioning, retrieval, and error conditions.
"""

import base64
import json
import secrets
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from unittest.mock import Mock, patch


class SecretsManagerMockError(Exception):
    """Base exception for Secrets Manager mock errors."""
    pass


class ResourceNotFoundError(SecretsManagerMockError):
    """Simulates AWS Secrets Manager ResourceNotFoundException."""
    pass


class InvalidParameterError(SecretsManagerMockError):
    """Simulates AWS Secrets Manager InvalidParameterException."""
    pass


class InvalidRequestError(SecretsManagerMockError):
    """Simulates AWS Secrets Manager InvalidRequestException."""
    pass


class AccessDeniedError(SecretsManagerMockError):
    """Simulates AWS Secrets Manager AccessDeniedException."""
    pass


class MockSecretVersion:
    """Represents a version of a secret."""
    
    def __init__(self, 
                 secret_value: Union[str, bytes, Dict[str, Any]], 
                 version_id: str,
                 version_stage: str = "AWSCURRENT"):
        self.version_id = version_id
        self.version_stage = version_stage
        self.created_date = datetime.now(timezone.utc)
        self.last_accessed_date = None
        
        # Store the secret value and determine its type
        if isinstance(secret_value, dict):
            self.secret_string = json.dumps(secret_value)
            self.secret_binary = None
        elif isinstance(secret_value, str):
            self.secret_string = secret_value
            self.secret_binary = None
        elif isinstance(secret_value, bytes):
            self.secret_string = None
            self.secret_binary = base64.b64encode(secret_value).decode()
        else:
            raise InvalidParameterError(f"Invalid secret value type: {type(secret_value)}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert version to dictionary representation."""
        result = {
            "VersionId": self.version_id,
            "VersionStages": [self.version_stage],
            "CreatedDate": self.created_date.isoformat()
        }
        
        if self.last_accessed_date:
            result["LastAccessedDate"] = self.last_accessed_date.isoformat()
            
        return result


class MockSecret:
    """Represents a mock secret with versions and metadata."""
    
    def __init__(self, name: str, region: str = "us-east-1"):
        self.name = name
        self.arn = f"arn:aws:secretsmanager:{region}:123456789012:secret:{name}"
        self.description = ""
        self.kms_key_id = None
        self.created_date = datetime.now(timezone.utc)
        self.last_changed_date = self.created_date
        self.last_accessed_date = None
        self.deleted_date = None
        self.tags: List[Dict[str, str]] = []
        self.versions: Dict[str, MockSecretVersion] = {}
        self.version_stages: Dict[str, str] = {}  # stage -> version_id mapping
        self.replica_regions: List[str] = []
        
    def add_version(self, 
                    secret_value: Union[str, bytes, Dict[str, Any]], 
                    version_stage: str = "AWSCURRENT") -> str:
        """Add a new version of the secret."""
        version_id = secrets.token_hex(16)
        
        # If adding AWSCURRENT, move existing AWSCURRENT to AWSPENDING
        if version_stage == "AWSCURRENT" and "AWSCURRENT" in self.version_stages:
            old_current_version_id = self.version_stages["AWSCURRENT"]
            if old_current_version_id in self.versions:
                self.versions[old_current_version_id].version_stage = "AWSPENDING"
                self.version_stages["AWSPENDING"] = old_current_version_id
        
        # Add the new version
        version = MockSecretVersion(secret_value, version_id, version_stage)
        self.versions[version_id] = version
        self.version_stages[version_stage] = version_id
        
        self.last_changed_date = datetime.now(timezone.utc)
        return version_id
    
    def get_version(self, version_id: Optional[str] = None, 
                    version_stage: Optional[str] = None) -> MockSecretVersion:
        """Get a specific version of the secret."""
        if version_id:
            if version_id not in self.versions:
                raise ResourceNotFoundError(f"Version '{version_id}' not found")
            version = self.versions[version_id]
        elif version_stage:
            if version_stage not in self.version_stages:
                raise ResourceNotFoundError(f"Version stage '{version_stage}' not found")
            version_id = self.version_stages[version_stage]
            version = self.versions[version_id]
        else:
            # Default to AWSCURRENT
            if "AWSCURRENT" not in self.version_stages:
                raise ResourceNotFoundError("No current version found")
            version_id = self.version_stages["AWSCURRENT"]
            version = self.versions[version_id]
        
        # Update last accessed date
        version.last_accessed_date = datetime.now(timezone.utc)
        self.last_accessed_date = version.last_accessed_date
        
        return version
    
    def list_versions(self) -> List[MockSecretVersion]:
        """List all versions of the secret."""
        return list(self.versions.values())
    
    def delete_version(self, version_id: str) -> None:
        """Delete a specific version."""
        if version_id not in self.versions:
            raise ResourceNotFoundError(f"Version '{version_id}' not found")
        
        version = self.versions[version_id]
        
        # Don't allow deletion of AWSCURRENT
        if version.version_stage == "AWSCURRENT":
            raise InvalidRequestError("Cannot delete the current version")
        
        # Remove from version stages mapping
        if version.version_stage in self.version_stages:
            del self.version_stages[version.version_stage]
        
        # Remove the version
        del self.versions[version_id]
    
    def to_dict(self, include_versions: bool = False) -> Dict[str, Any]:
        """Convert secret to dictionary representation."""
        result = {
            "ARN": self.arn,
            "Name": self.name,
            "Description": self.description,
            "CreatedDate": self.created_date.isoformat(),
            "LastChangedDate": self.last_changed_date.isoformat(),
            "Tags": self.tags
        }
        
        if self.kms_key_id:
            result["KmsKeyId"] = self.kms_key_id
            
        if self.last_accessed_date:
            result["LastAccessedDate"] = self.last_accessed_date.isoformat()
            
        if self.deleted_date:
            result["DeletedDate"] = self.deleted_date.isoformat()
            
        if self.replica_regions:
            result["ReplicationStatus"] = [
                {"Region": region, "Status": "InSync"}
                for region in self.replica_regions
            ]
        
        if include_versions:
            result["VersionIdsToStages"] = {
                version_id: [version.version_stage]
                for version_id, version in self.versions.items()
            }
        
        return result


class MockSecretsManagerService:
    """
    Comprehensive AWS Secrets Manager service mock.
    
    This mock provides realistic Secrets Manager behavior for testing, including:
    - Secret creation, storage, and retrieval
    - Version management with staging
    - JSON and binary secret support
    - Error simulation (not found, access denied, etc.)
    - Realistic response formats
    """
    
    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.secrets: Dict[str, MockSecret] = {}
        self.access_policies: Dict[str, Dict[str, Any]] = {}
        self._setup_default_secrets()
    
    def _setup_default_secrets(self):
        """Set up default test secrets."""
        # Database credentials
        db_secret = MockSecret("test/database/credentials", self.region)
        db_secret.description = "Test database credentials"
        db_credentials = {
            "username": "testuser",
            "password": "testpassword123",
            "engine": "mysql",
            "host": "localhost",
            "port": 3306,
            "dbname": "testdb"
        }
        db_secret.add_version(db_credentials)
        self.secrets[db_secret.name] = db_secret
        
        # API key secret
        api_secret = MockSecret("test/api/key", self.region)
        api_secret.description = "Test API key"
        api_secret.add_version("sk-test-api-key-123456789")
        self.secrets[api_secret.name] = api_secret
        
        # Binary secret (e.g., encryption key)
        binary_secret = MockSecret("test/encryption/key", self.region)
        binary_secret.description = "Test encryption key"
        binary_secret.add_version(secrets.randbits(256).to_bytes(32, 'big'))
        self.secrets[binary_secret.name] = binary_secret
        
        # Starknet-specific secrets
        starknet_secret = MockSecret("starknet/master-seed", self.region)
        starknet_secret.description = "Starknet master seed"
        starknet_secret.add_version(secrets.randbits(256).to_bytes(32, 'big'))
        self.secrets[starknet_secret.name] = starknet_secret
    
    def create_secret(self, 
                      name: str,
                      secret_value: Union[str, bytes, Dict[str, Any]],
                      description: Optional[str] = None,
                      kms_key_id: Optional[str] = None,
                      tags: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
        """Create a new secret."""
        if name in self.secrets:
            raise InvalidRequestError(f"Secret '{name}' already exists")
        
        secret = MockSecret(name, self.region)
        if description:
            secret.description = description
        if kms_key_id:
            secret.kms_key_id = kms_key_id
        if tags:
            secret.tags = tags
            
        version_id = secret.add_version(secret_value)
        self.secrets[name] = secret
        
        return {
            "ARN": secret.arn,
            "Name": name,
            "VersionId": version_id
        }
    
    def get_secret_value(self, 
                         secret_id: str,
                         version_id: Optional[str] = None,
                         version_stage: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve a secret value."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:GetSecretValue"):
            raise AccessDeniedError("Access denied for GetSecretValue operation")
        
        try:
            version = secret.get_version(version_id, version_stage)
        except ResourceNotFoundError:
            raise ResourceNotFoundError(f"Secret version not found for secret '{secret_id}'")
        
        result = {
            "ARN": secret.arn,
            "Name": secret.name,
            "VersionId": version.version_id,
            "VersionStages": [version.version_stage],
            "CreatedDate": version.created_date.isoformat()
        }
        
        if version.secret_string is not None:
            result["SecretString"] = version.secret_string
        if version.secret_binary is not None:
            result["SecretBinary"] = version.secret_binary
            
        return result
    
    def put_secret_value(self, 
                         secret_id: str,
                         secret_value: Union[str, bytes, Dict[str, Any]],
                         version_stages: Optional[List[str]] = None) -> Dict[str, Any]:
        """Update a secret value."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:PutSecretValue"):
            raise AccessDeniedError("Access denied for PutSecretValue operation")
        
        # Default to AWSCURRENT stage
        stage = version_stages[0] if version_stages else "AWSCURRENT"
        version_id = secret.add_version(secret_value, stage)
        
        return {
            "ARN": secret.arn,
            "Name": secret.name,
            "VersionId": version_id,
            "VersionStages": [stage]
        }
    
    def describe_secret(self, secret_id: str) -> Dict[str, Any]:
        """Describe a secret."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:DescribeSecret"):
            raise AccessDeniedError("Access denied for DescribeSecret operation")
            
        return secret.to_dict(include_versions=True)
    
    def list_secrets(self, 
                     max_results: Optional[int] = None,
                     filters: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """List secrets."""
        secrets_list = list(self.secrets.values())
        
        # Apply filters if provided
        if filters:
            for filter_item in filters:
                key = filter_item.get("Key")
                values = filter_item.get("Values", [])
                
                if key == "name":
                    secrets_list = [s for s in secrets_list if any(v in s.name for v in values)]
                elif key == "description":
                    secrets_list = [s for s in secrets_list if any(v in s.description for v in values)]
                elif key == "tag-key":
                    secrets_list = [s for s in secrets_list 
                                  if any(tag["Key"] in values for tag in s.tags)]
                elif key == "tag-value":
                    secrets_list = [s for s in secrets_list 
                                  if any(tag["Value"] in values for tag in s.tags)]
        
        # Apply pagination
        if max_results:
            secrets_list = secrets_list[:max_results]
        
        return {
            "SecretList": [secret.to_dict() for secret in secrets_list]
        }
    
    def delete_secret(self, 
                      secret_id: str,
                      recovery_window_in_days: Optional[int] = 30,
                      force_delete: bool = False) -> Dict[str, Any]:
        """Delete a secret."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:DeleteSecret"):
            raise AccessDeniedError("Access denied for DeleteSecret operation")
        
        if force_delete:
            # Immediately delete
            del self.secrets[secret_id]
            deletion_date = datetime.now(timezone.utc)
        else:
            # Schedule for deletion
            import datetime as dt
            deletion_date = datetime.now(timezone.utc) + dt.timedelta(days=recovery_window_in_days or 30)
            secret.deleted_date = deletion_date
        
        return {
            "ARN": secret.arn,
            "Name": secret.name,
            "DeletionDate": deletion_date.isoformat()
        }
    
    def restore_secret(self, secret_id: str) -> Dict[str, Any]:
        """Restore a deleted secret."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:RestoreSecret"):
            raise AccessDeniedError("Access denied for RestoreSecret operation")
        
        if not secret.deleted_date:
            raise InvalidRequestError("Secret is not scheduled for deletion")
        
        secret.deleted_date = None
        
        return {
            "ARN": secret.arn,
            "Name": secret.name
        }
    
    def update_secret_version_stage(self, 
                                    secret_id: str,
                                    version_stage: str,
                                    move_to_version_id: Optional[str] = None,
                                    remove_from_version_id: Optional[str] = None) -> Dict[str, Any]:
        """Update version stage assignments."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:UpdateSecretVersionStage"):
            raise AccessDeniedError("Access denied for UpdateSecretVersionStage operation")
        
        # Remove stage from old version
        if remove_from_version_id:
            if remove_from_version_id in secret.versions:
                old_version = secret.versions[remove_from_version_id]
                if old_version.version_stage == version_stage:
                    if version_stage in secret.version_stages:
                        del secret.version_stages[version_stage]
        
        # Add stage to new version
        if move_to_version_id:
            if move_to_version_id not in secret.versions:
                raise ResourceNotFoundError(f"Version '{move_to_version_id}' not found")
            
            new_version = secret.versions[move_to_version_id]
            new_version.version_stage = version_stage
            secret.version_stages[version_stage] = move_to_version_id
        
        return {
            "ARN": secret.arn,
            "Name": secret.name
        }
    
    def tag_resource(self, secret_id: str, tags: List[Dict[str, str]]) -> None:
        """Add tags to a secret."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:TagResource"):
            raise AccessDeniedError("Access denied for TagResource operation")
        
        # Merge with existing tags (replace if key exists)
        existing_keys = {tag["Key"] for tag in secret.tags}
        for tag in tags:
            if tag["Key"] in existing_keys:
                # Replace existing tag
                secret.tags = [t for t in secret.tags if t["Key"] != tag["Key"]]
            secret.tags.append(tag)
    
    def untag_resource(self, secret_id: str, tag_keys: List[str]) -> None:
        """Remove tags from a secret."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:UntagResource"):
            raise AccessDeniedError("Access denied for UntagResource operation")
        
        secret.tags = [tag for tag in secret.tags if tag["Key"] not in tag_keys]
    
    def _get_secret(self, secret_id: str) -> MockSecret:
        """Get secret by ID or ARN."""
        # Support both name and ARN lookups
        if secret_id.startswith("arn:aws:secretsmanager:"):
            # Extract name from ARN
            secret_name = secret_id.split(":")[-1]
        else:
            secret_name = secret_id
        
        if secret_name not in self.secrets:
            raise ResourceNotFoundError(f"Secret '{secret_id}' not found")
        
        secret = self.secrets[secret_name]
        
        # Check if secret is scheduled for deletion
        if secret.deleted_date and datetime.now(timezone.utc) >= secret.deleted_date:
            raise ResourceNotFoundError(f"Secret '{secret_id}' has been deleted")
        
        return secret
    
    def _check_access(self, secret_id: str, action: str) -> bool:
        """Check if access is allowed for the operation."""
        access_policy = self.access_policies.get(secret_id, {})
        denied_actions = access_policy.get("denied_actions", [])
        
        return action not in denied_actions
    
    def set_access_policy(self, secret_id: str, policy: Dict[str, Any]) -> None:
        """Set access policy for testing (not a real Secrets Manager operation)."""
        self.access_policies[secret_id] = policy
    
    def get_random_password(self, 
                           password_length: int = 32,
                           exclude_characters: Optional[str] = None,
                           exclude_numbers: bool = False,
                           exclude_punctuation: bool = False,
                           exclude_uppercase: bool = False,
                           exclude_lowercase: bool = False,
                           include_space: bool = False,
                           require_each_included_type: bool = True) -> Dict[str, Any]:
        """Generate a random password."""
        import string
        
        if password_length < 4 or password_length > 4096:
            raise InvalidParameterError("Password length must be between 4 and 4096")
        
        # Build character set
        chars = ""
        if not exclude_lowercase:
            chars += string.ascii_lowercase
        if not exclude_uppercase:
            chars += string.ascii_uppercase
        if not exclude_numbers:
            chars += string.digits
        if not exclude_punctuation:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if include_space:
            chars += " "
        
        if exclude_characters:
            for char in exclude_characters:
                chars = chars.replace(char, "")
        
        if not chars:
            raise InvalidParameterError("No valid characters available for password generation")
        
        # Generate password
        password = "".join(secrets.choice(chars) for _ in range(password_length))
        
        return {
            "RandomPassword": password
        }
    
    def replicate_secret_to_regions(self, 
                                   secret_id: str,
                                   replica_regions: List[str],
                                   force_overwrite_replica_secret: bool = False) -> Dict[str, Any]:
        """Replicate secret to multiple regions."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:ReplicateSecretToRegions"):
            raise AccessDeniedError("Access denied for ReplicateSecretToRegions operation")
        
        # Mock replication
        replication_status = []
        for region in replica_regions:
            replication_status.append({
                "Region": region,
                "KmsKeyId": secret.kms_key_id,
                "Status": "InProgress",
                "StatusMessage": "Replication in progress"
            })
        
        secret.replica_regions.extend(replica_regions)
        
        return {
            "ARN": secret.arn,
            "ReplicationStatus": replication_status
        }
    
    def stop_replication_to_replica(self, secret_id: str, region: str) -> Dict[str, Any]:
        """Stop replication to a specific region."""
        secret = self._get_secret(secret_id)
        
        if not self._check_access(secret_id, "secretsmanager:StopReplicationToReplica"):
            raise AccessDeniedError("Access denied for StopReplicationToReplica operation")
        
        if region in secret.replica_regions:
            secret.replica_regions.remove(region)
        
        return {
            "ARN": secret.arn
        }
    
    def validate_resource_policy(self, secret_id: str, resource_policy: str) -> Dict[str, Any]:
        """Validate a resource policy."""
        try:
            policy_doc = json.loads(resource_policy)
            
            # Basic validation
            required_fields = ["Version", "Statement"]
            for field in required_fields:
                if field not in policy_doc:
                    return {
                        "PolicyValidationPassed": False,
                        "ValidationErrors": [f"Missing required field: {field}"]
                    }
            
            return {
                "PolicyValidationPassed": True,
                "ValidationErrors": []
            }
            
        except json.JSONDecodeError as e:
            return {
                "PolicyValidationPassed": False,
                "ValidationErrors": [f"Invalid JSON: {str(e)}"]
            }
    
    def batch_get_secret_value(self, secret_ids: List[str]) -> Dict[str, Any]:
        """Get multiple secret values in a single call."""
        secret_values = []
        errors = []
        
        for secret_id in secret_ids:
            try:
                secret_value = self.get_secret_value(secret_id)
                secret_values.append(secret_value)
            except Exception as e:
                errors.append({
                    "SecretId": secret_id,
                    "ErrorCode": type(e).__name__,
                    "Message": str(e)
                })
        
        return {
            "SecretValues": secret_values,
            "Errors": errors
        }
    
    def simulate_error(self, error_type: str, secret_id: Optional[str] = None) -> None:
        """Simulate various error conditions for testing."""
        if error_type == "access_denied" and secret_id:
            self.access_policies[secret_id] = {"denied_actions": ["secretsmanager:*"]}
        elif error_type == "secret_not_found":
            # This will be handled by operations checking secret existence
            pass
        elif error_type == "throttling":
            # Simulate rate limiting
            if not hasattr(self, '_throttle_count'):
                self._throttle_count = 0
            self._throttle_count += 1
        elif error_type == "service_unavailable":
            # Simulate service unavailability
            self._service_unavailable = True
        elif error_type == "encryption_failure" and secret_id:
            # Simulate KMS encryption issues
            if secret_id in self.secrets:
                self.secrets[secret_id].kms_key_id = "invalid-key-id"
    
    def simulate_realistic_latency(self, operation: str) -> None:
        """Simulate realistic AWS Secrets Manager latency."""
        import time
        
        # Realistic latency patterns (in seconds)
        latencies = {
            "get_secret_value": 0.06,  # 60ms
            "put_secret_value": 0.09,  # 90ms
            "create_secret": 0.12,  # 120ms
            "delete_secret": 0.08,  # 80ms
            "list_secrets": 0.05,  # 50ms
            "describe_secret": 0.04,  # 40ms
        }
        
        if operation in latencies and not os.getenv("__DEV_MODE__") == "test":
            time.sleep(latencies[operation])
    
    def reset(self) -> None:
        """Reset the mock service to initial state."""
        self.secrets.clear()
        self.access_policies.clear()
        self._setup_default_secrets()
        
        # Reset error states
        if hasattr(self, '_throttle_count'):
            self._throttle_count = 0
        if hasattr(self, '_service_unavailable'):
            self._service_unavailable = False


def create_secrets_manager_mock(region: str = "us-east-1") -> MockSecretsManagerService:
    """Create a configured Secrets Manager mock for testing."""
    mock_service = MockSecretsManagerService(region)
    
    # Add additional test secrets
    test_master_seed = secrets.randbits(256).to_bytes(32, 'big')
    mock_service.create_secret(
        "test/master-seed",
        test_master_seed,
        description="Test master seed for key derivation"
    )
    
    # Store test data as service attributes for easy access
    mock_service.test_master_seed = test_master_seed
    
    return mock_service


# Integration helpers for boto3 mocking
def patch_boto3_secrets_client(mock_service: MockSecretsManagerService):
    """Patch boto3 Secrets Manager client to use mock service."""
    
    class MockBoto3SecretsClient:
        def __init__(self, region_name=None, **kwargs):
            self.mock_service = mock_service
        
        def get_secret_value(self, SecretId, VersionId=None, VersionStage=None):
            return self.mock_service.get_secret_value(SecretId, VersionId, VersionStage)
        
        def put_secret_value(self, SecretId, SecretString=None, SecretBinary=None, VersionStages=None):
            secret_value = SecretString or SecretBinary
            return self.mock_service.put_secret_value(SecretId, secret_value, VersionStages)
        
        def create_secret(self, Name, SecretString=None, SecretBinary=None, Description=None, KmsKeyId=None, Tags=None):
            secret_value = SecretString or SecretBinary
            return self.mock_service.create_secret(Name, secret_value, Description, KmsKeyId, Tags)
        
        def describe_secret(self, SecretId):
            return self.mock_service.describe_secret(SecretId)
        
        def list_secrets(self, MaxResults=None, Filters=None):
            return self.mock_service.list_secrets(MaxResults, Filters)
        
        def delete_secret(self, SecretId, RecoveryWindowInDays=None, ForceDeleteWithoutRecovery=False):
            return self.mock_service.delete_secret(SecretId, RecoveryWindowInDays, ForceDeleteWithoutRecovery)
        
        def restore_secret(self, SecretId):
            return self.mock_service.restore_secret(SecretId)
        
        def update_secret_version_stage(self, SecretId, VersionStage, MoveToVersionId=None, RemoveFromVersionId=None):
            return self.mock_service.update_secret_version_stage(
                SecretId, VersionStage, MoveToVersionId, RemoveFromVersionId
            )
        
        def tag_resource(self, SecretId, Tags):
            return self.mock_service.tag_resource(SecretId, Tags)
        
        def untag_resource(self, SecretId, TagKeys):
            return self.mock_service.untag_resource(SecretId, TagKeys)
    
    return patch('boto3.client', return_value=MockBoto3SecretsClient())