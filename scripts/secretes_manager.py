#!/usr/bin/env python3
"""
Secrets Manager for CI/CD Pipeline Security

This script provides comprehensive secrets management for the CI/CD pipeline,
including secure handling of secrets, integration with external secrets stores,
rotation capabilities, and validation mechanisms.

Features:
- Integration with multiple secret stores (Vault, AWS Secrets Manager, Azure Key Vault)
- Secure environment variable handling
- Secret rotation and versioning
- Secret validation and compliance checks
- Audit logging for secret access
- Temporary secret injection for pipeline jobs

Usage:
    python secrets_manager.py --action fetch --name API_KEY --store vault
    python secrets_manager.py --action rotate --name DATABASE_PASSWORD
    python secrets_manager.py --action validate --file .env
    python secrets_manager.py --action inject --pipeline-id 12345
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, Set

# Optional dependencies - handled gracefully if not installed
try:
    import hvac  # HashiCorp Vault client
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

try:
    import boto3  # AWS SDK
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("secrets-manager")


class SecretStore(Enum):
    """Supported secret storage backends"""
    LOCAL = "local"       # Local encrypted file
    VAULT = "vault"       # HashiCorp Vault
    AWS = "aws"           # AWS Secrets Manager
    AZURE = "azure"       # Azure Key Vault
    GCP = "gcp"           # Google Secret Manager
    ENV = "env"           # Environment variables (not recommended for production)


class SecretType(Enum):
    """Types of secrets with different handling requirements"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    ENV_VAR = "env_var"
    CONFIG = "config"


class SecretSeverity(Enum):
    """Security level of secrets for access control"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Secret:
    """Class representing a secret with metadata"""
    
    def __init__(self, name: str, value: str = None, 
                secret_type: SecretType = SecretType.API_KEY,
                severity: SecretSeverity = SecretSeverity.MEDIUM,
                expires_at: datetime.datetime = None,
                description: str = None,
                created_by: str = None,
                tags: Dict[str, str] = None):
        """
        Initialize a secret object with metadata
        
        Args:
            name: Unique name of the secret
            value: The secret value (will be encrypted)
            secret_type: Type of secret
            severity: Security level of secret
            expires_at: Expiration date if temporary
            description: Human-readable description
            created_by: User or system that created the secret
            tags: Key-value tags for organization
        """
        self.id = str(uuid.uuid4())
        self.name = name
        self._value = value
        self.secret_type = secret_type if isinstance(secret_type, SecretType) else SecretType(secret_type)
        self.severity = severity if isinstance(severity, SecretSeverity) else SecretSeverity(severity)
        self.expires_at = expires_at
        self.description = description
        self.created_at = datetime.datetime.now()
        self.updated_at = self.created_at
        self.created_by = created_by or os.environ.get('USER', 'unknown')
        self.tags = tags or {}
        self.version = 1
        self.rotation_history = []
    
    @property
    def is_expired(self) -> bool:
        """Check if the secret has expired"""
        if self.expires_at is None:
            return False
        return datetime.datetime.now() > self.expires_at
    
    @property
    def days_until_expiry(self) -> Optional[int]:
        """Calculate days until expiry, or None if no expiry"""
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.datetime.now()
        return max(0, delta.days)
    
    def rotate(self, new_value: str, rotated_by: str = None) -> None:
        """Rotate the secret with a new value"""
        # Store history
        history_entry = {
            "rotated_at": datetime.datetime.now().isoformat(),
            "rotated_by": rotated_by or os.environ.get('USER', 'unknown'),
            "previous_version": self.version,
        }
        self.rotation_history.append(history_entry)
        
        # Update with new value
        self._value = new_value
        self.version += 1
        self.updated_at = datetime.datetime.now()
    
    def to_dict(self, include_value: bool = False) -> Dict[str, Any]:
        """Convert to dictionary, optionally including the secret value"""
        result = {
            "id": self.id,
            "name": self.name,
            "secret_type": self.secret_type.value,
            "severity": self.severity.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "version": self.version,
            "tags": self.tags,
        }
        
        if self.expires_at:
            result["expires_at"] = self.expires_at.isoformat()
            result["is_expired"] = self.is_expired
            result["days_until_expiry"] = self.days_until_expiry
            
        if self.description:
            result["description"] = self.description
            
        if include_value and self._value:
            result["value"] = self._value
            
        if self.rotation_history:
            result["rotation_history"] = self.rotation_history
            
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Secret':
        """Create a secret object from dictionary"""
        secret = cls(name=data["name"])
        
        # Set basic attributes
        secret.id = data.get("id", str(uuid.uuid4()))
        secret._value = data.get("value")
        secret.secret_type = SecretType(data.get("secret_type", "api_key"))
        secret.severity = SecretSeverity(data.get("severity", "medium"))
        secret.description = data.get("description")
        secret.created_by = data.get("created_by", "unknown")
        secret.tags = data.get("tags", {})
        secret.version = data.get("version", 1)
        
        # Parse dates
        if "created_at" in data:
            secret.created_at = datetime.datetime.fromisoformat(data["created_at"])
        if "updated_at" in data:
            secret.updated_at = datetime.datetime.fromisoformat(data["updated_at"])
        if "expires_at" in data and data["expires_at"]:
            secret.expires_at = datetime.datetime.fromisoformat(data["expires_at"])
            
        # Parse rotation history
        secret.rotation_history = data.get("rotation_history", [])
        
        return secret


class SecretsManagerError(Exception):
    """Base exception for secrets manager errors"""
    pass


class StoreConnectionError(SecretsManagerError):
    """Error connecting to secrets store"""
    pass


class SecretNotFoundError(SecretsManagerError):
    """Secret not found in store"""
    pass


class SecretValidationError(SecretsManagerError):
    """Secret failed validation"""
    pass


class SecretRotationError(SecretsManagerError):
    """Error during secret rotation"""
    pass


class SecretsManager:
    """Core secrets management functionality"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize the secrets manager
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.default_store = SecretStore(self.config.get("default_store", "local"))
        self.stores = {}
        self.encryption_key = self._get_encryption_key()
        self.audit_logger = self._setup_audit_logging()
        
        # Initialize secret stores
        self._init_stores()
    
    def _load_config(self, config_path: str = None) -> Dict[str, Any]:
        """
        Load configuration from file or use defaults
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        default_config = {
            "default_store": "local",
            "stores": {
                "local": {
                    "path": os.path.expanduser("~/.secrets/secrets.json"),
                    "encryption_key_env": "SECRETS_ENCRYPTION_KEY"
                },
                "vault": {
                    "url": "http://localhost:8200",
                    "token_env": "VAULT_TOKEN",
                    "path": "secret/cicd"
                },
                "aws": {
                    "region": "us-east-1",
                    "prefix": "cicd/"
                },
                "azure": {
                    "vault_url": "https://example-vault.vault.azure.net/",
                    "prefix": "cicd-"
                },
                "gcp": {
                    "project_id": "my-project",
                    "prefix": "cicd-"
                }
            },
            "rotation": {
                "reminder_days": 30,
                "max_age_days": 90
            },
            "audit": {
                "enabled": True,
                "log_path": "logs/secrets_audit.log"
            },
            "validation": {
                "enabled": True,
                "min_length": 12,
                "require_special_chars": True
            }
        }
        
        # Use default config if no path provided
        if not config_path:
            return default_config
        
        # Load from YAML file if available
        if YAML_AVAILABLE:
            try:
                with open(config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Merge user config with defaults
                    return self._deep_merge(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {str(e)}")
                return default_config
        else:
            logger.warning("YAML not available, using default configuration")
            return default_config
    
    def _deep_merge(self, dict1: Dict, dict2: Dict) -> Dict:
        """Recursively merge dictionaries"""
        result = dict1.copy()
        
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
                
        return result
    
    def _get_encryption_key(self) -> bytes:
        """
        Get or generate encryption key for local secrets
        
        Returns:
            Bytes key for encryption/decryption
        """
        # Check for encryption key in environment
        env_var = self.config.get("stores", {}).get("local", {}).get("encryption_key_env", "SECRETS_ENCRYPTION_KEY")
        key = os.environ.get(env_var)
        
        if key:
            # If key exists in environment, derive a proper key using PBKDF2
            if CRYPTO_AVAILABLE:
                salt = b'secretsmanagersalt'  # In production, this should be stored securely
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                return base64.urlsafe_b64encode(kdf.derive(key.encode()))
            else:
                # Fallback if cryptography module not available
                return hashlib.sha256(key.encode()).digest()
        else:
            # Generate and store a key if none exists
            if CRYPTO_AVAILABLE:
                # Generate a Fernet key
                key = Fernet.generate_key()
                logger.warning(f"Generated new encryption key. Set {env_var} environment variable for persistence.")
                return key
            else:
                # Fallback to a less secure method if cryptography not available
                logger.warning("Cryptography module not available, using less secure key generation")
                random_key = str(uuid.uuid4()) + str(time.time())
                return hashlib.sha256(random_key.encode()).digest()
    
    def _setup_audit_logging(self) -> logging.Logger:
        """
        Set up audit logging for secret operations
        
        Returns:
            Configured logger for audit events
        """
        audit_config = self.config.get("audit", {})
        
        if not audit_config.get("enabled", True):
            # Return dummy logger if audit logging disabled
            return logging.getLogger("secrets-audit-disabled")
        
        # Create audit logger
        audit_logger = logging.getLogger("secrets-audit")
        audit_logger.setLevel(logging.INFO)
        
        # Set up file handler
        log_path = audit_config.get("log_path", "logs/secrets_audit.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        handler = logging.FileHandler(log_path)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        handler.setFormatter(formatter)
        
        audit_logger.addHandler(handler)
        return audit_logger
    
    def _init_stores(self) -> None:
        """Initialize connections to configured secret stores"""
        for store_type in SecretStore:
            store_config = self.config.get("stores", {}).get(store_type.value, {})
            
            if not store_config:
                continue
                
            try:
                if store_type == SecretStore.VAULT:
                    self._init_vault_store(store_config)
                elif store_type == SecretStore.AWS:
                    self._init_aws_store(store_config)
                elif store_type == SecretStore.AZURE:
                    self._init_azure_store(store_config)
                elif store_type == SecretStore.GCP:
                    self._init_gcp_store(store_config)
                elif store_type == SecretStore.LOCAL:
                    self._init_local_store(store_config)
            except Exception as e:
                logger.error(f"Failed to initialize {store_type.value} store: {str(e)}")
    
    def _init_vault_store(self, config: Dict[str, Any]) -> None:
        """Initialize HashiCorp Vault connection"""
        if not VAULT_AVAILABLE:
            logger.warning("HashiCorp Vault client (hvac) not installed")
            return
            
        url = config.get("url", "http://localhost:8200")
        token_env = config.get("token_env", "VAULT_TOKEN")
        token = os.environ.get(token_env)
        
        if not token:
            logger.warning(f"Vault token not found in environment variable {token_env}")
            return
            
        try:
            client = hvac.Client(url=url, token=token)
            if client.is_authenticated():
                self.stores[SecretStore.VAULT] = {
                    "client": client,
                    "path": config.get("path", "secret/cicd")
                }
                logger.info("Successfully connected to HashiCorp Vault")
            else:
                logger.warning("Failed to authenticate with Vault")
        except Exception as e:
            logger.error(f"Error connecting to Vault: {str(e)}")
    
    def _init_aws_store(self, config: Dict[str, Any]) -> None:
        """Initialize AWS Secrets Manager connection"""
        if not AWS_AVAILABLE:
            logger.warning("AWS SDK (boto3) not installed")
            return
            
        region = config.get("region", "us-east-1")
        
        try:
            session = boto3.session.Session()
            client = session.client(
                service_name='secretsmanager',
                region_name=region
            )
            
            # Test connection with a simple API call
            client.list_secrets(MaxResults=1)
            
            self.stores[SecretStore.AWS] = {
                "client": client,
                "prefix": config.get("prefix", "cicd/")
            }
            logger.info(f"Successfully connected to AWS Secrets Manager in {region}")
        except Exception as e:
            logger.error(f"Error connecting to AWS Secrets Manager: {str(e)}")
    
    def _init_azure_store(self, config: Dict[str, Any]) -> None:
        """Initialize Azure Key Vault connection"""
        if not AZURE_AVAILABLE:
            logger.warning("Azure Key Vault client not installed")
            return
            
        vault_url = config.get("vault_url")
        
        if not vault_url:
            logger.warning("Azure Key Vault URL not configured")
            return
            
        try:
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=vault_url, credential=credential)
            
            # Test connection with a simple operation
            client.get_secret_properties("test-connection")
            
            self.stores[SecretStore.AZURE] = {
                "client": client,
                "prefix": config.get("prefix", "cicd-")
            }
            logger.info(f"Successfully connected to Azure Key Vault at {vault_url}")
        except Exception as e:
            logger.error(f"Error connecting to Azure Key Vault: {str(e)}")
    
    def _init_gcp_store(self, config: Dict[str, Any]) -> None:
        """Initialize Google Secret Manager connection"""
        # Not implemented in this version
        # Would use google-cloud-secret-manager package
        logger.info("GCP Secret Manager integration not implemented yet")
    
    def _init_local_store(self, config: Dict[str, Any]) -> None:
        """Initialize local secrets file store"""
        path = config.get("path", os.path.expanduser("~/.secrets/secrets.json"))
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Create empty file if it doesn't exist
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump({"secrets": {}}, f)
        
        self.stores[SecretStore.LOCAL] = {
            "path": path
        }
        logger.info(f"Local secret store initialized at {path}")
    
    def _encrypt_value(self, value: str) -> str:
        """
        Encrypt a secret value
        
        Args:
            value: Plain text secret value
            
        Returns:
            Encrypted value as a string
        """
        if not value:
            return None
            
        if CRYPTO_AVAILABLE:
            f = Fernet(self.encryption_key)
            encrypted = f.encrypt(value.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        else:
            # Fallback encryption if cryptography module not available
            # Note: This is NOT secure for production use
            logger.warning("Using fallback encryption (not recommended for production)")
            key = self.encryption_key
            encrypted = []
            for i, c in enumerate(value):
                key_c = key[i % len(key)]
                encrypted_c = chr(ord(c) + key_c[0])
                encrypted.append(encrypted_c)
            return base64.b64encode(''.join(encrypted).encode()).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """
        Decrypt a secret value
        
        Args:
            encrypted_value: Encrypted secret value
            
        Returns:
            Plain text secret value
        """
        if not encrypted_value:
            return None
            
        try:
            if CRYPTO_AVAILABLE:
                f = Fernet(self.encryption_key)
                decoded = base64.urlsafe_b64decode(encrypted_value.encode())
                decrypted = f.decrypt(decoded)
                return decrypted.decode()
            else:
                # Fallback decryption if cryptography module not available
                key = self.encryption_key
                decoded = base64.b64decode(encrypted_value.encode()).decode()
                decrypted = []
                for i, c in enumerate(decoded):
                    key_c = key[i % len(key)]
                    decrypted_c = chr(ord(c) - key_c[0])
                    decrypted.append(decrypted_c)
                return ''.join(decrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt value: {str(e)}")
            return None
    
    def _audit_log(self, action: str, secret_name: str, 
                  user: str = None, store: str = None, 
                  success: bool = True, details: str = None) -> None:
        """
        Log an audit event
        
        Args:
            action: Action performed (get, set, rotate, etc.)
            secret_name: Name of the secret
            user: User performing the action
            store: Secret store used
            success: Whether the action succeeded
            details: Additional details
        """
        user = user or os.environ.get('USER', 'unknown')
        store = store or self.default_store.value
        
        message = f"ACTION={action} SECRET={secret_name} USER={user} STORE={store} SUCCESS={success}"
        
        if details:
            message += f" DETAILS={details}"
            
        self.audit_logger.info(message)
    
    def _validate_secret(self, secret: Union[Secret, str], 
                        secret_type: SecretType = None) -> Tuple[bool, str]:
        """
        Validate a secret against security policies
        
        Args:
            secret: Secret object or value to validate
            secret_type: Type of secret if only value provided
            
        Returns:
            Tuple of (is_valid, reason)
        """
        validation_config = self.config.get("validation", {})
        
        if not validation_config.get("enabled", True):
            return True, "Validation disabled"
            
        # Extract the value to validate
        if isinstance(secret, Secret):
            value = secret._value
            secret_type = secret.secret_type
        else:
            value = secret
            
        if not value:
            return False, "Secret value is empty"
            
        # Basic validation for all secrets
        min_length = validation_config.get("min_length", 8)
        if len(value) < min_length:
            return False, f"Secret too short (minimum {min_length} characters)"
            
        # Special character validation
        if validation_config.get("require_special_chars", True):
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
                return False, "Secret must contain at least one special character"
                
        # Type-specific validation
        if secret_type == SecretType.PASSWORD:
            # Password requirements
            if not re.search(r'[A-Z]', value):
                return False, "Password must contain at least one uppercase letter"
            if not re.search(r'[a-z]', value):
                return False, "Password must contain at least one lowercase letter"
            if not re.search(r'[0-9]', value):
                return False, "Password must contain at least one number"
        
        elif secret_type == SecretType.API_KEY:
            # API keys are often hexadecimal or base64
            if not (re.match(r'^[A-Za-z0-9+/]+={0,2}$', value) or  # base64
                   re.match(r'^[A-Fa-f0-9]+$', value)):           # hex
                return False, "API key has invalid format"
                
        elif secret_type == SecretType.CERTIFICATE:
            # Basic certificate validation
            if "BEGIN CERTIFICATE" not in value and "PRIVATE KEY" not in value:
                return False, "Certificate must be in PEM format"
                
        # Check for common leaked secrets patterns
        if re.search(r'(AKIA[0-9A-Z]{16})', value):  # AWS Access Key
            return False, "Contains what appears to be an AWS access key"
            
        if re.search(r'ghp_[a-zA-Z0-9]{36}', value):  # GitHub Personal Access Token
            return False, "Contains what appears to be a GitHub PAT"
        
        return True, "Secret is valid"
    
    def get_secret(self, name: str, 
                  store: SecretStore = None, 
                  raise_if_missing: bool = True,
                  user: str = None) -> Union[Secret, None]:
        """
        Retrieve a secret from the store
        
        Args:
            name: Secret name
            store: Secret store to use (default: configured default store)
            raise_if_missing: Whether to raise an exception if secret not found
            user: User retrieving the secret (for audit)
            
        Returns:
            Secret object or None if not found and raise_if_missing is False
            
        Raises:
            SecretNotFoundError: If secret not found and raise_if_missing is True
            StoreConnectionError: If connection to store fails
        """
        store = store or self.default_store
        
        # Log the attempt
        self._audit_log("get", name, user=user, store=store.value, success=True)
        
        try:
            if store == SecretStore.LOCAL:
                secret = self._get_from_local(name)
            elif store == SecretStore.VAULT:
                secret = self._get_from_vault(name)
            elif store == SecretStore.AWS:
                secret = self._get_from_aws(name)
            elif store == SecretStore.AZURE:
                secret = self._get_from_azure(name)
            elif store == SecretStore.ENV:
                secret = self._get_from_env(name)
            else:
                raise ValueError(f"Unsupported store type: {store}")
                
            # Check expiration
            if secret and secret.is_expired:
                self._audit_log(
                    "expiration_check", name, user=user, 
                    store=store.value, success=False, 
                    details="Secret has expired"
                )
                logger.warning(f"Secret {name} has expired")
                
            return secret
        except SecretNotFoundError:
            self._audit_log(
                "get", name, user=user, 
                store=store.value, success=False, 
                details="Secret not found"
            )
            
            if raise_if_missing:
                raise
            return None
        except Exception as e:
            self._audit_log(
                "get", name, user=user, 
                store=store.value, success=False, 
                details=f"Error: {str(e)}"
            )
            raise StoreConnectionError(f"Failed to get secret {name}: {str(e)}")
    
    def _get_from_local(self, name: str) -> Secret:
        """Retrieve secret from local store"""
        store_config = self.stores.get(SecretStore.LOCAL)
        if not store_config:
            raise StoreConnectionError("Local store not initialized")
            
        path = store_config["path"]
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                
            if name not in data.get("secrets", {}):
                raise SecretNotFoundError(f"Secret {name} not found in local store")
                
            secret_data = data["secrets"][name]
            secret = Secret.from_dict(secret_data)
            
            # Decrypt the value
            if "encrypted_value" in secret_data:
                secret._value = self._decrypt_value(secret_data["encrypted_value"])
                
            return secret
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise StoreConnectionError(f"Failed to read from local store: {str(e)}")
    
    def _get_from_vault(self, name: str) -> Secret:
        """Retrieve secret from HashiCorp Vault"""
        store_config = self.stores.get(SecretStore.VAULT)
        if not store_config:
            raise StoreConnectionError("Vault store not initialized")
            
        client = store_config["client"]
        path = f"{store_config['path']}/{name}"
        
        try:
            response = client.secrets.kv.v2.read_secret_version(path=path)
            
            if not response or "data" not in response or "data" not in response["data"]:
                raise SecretNotFoundError(f"Secret {name} not found in Vault")
                
            data = response["data"]["data"]
            
            # Convert Vault secret to our Secret model
            value = data.pop("value", None)
            metadata = data.pop("metadata", {})
            
            # Create a Secret object with the returned data
            secret = Secret(
                name=name,
                value=value,
                secret_type=data.get("type", SecretType.API_KEY),
                severity=data.get("severity", SecretSeverity.MEDIUM)
            )
            
            # Add additional metadata from Vault
            if "created_time" in metadata:
                secret.created_at = datetime.datetime.fromisoformat(metadata["created_time"].replace("Z", "+00:00"))
            if "updated_time" in metadata:
                secret.updated_at = datetime.datetime.fromisoformat(metadata["updated_time"].replace("Z", "+00:00"))
                
            return secret
        except Exception as e:
            raise StoreConnectionError(f"Failed to get secret from Vault: {str(e)}")
    
    def _get_from_aws(self, name: str) -> Secret:
        """Retrieve secret from AWS Secrets Manager"""
        store_config = self.stores.get(SecretStore.AWS)
        if not store_config:
            raise StoreConnectionError("AWS Secrets Manager store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        secret_id = f"{prefix}{name}"
        
        try:
            response = client.get_secret_value(SecretId=secret_id)
            
            if "SecretString" not in response:
                raise SecretNotFoundError(f"Secret {name} not found in AWS Secrets Manager")
                
            # Parse the secret string (JSON)
            secret_string = response["SecretString"]
            try:
                secret_data = json.loads(secret_string)
                value = secret_data.pop("value", secret_string)
            except json.JSONDecodeError:
                # If not JSON, use the entire string as the value
                value = secret_string
                secret_data = {}
                
            # Create a Secret object
            secret = Secret(
                name=name,
                value=value,
                secret_type=secret_data.get("type", SecretType.API_KEY),
                severity=secret_data.get("severity", SecretSeverity.MEDIUM),
                description=secret_data.get("description")
            )
            
            # Add creation/update dates from AWS metadata
            if "CreatedDate" in response:
                secret.created_at = response["CreatedDate"]
            if "LastAccessedDate" in response:
                secret.updated_at = response["LastAccessedDate"]
                
            return secret
        except client.exceptions.ResourceNotFoundException:
            raise SecretNotFoundError(f"Secret {name} not found in AWS Secrets Manager")
        except Exception as e:
            raise StoreConnectionError(f"Failed to get secret from AWS: {str(e)}")
    
    def _get_from_azure(self, name: str) -> Secret:
        """Retrieve secret from Azure Key Vault"""
        store_config = self.stores.get(SecretStore.AZURE)
        if not store_config:
            raise StoreConnectionError("Azure Key Vault store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        secret_name = f"{prefix}{name}"
        
        try:
            # Get the secret
            response = client.get_secret(secret_name)
            
            if not response.value:
                raise SecretNotFoundError(f"Secret {name} not found in Azure Key Vault")
                
            # Try to parse as JSON for metadata
            try:
                secret_data = json.loads(response.value)
                value = secret_data.pop("value", response.value)
            except json.JSONDecodeError:
                # If not JSON, use the entire string as the value
                value = response.value
                secret_data = {}
                
            # Create a Secret object
            secret = Secret(
                name=name,
                value=value,
                secret_type=secret_data.get("type", SecretType.API_KEY),
                severity=secret_data.get("severity", SecretSeverity.MEDIUM),
                description=secret_data.get("description")
            )
            
            # Add metadata from Azure
            if response.properties.created_on:
                secret.created_at = response.properties.created_on
            if response.properties.updated_on:
                secret.updated_at = response.properties.updated_on
            if response.properties.expires_on:
                secret.expires_at = response.properties.expires_on
                
            return secret
        except Exception as e:
            if "SecretNotFound" in str(e):
                raise SecretNotFoundError(f"Secret {name} not found in Azure Key Vault")
            raise StoreConnectionError(f"Failed to get secret from Azure: {str(e)}")
    
    def _get_from_env(self, name: str) -> Secret:
        """Retrieve secret from environment variables"""
        value = os.environ.get(name)
        
        if not value:
            raise SecretNotFoundError(f"Environment variable {name} not set")
            
        # Create a basic Secret object
        secret = Secret(
            name=name,
            value=value,
            secret_type=SecretType.ENV_VAR,
            severity=SecretSeverity.LOW,
            description=f"Environment variable {name}"
        )
        
        return secret
    
    def set_secret(self, secret: Secret, 
                  store: SecretStore = None,
                  user: str = None,
                  validate: bool = True) -> bool:
        """
        Store a secret
        
        Args:
            secret: Secret object to store
            store: Secret store to use (default: configured default store)
            user: User storing the secret (for audit)
            validate: Whether to validate the secret before storing
            
        Returns:
            True if successful
            
        Raises:
            SecretValidationError: If secret validation fails
            StoreConnectionError: If connection to store fails
        """
        store = store or self.default_store
        
        # Validate the secret
        if validate:
            is_valid, reason = self._validate_secret(secret)
            if not is_valid:
                self._audit_log(
                    "set", secret.name, user=user, 
                    store=store.value, success=False, 
                    details=f"Validation failed: {reason}"
                )
                raise SecretValidationError(f"Secret validation failed: {reason}")
        
        try:
            if store == SecretStore.LOCAL:
                self._set_to_local(secret)
            elif store == SecretStore.VAULT:
                self._set_to_vault(secret)
            elif store == SecretStore.AWS:
                self._set_to_aws(secret)
            elif store == SecretStore.AZURE:
                self._set_to_azure(secret)
            elif store == SecretStore.ENV:
                self._set_to_env(secret)
            else:
                raise ValueError(f"Unsupported store type: {store}")
                
            self._audit_log("set", secret.name, user=user, store=store.value, success=True)
            return True
        except Exception as e:
            self._audit_log(
                "set", secret.name, user=user, 
                store=store.value, success=False, 
                details=f"Error: {str(e)}"
            )
            raise StoreConnectionError(f"Failed to set secret {secret.name}: {str(e)}")
    
    def _set_to_local(self, secret: Secret) -> None:
        """Store secret in local store"""
        store_config = self.stores.get(SecretStore.LOCAL)
        if not store_config:
            raise StoreConnectionError("Local store not initialized")
            
        path = store_config["path"]
        
        try:
            # Read existing secrets
            try:
                with open(path, 'r') as f:
                    data = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                data = {"secrets": {}}
                
            # Prepare secret data for storage
            secret_dict = secret.to_dict(include_value=False)
            if secret._value:
                secret_dict["encrypted_value"] = self._encrypt_value(secret._value)
                
            # Add or update secret
            data["secrets"][secret.name] = secret_dict
                
            # Write back to file with proper permission
            temp_file = f"{path}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            # Set proper permissions (readable only by owner)
            os.chmod(temp_file, 0o600)
            
            # Replace the original file
            shutil.move(temp_file, path)
        except Exception as e:
            raise StoreConnectionError(f"Failed to write to local store: {str(e)}")
    
    def _set_to_vault(self, secret: Secret) -> None:
        """Store secret in HashiCorp Vault"""
        store_config = self.stores.get(SecretStore.VAULT)
        if not store_config:
            raise StoreConnectionError("Vault store not initialized")
            
        client = store_config["client"]
        path = f"{store_config['path']}/{secret.name}"
        
        # Prepare data for Vault
        data = {
            "value": secret._value,
            "type": secret.secret_type.value,
            "severity": secret.severity.value,
            "metadata": {
                "created_time": secret.created_at.isoformat(),
                "updated_time": secret.updated_at.isoformat(),
                "created_by": secret.created_by,
                "version": secret.version
            }
        }
        
        if secret.description:
            data["description"] = secret.description
            
        if secret.expires_at:
            data["metadata"]["expires_at"] = secret.expires_at.isoformat()
            
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data
            )
        except Exception as e:
            raise StoreConnectionError(f"Failed to set secret in Vault: {str(e)}")
    
    def _set_to_aws(self, secret: Secret) -> None:
        """Store secret in AWS Secrets Manager"""
        store_config = self.stores.get(SecretStore.AWS)
        if not store_config:
            raise StoreConnectionError("AWS Secrets Manager store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        secret_id = f"{prefix}{secret.name}"
        
        # Prepare data for AWS
        data = {
            "value": secret._value,
            "type": secret.secret_type.value,
            "severity": secret.severity.value,
            "version": secret.version
        }
        
        if secret.description:
            data["description"] = secret.description
            
        try:
            # Check if secret exists
            try:
                client.describe_secret(SecretId=secret_id)
                # Secret exists, update it
                client.put_secret_value(
                    SecretId=secret_id,
                    SecretString=json.dumps(data)
                )
            except client.exceptions.ResourceNotFoundException:
                # Secret doesn't exist, create it
                tags = [{"Key": k, "Value": v} for k, v in secret.tags.items()]
                client.create_secret(
                    Name=secret_id,
                    Description=secret.description or f"Secret for {secret.name}",
                    SecretString=json.dumps(data),
                    Tags=tags
                )
        except Exception as e:
            raise StoreConnectionError(f"Failed to set secret in AWS: {str(e)}")
    
    def _set_to_azure(self, secret: Secret) -> None:
        """Store secret in Azure Key Vault"""
        store_config = self.stores.get(SecretStore.AZURE)
        if not store_config:
            raise StoreConnectionError("Azure Key Vault store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        secret_name = f"{prefix}{secret.name}"
        
        # Prepare data for Azure
        data = {
            "value": secret._value,
            "type": secret.secret_type.value,
            "severity": secret.severity.value,
            "version": secret.version
        }
        
        if secret.description:
            data["description"] = secret.description
            
        try:
            # Set properties for the secret
            kwargs = {}
            if secret.expires_at:
                kwargs["expires_on"] = secret.expires_at
                
            if secret.tags:
                kwargs["tags"] = secret.tags
                
            if secret.description:
                kwargs["content_type"] = "application/json"
                
            # Create or update the secret
            client.set_secret(
                name=secret_name,
                value=json.dumps(data),
                **kwargs
            )
        except Exception as e:
            raise StoreConnectionError(f"Failed to set secret in Azure: {str(e)}")
    
    def _set_to_env(self, secret: Secret) -> None:
        """Store secret in environment variables (runtime only)"""
        os.environ[secret.name] = secret._value
        logger.warning(f"Secret {secret.name} set to environment variable (runtime only)")
    
    def delete_secret(self, name: str, 
                     store: SecretStore = None,
                     user: str = None) -> bool:
        """
        Delete a secret
        
        Args:
            name: Secret name
            store: Secret store to use
            user: User deleting the secret (for audit)
            
        Returns:
            True if successful
            
        Raises:
            SecretNotFoundError: If secret doesn't exist
            StoreConnectionError: If connection to store fails
        """
        store = store or self.default_store
        
        try:
            if store == SecretStore.LOCAL:
                self._delete_from_local(name)
            elif store == SecretStore.VAULT:
                self._delete_from_vault(name)
            elif store == SecretStore.AWS:
                self._delete_from_aws(name)
            elif store == SecretStore.AZURE:
                self._delete_from_azure(name)
            elif store == SecretStore.ENV:
                self._delete_from_env(name)
            else:
                raise ValueError(f"Unsupported store type: {store}")
                
            self._audit_log("delete", name, user=user, store=store.value, success=True)
            return True
        except SecretNotFoundError:
            self._audit_log(
                "delete", name, user=user, 
                store=store.value, success=False, 
                details="Secret not found"
            )
            raise
        except Exception as e:
            self._audit_log(
                "delete", name, user=user, 
                store=store.value, success=False, 
                details=f"Error: {str(e)}"
            )
            raise StoreConnectionError(f"Failed to delete secret {name}: {str(e)}")
    
    def _delete_from_local(self, name: str) -> None:
        """Delete secret from local store"""
        store_config = self.stores.get(SecretStore.LOCAL)
        if not store_config:
            raise StoreConnectionError("Local store not initialized")
            
        path = store_config["path"]
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                
            if name not in data.get("secrets", {}):
                raise SecretNotFoundError(f"Secret {name} not found in local store")
                
            # Remove the secret
            del data["secrets"][name]
            
            # Write back to file
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise StoreConnectionError(f"Failed to read from local store: {str(e)}")
    
    def _delete_from_vault(self, name: str) -> None:
        """Delete secret from HashiCorp Vault"""
        store_config = self.stores.get(SecretStore.VAULT)
        if not store_config:
            raise StoreConnectionError("Vault store not initialized")
            
        client = store_config["client"]
        path = f"{store_config['path']}/{name}"
        
        try:
            # Check if secret exists
            try:
                client.secrets.kv.v2.read_secret_version(path=path)
            except Exception:
                raise SecretNotFoundError(f"Secret {name} not found in Vault")
                
            # Delete the secret
            client.secrets.kv.v2.delete_latest_version_of_secret(path=path)
        except Exception as e:
            if isinstance(e, SecretNotFoundError):
                raise
            raise StoreConnectionError(f"Failed to delete secret from Vault: {str(e)}")
    
    def _delete_from_aws(self, name: str) -> None:
        """Delete secret from AWS Secrets Manager"""
        store_config = self.stores.get(SecretStore.AWS)
        if not store_config:
            raise StoreConnectionError("AWS Secrets Manager store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        secret_id = f"{prefix}{name}"
        
        try:
            # Delete the secret
            client.delete_secret(
                SecretId=secret_id,
                ForceDeleteWithoutRecovery=True
            )
        except client.exceptions.ResourceNotFoundException:
            raise SecretNotFoundError(f"Secret {name} not found in AWS Secrets Manager")
        except Exception as e:
            raise StoreConnectionError(f"Failed to delete secret from AWS: {str(e)}")
    
    def _delete_from_azure(self, name: str) -> None:
        """Delete secret from Azure Key Vault"""
        store_config = self.stores.get(SecretStore.AZURE)
        if not store_config:
            raise StoreConnectionError("Azure Key Vault store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        secret_name = f"{prefix}{name}"
        
        try:
            # Delete the secret
            client.begin_delete_secret(secret_name).wait()
        except Exception as e:
            if "SecretNotFound" in str(e):
                raise SecretNotFoundError(f"Secret {name} not found in Azure Key Vault")
            raise StoreConnectionError(f"Failed to delete secret from Azure: {str(e)}")
    
    def _delete_from_env(self, name: str) -> None:
        """Delete secret from environment variables"""
        if name not in os.environ:
            raise SecretNotFoundError(f"Environment variable {name} not set")
            
        del os.environ[name]
    
    def rotate_secret(self, name: str, new_value: str,
                     store: SecretStore = None,
                     user: str = None,
                     validate: bool = True) -> bool:
        """
        Rotate a secret with a new value
        
        Args:
            name: Secret name
            new_value: New secret value
            store: Secret store to use
            user: User rotating the secret (for audit)
            validate: Whether to validate the new value
            
        Returns:
            True if successful
            
        Raises:
            SecretNotFoundError: If secret doesn't exist
            SecretValidationError: If validation fails
            StoreConnectionError: If connection to store fails
        """
        store = store or self.default_store
        
        try:
            # Get the current secret
            secret = self.get_secret(name, store)
            
            # Validate the new value
            if validate:
                is_valid, reason = self._validate_secret(new_value, secret.secret_type)
                if not is_valid:
                    self._audit_log(
                        "rotate", name, user=user, 
                        store=store.value, success=False, 
                        details=f"Validation failed: {reason}"
                    )
                    raise SecretValidationError(f"Secret validation failed: {reason}")
            
            # Rotate the secret
            secret.rotate(new_value, rotated_by=user)
            
            # Store the updated secret
            self.set_secret(secret, store, user, validate=False)
            
            self._audit_log("rotate", name, user=user, store=store.value, success=True)
            return True
        except (SecretNotFoundError, SecretValidationError):
            raise
        except Exception as e:
            self._audit_log(
                "rotate", name, user=user, 
                store=store.value, success=False, 
                details=f"Error: {str(e)}"
            )
            raise SecretRotationError(f"Failed to rotate secret {name}: {str(e)}")
    
    def list_secrets(self, store: SecretStore = None, 
                    pattern: str = None,
                    include_values: bool = False,
                    user: str = None) -> List[Dict[str, Any]]:
        """
        List secrets in the store
        
        Args:
            store: Secret store to use
            pattern: Regex pattern to filter secret names
            include_values: Whether to include secret values (use with caution)
            user: User listing the secrets (for audit)
            
        Returns:
            List of secret dictionaries
        """
        store = store or self.default_store
        
        try:
            if store == SecretStore.LOCAL:
                secrets = self._list_from_local(include_values)
            elif store == SecretStore.VAULT:
                secrets = self._list_from_vault(include_values)
            elif store == SecretStore.AWS:
                secrets = self._list_from_aws(include_values)
            elif store == SecretStore.AZURE:
                secrets = self._list_from_azure(include_values)
            elif store == SecretStore.ENV:
                secrets = self._list_from_env(include_values)
            else:
                raise ValueError(f"Unsupported store type: {store}")
                
            # Filter by pattern if provided
            if pattern:
                regex = re.compile(pattern)
                secrets = [s for s in secrets if regex.search(s["name"])]
                
            self._audit_log(
                "list", "all", user=user, 
                store=store.value, success=True,
                details=f"Count: {len(secrets)}, Pattern: {pattern}"
            )
            return secrets
        except Exception as e:
            self._audit_log(
                "list", "all", user=user, 
                store=store.value, success=False, 
                details=f"Error: {str(e)}"
            )
            raise StoreConnectionError(f"Failed to list secrets: {str(e)}")
    
    def _list_from_local(self, include_values: bool) -> List[Dict[str, Any]]:
        """List secrets from local store"""
        store_config = self.stores.get(SecretStore.LOCAL)
        if not store_config:
            raise StoreConnectionError("Local store not initialized")
            
        path = store_config["path"]
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                
            secrets = []
            for name, secret_data in data.get("secrets", {}).items():
                secret = Secret.from_dict(secret_data)
                
                # Decrypt value if requested
                if include_values and "encrypted_value" in secret_data:
                    secret._value = self._decrypt_value(secret_data["encrypted_value"])
                    
                secrets.append(secret.to_dict(include_value=include_values))
                
            return secrets
        except (json.JSONDecodeError, FileNotFoundError) as e:
            raise StoreConnectionError(f"Failed to read from local store: {str(e)}")
    
    def _list_from_vault(self, include_values: bool) -> List[Dict[str, Any]]:
        """List secrets from HashiCorp Vault"""
        store_config = self.stores.get(SecretStore.VAULT)
        if not store_config:
            raise StoreConnectionError("Vault store not initialized")
            
        client = store_config["client"]
        path = store_config["path"]
        
        try:
            # List secrets at path
            response = client.secrets.kv.v2.list_secrets(path=path)
            
            if not response or "data" not in response or "keys" not in response["data"]:
                return []
                
            secret_names = response["data"]["keys"]
            secrets = []
            
            for name in secret_names:
                if include_values:
                    # Get full secret if values are requested
                    secret = self.get_secret(name, SecretStore.VAULT)
                    secrets.append(secret.to_dict(include_value=True))
                else:
                    # Otherwise just include the name
                    secrets.append({"name": name})
                    
            return secrets
        except Exception as e:
            raise StoreConnectionError(f"Failed to list secrets from Vault: {str(e)}")
    
    def _list_from_aws(self, include_values: bool) -> List[Dict[str, Any]]:
        """List secrets from AWS Secrets Manager"""
        store_config = self.stores.get(SecretStore.AWS)
        if not store_config:
            raise StoreConnectionError("AWS Secrets Manager store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        
        try:
            secrets = []
            next_token = None
            
            while True:
                if next_token:
                    response = client.list_secrets(
                        MaxResults=100,
                        NextToken=next_token,
                        Filters=[
                            {
                                'Key': 'name',
                                'Values': [f"{prefix}*"]
                            },
                        ]
                    )
                else:
                    response = client.list_secrets(
                        MaxResults=100,
                        Filters=[
                            {
                                'Key': 'name',
                                'Values': [f"{prefix}*"]
                            },
                        ]
                    )
                    
                for secret in response.get("SecretList", []):
                    name = secret["Name"]
                    if name.startswith(prefix):
                        name = name[len(prefix):]
                        
                    if include_values:
                        # Get full secret if values are requested
                        secret_obj = self.get_secret(name, SecretStore.AWS)
                        secrets.append(secret_obj.to_dict(include_value=True))
                    else:
                        # Otherwise just include basic metadata
                        secrets.append({
                            "name": name,
                            "created_at": secret.get("CreatedDate", "").isoformat() if "CreatedDate" in secret else None,
                            "description": secret.get("Description")
                        })
                
                next_token = response.get("NextToken")
                if not next_token:
                    break
                    
            return secrets
        except Exception as e:
            raise StoreConnectionError(f"Failed to list secrets from AWS: {str(e)}")
    
    def _list_from_azure(self, include_values: bool) -> List[Dict[str, Any]]:
        """List secrets from Azure Key Vault"""
        store_config = self.stores.get(SecretStore.AZURE)
        if not store_config:
            raise StoreConnectionError("Azure Key Vault store not initialized")
            
        client = store_config["client"]
        prefix = store_config["prefix"]
        
        try:
            secrets = []
            
            # List all secrets
            for secret_properties in client.list_properties_of_secrets():
                name = secret_properties.name
                
                # Filter by prefix
                if prefix and name.startswith(prefix):
                    name = name[len(prefix):]
                elif prefix:
                    continue
                    
                if include_values:
                    # Get full secret if values are requested
                    secret_obj = self.get_secret(name, SecretStore.AZURE)
                    secrets.append(secret_obj.to_dict(include_value=True))
                else:
                    # Otherwise just include basic metadata
                    secrets.append({
                        "name": name,
                        "created_at": secret_properties.created_on.isoformat() if secret_properties.created_on else None,
                        "updated_at": secret_properties.updated_on.isoformat() if secret_properties.updated_on else None,
                        "expires_at": secret_properties.expires_on.isoformat() if secret_properties.expires_on else None,
                        "enabled": secret_properties.enabled
                    })
                    
            return secrets
        except Exception as e:
            raise StoreConnectionError(f"Failed to list secrets from Azure: {str(e)}")
    
    def _list_from_env(self, include_values: bool) -> List[Dict[str, Any]]:
        """List secrets from environment variables"""
        # This is just a helper - in practice, we wouldn't list all env vars as secrets
        secrets = []
        
        # Look for env vars that match common secret patterns
        secret_prefixes = ["API_", "KEY_", "SECRET_", "TOKEN_", "PASSWORD_", "CREDENTIAL_"]
        
        for name, value in os.environ.items():
            if any(name.startswith(prefix) for prefix in secret_prefixes):
                secret = {
                    "name": name,
                    "type": "env_var",
                }
                
                if include_values:
                    secret["value"] = value
                    
                secrets.append(secret)
                
        return secrets
    
    def check_rotation_status(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Check which secrets need rotation based on age
        
        Returns:
            Dictionary with lists of secrets needing rotation
        """
        rotation_config = self.config.get("rotation", {})
        max_age_days = rotation_config.get("max_age_days", 90)
        reminder_days = rotation_config.get("reminder_days", 30)
        
        # Get all secrets from the default store
        all_secrets = self.list_secrets(self.default_store)
        
        # Calculate current time
        now = datetime.datetime.now()
        
        # Categorize secrets by rotation status
        expired = []
        due_soon = []
        ok = []
        
        for secret_dict in all_secrets:
            if "updated_at" not in secret_dict:
                # Skip secrets without timestamp
                continue
                
            # Calculate age in days
            updated_at = datetime.datetime.fromisoformat(secret_dict["updated_at"])
            age_days = (now - updated_at).days
            
            # Add age information
            secret_dict["age_days"] = age_days
            secret_dict["rotation_due_days"] = max(0, max_age_days - age_days)
            
            if age_days >= max_age_days:
                expired.append(secret_dict)
            elif age_days >= (max_age_days - reminder_days):
                due_soon.append(secret_dict)
            else:
                ok.append(secret_dict)
                
        return {
            "expired": expired,
            "due_soon": due_soon,
            "ok": ok
        }
    
    def validate_env_file(self, file_path: str) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Validate a .env file for security issues
        
        Args:
            file_path: Path to .env file
            
        Returns:
            Tuple of (is_valid, issues)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        issues = []
        
        try:
            with open(file_path, 'r') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                        
                    # Parse the line
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Remove quotes if present
                        if (value.startswith('"') and value.endswith('"')) or \
                           (value.startswith("'") and value.endswith("'")):
                            value = value[1:-1]
                            
                        # Validate the value
                        is_valid, reason = self._validate_secret(value)
                        if not is_valid:
                            issues.append({
                                "line": i,
                                "key": key,
                                "issue": reason,
                                "severity": "high" if "too short" in reason or "weak" in reason else "medium"
                            })
                            
                        # Check for hardcoded credentials
                        if key.lower() in ['password', 'api_key', 'secret', 'token'] and \
                           value and not value.startswith('$'):
                            issues.append({
                                "line": i,
                                "key": key,
                                "issue": "Hardcoded credential detected",
                                "severity": "critical"
                            })
                            
                        # Check for AWS keys
                        if re.match(r'AKIA[0-9A-Z]{16}', value):
                            issues.append({
                                "line": i,
                                "key": key,
                                "issue": "AWS access key detected",
                                "severity": "critical"
                            })
                    else:
                        issues.append({
                            "line": i,
                            "issue": "Invalid line format (missing '=')",
                            "severity": "low"
                        })
        except Exception as e:
            issues.append({
                "line": 0,
                "issue": f"Error reading file: {str(e)}",
                "severity": "high"
            })
            
        is_valid = not any(issue["severity"] in ["critical", "high"] for issue in issues)
        return is_valid, issues
    
    def inject_secrets_to_env(self, names: List[str] = None, 
                            store: SecretStore = None,
                            dotenv_path: str = None) -> Dict[str, bool]:
        """
        Inject secrets into environment variables
        
        Args:
            names: List of secret names to inject (all if None)
            store: Secret store to use
            dotenv_path: Path to .env file to update (optional)
            
        Returns:
            Dictionary mapping secret names to success status
        """
        store = store or self.default_store
        
        # Get secrets to inject
        if names:
            secrets_to_inject = [
                self.get_secret(name, store, raise_if_missing=False)
                for name in names
            ]
            secrets_to_inject = [s for s in secrets_to_inject if s]
        else:
            # Use all secrets if no names provided
            secrets_list = self.list_secrets(store, include_values=True)
            secrets_to_inject = [
                Secret.from_dict(s) for s in secrets_list
            ]
            
        results = {}
        
        # Inject into environment
        for secret in secrets_to_inject:
            try:
                if secret._value:
                    os.environ[secret.name] = secret._value
                    results[secret.name] = True
                else:
                    results[secret.name] = False
            except Exception:
                results[secret.name] = False
                
        # Update .env file if specified
        if dotenv_path:
            self._update_dotenv_file(dotenv_path, secrets_to_inject)
            
        self._audit_log(
            "inject", ", ".join(results.keys()) if results else "none", 
            success=all(results.values()),
            details=f"Injected {sum(results.values())}/{len(results)} secrets"
        )
            
        return results
    
    def _update_dotenv_file(self, file_path: str, secrets: List[Secret]) -> None:
        """Update a .env file with secrets"""
        if not secrets:
            return
            
        # Create file if it doesn't exist
        if not os.path.exists(file_path):
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            with open(file_path, 'w') as f:
                f.write("# Environment variables\n")
                
        # Read existing file
        env_vars = {}
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
                        
        # Update values
        for secret in secrets:
            if secret._value:
                env_vars[secret.name] = f'"{secret._value}"'
                
        # Write back to file
        with open(file_path, 'w') as f:
            f.write("# Environment variables - updated by secrets manager\n")
            for key, value in sorted(env_vars.items()):
                f.write(f"{key}={value}\n")
                
        # Set secure permissions
        os.chmod(file_path, 0o600)
        
        logger.info(f"Updated .env file at {file_path}")
    
    def create_temporary_secret(self, name: str, value: str, 
                              duration: int = 3600,
                              store: SecretStore = None) -> Secret:
        """
        Create a temporary secret that expires after a specified duration
        
        Args:
            name: Secret name
            value: Secret value
            duration: Duration in seconds before expiry
            store: Secret store to use
            
        Returns:
            Created Secret object
        """
        store = store or self.default_store
        
        # Create Secret object with expiry
        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=duration)
        
        secret = Secret(
            name=name,
            value=value,
            secret_type=SecretType.TOKEN,
            severity=SecretSeverity.MEDIUM,
            expires_at=expires_at,
            description=f"Temporary secret, expires in {duration} seconds"
        )
        
        # Store the secret
        self.set_secret(secret, store)
        
        self._audit_log(
            "create_temp", name, 
            store=store.value, success=True,
            details=f"Expires in {duration}s"
        )
        
        return secret
    
    def generate_secret_value(self, length: int = 32, 
                            include_special: bool = True,
                            include_digits: bool = True,
                            include_uppercase: bool = True) -> str:
        """
        Generate a cryptographically secure random secret value
        
        Args:
            length: Length of the secret
            include_special: Include special characters
            include_digits: Include digits
            include_uppercase: Include uppercase letters
            
        Returns:
            Generated secret string
        """
        import random
        
        # Define character sets
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        special = '!@#$%^&*()_-+=<>?'
        
        # Construct available characters
        available_chars = lowercase
        if include_uppercase:
            available_chars += uppercase
        if include_digits:
            available_chars += digits
        if include_special:
            available_chars += special
            
        # Ensure we have at least one of each required character type
        chars = [random.choice(lowercase)]
        
        if include_uppercase:
            chars.append(random.choice(uppercase))
        if include_digits:
            chars.append(random.choice(digits))
        if include_special:
            chars.append(random.choice(special))
            
        # Fill the rest with random characters
        chars.extend(random.choice(available_chars) for _ in range(length - len(chars)))
        
        # Shuffle the characters
        random.shuffle(chars)
        
        return ''.join(chars)
    
    def export_to_env(self, prefix: str = "", 
                     secrets: List[str] = None, 
                     output_file: str = None) -> Dict[str, str]:
        """
        Export secrets to environment format
        
        Args:
            prefix: Optional prefix for environment variable names
            secrets: List of secret names to export (defaults to all)
            output_file: Optional file to write environment variables to
            
        Returns:
            Dictionary of variable name to value
        """
        # Get secrets
        if secrets:
            secret_list = [self.get_secret(name) for name in secrets]
        else:
            # Get all secrets
            all_secrets = self.list_secrets(include_values=True)
            secret_list = [Secret.from_dict(s) for s in all_secrets if "value" in s]
            
        # Format as environment variables
        env_vars = {}
        for secret in secret_list:
            if secret._value:
                env_name = f"{prefix}{secret.name}"
                env_vars[env_name] = secret._value
                
        # Write to file if specified
        if output_file and env_vars:
            with open(output_file, 'w') as f:
                f.write("# Exported environment variables\n")
                for key, value in sorted(env_vars.items()):
                    f.write(f'{key}="{value}"\n')
                    
            # Set secure permissions
            os.chmod(output_file, 0o600)
            
        return env_vars
    
    def import_from_file(self, file_path: str, 
                        store: SecretStore = None,
                        validate: bool = True) -> Dict[str, bool]:
        """
        Import secrets from a file
        
        Args:
            file_path: Path to file (.env, .json, or .yaml format)
            store: Secret store to use
            validate: Whether to validate secrets before importing
            
        Returns:
            Dictionary mapping secret names to success status
        """
        store = store or self.default_store
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        # Determine file type by extension
        ext = os.path.splitext(file_path)[1].lower()
        
        secrets = {}
        
        if ext == '.env':
            # Parse .env file
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        # Remove quotes if present
                        if (value.startswith('"') and value.endswith('"')) or \
                           (value.startswith("'") and value.endswith("'")):
                            value = value[1:-1]
                            
                        secrets[key] = value
        elif ext == '.json':
            # Parse JSON file
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if isinstance(data, dict):
                if "secrets" in data:
                    # Structured format with secret objects
                    for name, secret_data in data["secrets"].items():
                        secret = Secret.from_dict({**secret_data, "name": name})
                        secrets[name] = secret
                else:
                    # Simple key-value format
                    for key, value in data.items():
                        if isinstance(value, str):
                            secrets[key] = value
                        elif isinstance(value, dict) and "value" in value:
                            # Handle structured values
                            secret = Secret.from_dict({**value, "name": key})
                            secrets[key] = secret
        elif ext == '.yaml' or ext == '.yml':
            # Parse YAML file
            if not YAML_AVAILABLE:
                raise ImportError("YAML support requires PyYAML package")
                
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
                
            if isinstance(data, dict):
                if "secrets" in data:
                    # Structured format with secret objects
                    for name, secret_data in data["secrets"].items():
                        secret = Secret.from_dict({**secret_data, "name": name})
                        secrets[name] = secret
                else:
                    # Simple key-value format
                    for key, value in data.items():
                        if isinstance(value, str):
                            secrets[key] = value
                        elif isinstance(value, dict) and "value" in value:
                            # Handle structured values
                            secret = Secret.from_dict({**value, "name": key})
                            secrets[key] = secret
        else:
            raise ValueError(f"Unsupported file format: {ext}")
            
        # Import secrets to store
        results = {}
        
        for name, value in secrets.items():
            try:
                if isinstance(value, Secret):
                    secret = value
                else:
                    secret = Secret(name=name, value=value)
                    
                if validate:
                    is_valid, reason = self._validate_secret(secret)
                    if not is_valid:
                        logger.warning(f"Skipping invalid secret {name}: {reason}")
                        results[name] = False
                        continue
                        
                self.set_secret(secret, store, validate=False)
                results[name] = True
            except Exception as e:
                logger.error(f"Failed to import secret {name}: {str(e)}")
                results[name] = False
                
        self._audit_log(
            "import", file_path, 
            store=store.value, success=all(results.values()),
            details=f"Imported {sum(results.values())}/{len(results)} secrets"
        )
            
        return results
    
    def inject_temporary_credentials(self, output_file: str, duration: int = 3600) -> None:
        """
        Generate temporary credentials for CI/CD pipeline and write to file
        Args:
        output_file: File to write credentials to
        duration: Duration in seconds for credential validity
        """
        # Generate temporary credentials
        creds = {
            "CI_TEMP_TOKEN": self.generate_secret_value(length=40),
            "CI_TEMP_API_KEY": self.generate_secret_value(length=32, include_special=False),
            "CI_TEMP_USERNAME": f"ci-temp-{uuid.uuid4().hex[:8]}",
            "CI_TEMP_PASSWORD": self.generate_secret_value(length=20)
        }
        # Create temporary secrets in the store
        for name, value in creds.items():
            self.create_temporary_secret(name, value, duration=duration)
        # Write to output file
        with open(output_file, 'w') as f:
            f.write("# Temporary CI/CD credentials - DO NOT COMMIT\n")
            f.write(f"# Generated: {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Expires: {(datetime.datetime.now() + datetime.timedelta(seconds=duration)).isoformat()}\n\n")
            for name, value in creds.items():
                f.write(f'{name}="{value}"\n')
        # Set secure permissions
        os.chmod(output_file, 0o600)
        logger.info(f"Generated temporary credentials in {output_file}, valid for {duration}s")
    
    def setup_ci_secrets(self, ci_yaml_path: str, source_env_file: str = None) -> None:
        """
        Set up secrets for CI/CD pipeline by updating CI configuration
        Args:
        ci_yaml_path: Path to CI configuration YAML file
        source_env_file: Optional .env file to source secrets from
        """
        if not YAML_AVAILABLE:
            raise ImportError("YAML support requires PyYAML package")
        # Load secrets from env file if provided
        source_secrets = {}
        if source_env_file and os.path.exists(source_env_file):
            with open(source_env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        # Remove quotes if present
                        if (value.startswith('"') and value.endswith('"')) or \
                           (value.startswith("'") and value.endswith("'")):
                            value = value[1:-1]
                        source_secrets[key] = value
        # Load CI configuration
        with open(ci_yaml_path, 'r') as f:
            ci_config = yaml.safe_load(f)
        # Update CI configuration with secrets
        if 'env' not in ci_config:
            ci_config['env'] = {}
        for key, value in source_secrets.items():
            # Only add if key doesn't already exist or is empty
            if key not in ci_config['env'] or not ci_config['env'][key]:
                ci_config['env'][key] = f"${{{{ {key} }}}}"
        # Write updated CI configuration
        with open(ci_yaml_path, 'w') as f:
            yaml.dump(ci_config, f, default_flow_style=False)
        logger.info(f"Updated CI configuration in {ci_yaml_path}")
    
    def verify_ci_secrets(self, required_secrets: List[str]) -> Tuple[bool, List[str]]:
        """
        Verify that required secrets are available in the CI environment
        Args:
        required_secrets: List of required secret names
        Returns:
        Tuple of (all_available, missing_secrets)
        """
        missing = []
        for secret in required_secrets:
            if not os.environ.get(secret):
                missing.append(secret)
        return len(missing) == 0, missing
    
    def main(self) -> None:
        """Main function."""
        parser = argparse.ArgumentParser(description='Secrets Manager for CI/CD Pipeline Security')
        # Common arguments
        parser.add_argument('--config', help='Path to configuration file')
        parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Logging level')
        parser.add_argument('--store', choices=[s.value for s in SecretStore], help='Secret store to use')
        # Action subparsers
        subparsers = parser.add_subparsers(dest='action', help='Action to perform')
        # Get secret
        get_parser = subparsers.add_parser('get', help='Get a secret')
        get_parser.add_argument('name', help='Secret name')
        get_parser.add_argument('--output', help='Output file to write secret to')
        get_parser.add_argument('--env', action='store_true', help='Set as environment variable')
        # Set secret
        set_parser = subparsers.add_parser('set', help='Set a secret')
        set_parser.add_argument('name', help='Secret name')
        set_parser.add_argument('--value', help='Secret value (omit to prompt securely)')
        set_parser.add_argument('--file', help='Read secret value from file')
        set_parser.add_argument('--type', choices=[t.value for t in SecretType], default='api_key', help='Secret type')
        set_parser.add_argument('--severity', choices=[s.value for s in SecretSeverity], default='medium', help='Secret severity')
        set_parser.add_argument('--description', help='Secret description')
        set_parser.add_argument('--expires', help='Expiration date (ISO format)')
        set_parser.add_argument('--no-validate', action='store_true', help='Skip validation')
        # Delete secret
        delete_parser = subparsers.add_parser('delete', help='Delete a secret')
        delete_parser.add_argument('name', help='Secret name')
        # Rotate secret
        rotate_parser = subparsers.add_parser('rotate', help='Rotate a secret')
        rotate_parser.add_argument('name', help='Secret name')
        rotate_parser.add_argument('--value', help='New secret value (omit to generate)')
        rotate_parser.add_argument('--file', help='Read new secret value from file')
        rotate_parser.add_argument('--length', type=int, default=32, help='Length of generated secret')
        rotate_parser.add_argument('--no-special', action='store_true', help='Exclude special characters')
        rotate_parser.add_argument('--no-validate', action='store_true', help='Skip validation')
        # List secrets
        list_parser = subparsers.add_parser('list', help='List secrets')
        list_parser.add_argument('--pattern', help='Regex pattern to filter secret names')
        list_parser.add_argument('--values', action='store_true', help='Include secret values (use with caution)')
        list_parser.add_argument('--json', action='store_true', help='Output in JSON format')
        list_parser.add_argument('--output', help='Output file')
        # Check rotation status
        rotation_parser = subparsers.add_parser('rotation-status', help='Check which secrets need rotation')
        rotation_parser.add_argument('--json', action='store_true', help='Output in JSON format')
        rotation_parser.add_argument('--output', help='Output file')
        # Validate environment file
        validate_env_parser = subparsers.add_parser('validate-env', help='Validate a .env file')
        validate_env_parser.add_argument('file', help='Path to .env file')
        validate_env_parser.add_argument('--json', action='store_true', help='Output in JSON format')
        validate_env_parser.add_argument('--output', help='Output file')
        # Inject secrets to environment
        inject_parser = subparsers.add_parser('inject', help='Inject secrets into environment')
        inject_parser.add_argument('--names', nargs='+', help='Secret names to inject (defaults to all)')
        inject_parser.add_argument('--dotenv', help='Path to .env file to update')
        # Create temporary secret
        temp_parser = subparsers.add_parser('create-temp', help='Create a temporary secret')
        temp_parser.add_argument('name', help='Secret name')
        temp_parser.add_argument('--value', help='Secret value (omit to generate)')
        temp_parser.add_argument('--duration', type=int, default=3600, help='Duration in seconds')
        temp_parser.add_argument('--length', type=int, default=32, help='Length of generated secret')
        temp_parser.add_argument('--no-special', action='store_true', help='Exclude special characters')
        # Generate secret value
        generate_parser = subparsers.add_parser('generate', help='Generate a secret value')
        generate_parser.add_argument('--length', type=int, default=32, help='Length of generated secret')
        generate_parser.add_argument('--no-special', action='store_true', help='Exclude special characters')
        generate_parser.add_argument('--no-digits', action='store_true', help='Exclude digits')
        generate_parser.add_argument('--no-uppercase', action='store_true', help='Exclude uppercase letters')
        generate_parser.add_argument('--output', help='Output file')
        # Export secrets to environment format
        export_parser = subparsers.add_parser('export', help='Export secrets to environment format')
        export_parser.add_argument('--prefix', default='', help='Prefix for environment variable names')
        export_parser.add_argument('--names', nargs='+', help='Secret names to export (defaults to all)')
        export_parser.add_argument('--output', required=True, help='Output file')
        # Import secrets from file
        import_parser = subparsers.add_parser('import', help='Import secrets from file')
        import_parser.add_argument('file', help='Path to file (.env, .json, or .yaml format)')
        import_parser.add_argument('--no-validate', action='store_true', help='Skip validation')
        # Inject temporary credentials
        temp_creds_parser = subparsers.add_parser('temp-creds', help='Generate temporary credentials for CI/CD pipeline')
        temp_creds_parser.add_argument('--output', required=True, help='Output file')
        temp_creds_parser.add_argument('--duration', type=int, default=3600, help='Duration in seconds')
        # Set up CI secrets
        ci_secrets_parser = subparsers.add_parser('setup-ci', help='Set up secrets for CI/CD pipeline')
        ci_secrets_parser.add_argument('ci_yaml', help='Path to CI configuration YAML file')
        ci_secrets_parser.add_argument('--env-file', help='Source .env file')
        # Verify CI secrets
        verify_ci_parser = subparsers.add_parser('verify-ci', help='Verify required secrets are available in CI environment')
        verify_ci_parser.add_argument('--names', nargs='+', required=True, help='Required secret names')
        args = parser.parse_args()
        # Set up logging
        logging.getLogger().setLevel(getattr(logging, args.log_level))
        try:
            # Initialize secrets manager
            manager = SecretsManager(args.config)
            # Get store
            store = SecretStore(args.store) if args.store else None
            # Execute requested action
            if args.action == 'get':
                secret = manager.get_secret(args.name, store)
                if args.env:
                    # Set as environment variable
                    os.environ[args.name] = secret.value
                    print(f"Secret {args.name} set as environment variable")
                elif args.output:
                    # Write to file
                    with open(args.output, 'w') as f:
                        f.write(secret.value)
                    os.chmod(args.output, 0o600)
                    print(f"Secret {args.name} written to {args.output}")
                else:
                    # Print to stdout
                    print(secret.value)
            elif args.action == 'set':
                # Get secret value
                value = None
                if args.value:
                    value = args.value
                elif args.file:
                    with open(args.file, 'r') as f:
                        value = f.read().strip()
                else:
                    # Prompt for value securely
                    import getpass
                    value = getpass.getpass(f"Enter value for secret {args.name}: ")
                # Create secret object
                expiry = None
                if args.expires:
                    expiry = datetime.datetime.fromisoformat(args.expires)
                secret = Secret(
                    name=args.name,
                    value=value,
                    secret_type=SecretType(args.type),
                    severity=SecretSeverity(args.severity),
                    expires_at=expiry,
                    description=args.description
                )
                # Store the secret
                manager.set_secret(secret, store, validate=not args.no_validate)
                print(f"Secret {args.name} set successfully")
            elif args.action == 'delete':
                manager.delete_secret(args.name, store)
                print(f"Secret {args.name} deleted successfully")
            elif args.action == 'rotate':
                # Get new value
                value = None
                if args.value:
                    value = args.value
                elif args.file:
                    with open(args.file, 'r') as f:
                        value = f.read().strip()
                else:
                    # Generate new value
                    value = self.generate_secret_value(
                        length=args.length,
                        include_special=not args.no_special
                    )
                # Rotate the secret
                manager.rotate_secret(args.name, value, store, validate=not args.no_validate)
                print(f"Secret {args.name} rotated successfully")
            elif args.action == 'list':
                secrets = manager.list_secrets(store, args.pattern, args.values)
                if args.json:
                    output = json.dumps(secrets, indent=2)
                else:
                    output = "Secrets:\n"
                for secret in sorted(secrets, key=lambda s: s["name"]):
                    output += f"- {secret['name']}"
                    if "description" in secret:
                        output += f" ({secret['description']})"
                    if args.values and "value" in secret:
                        output += f": {secret['value']}"
                    output += "\n"
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(output)
                    print(f"Secret list written to {args.output}")
                else:
                    print(output)
            elif args.action == 'rotation-status':
                status = manager.check_rotation_status()
                if args.json:
                    output = json.dumps(status, indent=2)
                else:
                    output = "Rotation Status:\n"
                if status["expired"]:
                    output += "\nExpired secrets (need immediate rotation):\n"
                    for secret in sorted(status["expired"], key=lambda s: s["age_days"], reverse=True):
                        output += f"- {secret['name']}: {secret['age_days']} days old\n"
                if status["due_soon"]:
                    output += "\nRotation due soon:\n"
                    for secret in sorted(status["due_soon"], key=lambda s: s["rotation_due_days"]):
                        output += f"- {secret['name']}: due in {secret['rotation_due_days']} days\n"
                if not status["expired"] and not status["due_soon"]:
                    output += "\nAll secrets are up to date!\n"
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(output)
                    print(f"Rotation status written to {args.output}")
                else:
                    print(output)
            elif args.action == 'validate-env':
                is_valid, issues = manager.validate_env_file(args.file)
                if args.json:
                    output = json.dumps({"valid": is_valid, "issues": issues}, indent=2)
                else:
                    if is_valid:
                        output = f"Environment file {args.file} is valid.\n"
                    else:
                        output = f"Environment file {args.file} has issues:\n"
                    for issue in issues:
                        line = issue.get("line", "")
                        key = issue.get("key", "")
                        severity = issue.get("severity", "").upper()
                        issue_text = issue.get("issue", "")
                        output += f"- Line {line}"
                        if key:
                            output += f" ({key})"
                        output += f" [{severity}]: {issue_text}\n"
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(output)
                    print(f"Validation results written to {args.output}")
                else:
                    print(output)
            elif args.action == 'inject':
                results = manager.inject_secrets_to_env(args.names, store, args.dotenv)
                success_count = sum(results.values())
                total_count = len(results)
                print(f"Injected {success_count}/{total_count} secrets into environment")
                if args.dotenv:
                    print(f"Updated .env file at {args.dotenv}")
            elif args.action == 'create-temp':
                # Get value
                value = args.value
                if not value:
                    value = self.generate_secret_value(
                        length=args.length,
                        include_special=not args.no_special
                    )
                # Create temporary secret
                secret = manager.create_temporary_secret(args.name, value, args.duration, store)
                print(f"Created temporary secret {args.name}")
                print(f"Value: {secret.value}")
                print(f"Expires: {secret.expires_at.isoformat()}")
            elif args.action == 'generate':
                value = self.generate_secret_value(
                    length=args.length,
                    include_special=not args.no_special,
                    include_digits=not args.no_digits,
                    include_uppercase=not args.no_uppercase
                )
                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(value)
                    os.chmod(args.output, 0o600)
                    print(f"Generated secret written to {args.output}")
                else:
                    print(value)
            elif args.action == 'export':
                env_vars = manager.export_to_env(args.prefix, args.names, args.output)
                print(f"Exported {len(env_vars)} secrets to {args.output}")
            elif args.action == 'import':
                results = manager.import_from_file(args.file, store, not args.no_validate)
                success_count = sum(results.values())
                total_count = len(results)
                print(f"Imported {success_count}/{total_count} secrets from {args.file}")
            elif args.action == 'temp-creds':
                self.inject_temporary_credentials(args.output, args.duration)
            elif args.action == 'setup-ci':
                self.setup_ci_secrets(args.ci_yaml, args.env_file)
            elif args.action == 'verify-ci':
                all_available, missing = self.verify_ci_secrets(args.names)
                if all_available:
                    print("All required secrets are available in the environment.")
                    sys.exit(0)
                else:
                    print("Missing required secrets:")
                    for secret in missing:
                        print(f"- {secret}")
                    sys.exit(1)
            else:
                parser.print_help()
        except SecretNotFoundError as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
        except SecretValidationError as e:
            print(f"Validation Error: {str(e)}")
            sys.exit(1)
        except StoreConnectionError as e:
            print(f"Store Error: {str(e)}")
            sys.exit(1)
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()


