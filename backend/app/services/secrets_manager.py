"""
Secrets Manager Abstraction
============================
Provides unified interface for secrets management across AWS, GCP, and Vault.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from enum import Enum

from app.config.logging import get_logger
from app.config.settings import get_settings

logger = get_logger(__name__)


class SecretsProvider(str, Enum):
    """Supported secrets providers."""
    AWS = "aws"
    GCP = "gcp"
    VAULT = "vault"
    ENV = "env"  # Fallback to environment variables (dev only)


class SecretsManagerInterface(ABC):
    """Abstract interface for secrets management."""
    
    @abstractmethod
    async def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret value by name."""
        pass
    
    @abstractmethod
    async def get_secret_dict(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """Get secret as dictionary (for JSON secrets)."""
        pass


class AWSSecretsManager(SecretsManagerInterface):
    """AWS Secrets Manager implementation."""
    
    def __init__(self, region: str = "us-east-1"):
        """Initialize AWS Secrets Manager client."""
        self.region = region
        self._client = None
    
    async def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from AWS Secrets Manager."""
        try:
            import boto3
            import json
            
            if not self._client:
                self._client = boto3.client('secretsmanager', region_name=self.region)
            
            response = self._client.get_secret_value(SecretId=secret_name)
            
            if 'SecretString' in response:
                return response['SecretString']
            else:
                # Binary secret
                import base64
                return base64.b64decode(response['SecretBinary']).decode('utf-8')
                
        except Exception as e:
            logger.error(f"Failed to get secret from AWS: {e}")
            return None
    
    async def get_secret_dict(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """Get secret as dictionary."""
        import json
        
        secret_str = await self.get_secret(secret_name)
        if secret_str:
            try:
                return json.loads(secret_str)
            except json.JSONDecodeError:
                logger.error(f"Secret {secret_name} is not valid JSON")
                return None
        return None


class GCPSecretsManager(SecretsManagerInterface):
    """Google Cloud Secret Manager implementation."""
    
    def __init__(self, project_id: str):
        """Initialize GCP Secret Manager client."""
        self.project_id = project_id
        self._client = None
    
    async def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from GCP Secret Manager."""
        try:
            from google.cloud import secretmanager
            
            if not self._client:
                self._client = secretmanager.SecretManagerServiceClient()
            
            name = f"projects/{self.project_id}/secrets/{secret_name}/versions/latest"
            response = self._client.access_secret_version(request={"name": name})
            
            return response.payload.data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to get secret from GCP: {e}")
            return None
    
    async def get_secret_dict(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """Get secret as dictionary."""
        import json
        
        secret_str = await self.get_secret(secret_name)
        if secret_str:
            try:
                return json.loads(secret_str)
            except json.JSONDecodeError:
                logger.error(f"Secret {secret_name} is not valid JSON")
                return None
        return None


class VaultSecretsManager(SecretsManagerInterface):
    """HashiCorp Vault implementation."""
    
    def __init__(self, vault_addr: str, vault_token: str):
        """Initialize Vault client."""
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self._client = None
    
    async def get_secret(self, secret_path: str) -> Optional[str]:
        """Get secret from Vault."""
        try:
            import hvac
            
            if not self._client:
                self._client = hvac.Client(url=self.vault_addr, token=self.vault_token)
            
            secret = self._client.secrets.kv.v2.read_secret_version(path=secret_path)
            
            # Vault returns nested data
            return secret['data']['data'].get('value')
            
        except Exception as e:
            logger.error(f"Failed to get secret from Vault: {e}")
            return None
    
    async def get_secret_dict(self, secret_path: str) -> Optional[Dict[str, Any]]:
        """Get secret as dictionary."""
        try:
            import hvac
            
            if not self._client:
                self._client = hvac.Client(url=self.vault_addr, token=self.vault_token)
            
            secret = self._client.secrets.kv.v2.read_secret_version(path=secret_path)
            return secret['data']['data']
            
        except Exception as e:
            logger.error(f"Failed to get secret dict from Vault: {e}")
            return None


class EnvSecretsManager(SecretsManagerInterface):
    """Environment variables fallback (development only)."""
    
    async def get_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from environment variables."""
        import os
        
        value = os.getenv(secret_name)
        if not value:
            logger.warning(f"Secret {secret_name} not found in environment")
        return value
    
    async def get_secret_dict(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """Get secret as dictionary."""
        import os
        import json
        
        value = os.getenv(secret_name)
        if value:
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                logger.error(f"Environment variable {secret_name} is not valid JSON")
                return None
        return None


# ============================================================================
# Factory
# ============================================================================

def get_secrets_manager() -> SecretsManagerInterface:
    """
    Get secrets manager based on configuration.
    
    Returns:
        Configured secrets manager instance
    """
    settings = get_settings()
    
    provider = getattr(settings, 'SECRETS_PROVIDER', 'env').lower()
    
    if provider == SecretsProvider.AWS:
        region = getattr(settings, 'AWS_REGION', 'us-east-1')
        return AWSSecretsManager(region=region)
    
    elif provider == SecretsProvider.GCP:
        project_id = getattr(settings, 'GCP_PROJECT_ID', None)
        if not project_id:
            logger.error("GCP_PROJECT_ID not configured")
            return EnvSecretsManager()
        return GCPSecretsManager(project_id=project_id)
    
    elif provider == SecretsProvider.VAULT:
        vault_addr = getattr(settings, 'VAULT_ADDR', None)
        vault_token = getattr(settings, 'VAULT_TOKEN', None)
        if not vault_addr or not vault_token:
            logger.error("VAULT_ADDR or VAULT_TOKEN not configured")
            return EnvSecretsManager()
        return VaultSecretsManager(vault_addr=vault_addr, vault_token=vault_token)
    
    else:
        # Default to environment variables
        logger.warning("Using environment variables for secrets (development only)")
        return EnvSecretsManager()


# ============================================================================
# Helper Functions
# ============================================================================

async def get_imap_credentials(tenant_id: str) -> Optional[Dict[str, str]]:
    """
    Get IMAP credentials for a tenant.
    
    Args:
        tenant_id: Tenant identifier
        
    Returns:
        Dictionary with 'user' and 'password' keys
    """
    secrets_manager = get_secrets_manager()
    
    secret_name = f"phishnet/mode1/imap/{tenant_id}"
    
    credentials = await secrets_manager.get_secret_dict(secret_name)
    
    if credentials and 'user' in credentials and 'password' in credentials:
        return credentials
    else:
        logger.error(f"Invalid IMAP credentials for tenant {tenant_id}")
        return None
