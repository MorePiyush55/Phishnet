"""Secret management service for secure credential handling."""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from app.config.settings import Settings, Environment

logger = logging.getLogger(__name__)


class SecretManagerError(Exception):
    """Base exception for secret management errors."""
    pass


class SecretProvider(ABC):
    """Abstract base class for secret providers."""
    
    @abstractmethod
    async def get_secret(self, secret_name: str) -> Dict[str, Any]:
        """Get secret by name."""
        pass
    
    @abstractmethod
    async def get_secret_value(self, secret_name: str, key: str) -> Optional[str]:
        """Get specific value from secret."""
        pass


class AWSSecretsManagerProvider(SecretProvider):
    """AWS Secrets Manager provider."""
    
    def __init__(self, region: str, secret_name: str):
        self.region = region
        self.secret_name = secret_name
        self._client = None
    
    async def _get_client(self):
        """Get AWS Secrets Manager client."""
        if self._client is None:
            try:
                import boto3
                from botocore.exceptions import ClientError
                self._client = boto3.client('secretsmanager', region_name=self.region)
                self._client_error = ClientError
            except ImportError:
                raise SecretManagerError("boto3 not installed. Install with: pip install boto3")
        return self._client
    
    async def get_secret(self, secret_name: Optional[str] = None) -> Dict[str, Any]:
        """Get secret from AWS Secrets Manager."""
        name = secret_name or self.secret_name
        client = await self._get_client()
        
        try:
            response = client.get_secret_value(SecretId=name)
            return json.loads(response['SecretString'])
        except self._client_error as e:
            logger.error(f"Failed to get secret {name} from AWS: {e}")
            raise SecretManagerError(f"Failed to get secret: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in secret {name}: {e}")
            raise SecretManagerError(f"Invalid secret format: {e}")
    
    async def get_secret_value(self, secret_name: str, key: str) -> Optional[str]:
        """Get specific value from AWS secret."""
        secret = await self.get_secret(secret_name)
        return secret.get(key)


class GCPSecretManagerProvider(SecretProvider):
    """Google Cloud Secret Manager provider."""
    
    def __init__(self, project_id: str, secret_name: str):
        self.project_id = project_id
        self.secret_name = secret_name
        self._client = None
    
    async def _get_client(self):
        """Get GCP Secret Manager client."""
        if self._client is None:
            try:
                from google.cloud import secretmanager
                self._client = secretmanager.SecretManagerServiceClient()
            except ImportError:
                raise SecretManagerError("google-cloud-secret-manager not installed. Install with: pip install google-cloud-secret-manager")
        return self._client
    
    async def get_secret(self, secret_name: Optional[str] = None) -> Dict[str, Any]:
        """Get secret from GCP Secret Manager."""
        name = secret_name or self.secret_name
        client = await self._get_client()
        
        try:
            secret_path = f"projects/{self.project_id}/secrets/{name}/versions/latest"
            response = client.access_secret_version(request={"name": secret_path})
            secret_data = response.payload.data.decode("UTF-8")
            return json.loads(secret_data)
        except Exception as e:
            logger.error(f"Failed to get secret {name} from GCP: {e}")
            raise SecretManagerError(f"Failed to get secret: {e}")
    
    async def get_secret_value(self, secret_name: str, key: str) -> Optional[str]:
        """Get specific value from GCP secret."""
        secret = await self.get_secret(secret_name)
        return secret.get(key)


class VaultProvider(SecretProvider):
    """HashiCorp Vault provider."""
    
    def __init__(self, vault_url: str, token: str):
        self.vault_url = vault_url.rstrip('/')
        self.token = token
        self._client = None
    
    async def _get_client(self):
        """Get Vault client."""
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(url=self.vault_url, token=self.token)
                if not self._client.is_authenticated():
                    raise SecretManagerError("Vault authentication failed")
            except ImportError:
                raise SecretManagerError("hvac not installed. Install with: pip install hvac")
        return self._client
    
    async def get_secret(self, secret_path: str) -> Dict[str, Any]:
        """Get secret from Vault."""
        client = await self._get_client()
        
        try:
            response = client.secrets.kv.v2.read_secret_version(path=secret_path)
            return response['data']['data']
        except Exception as e:
            logger.error(f"Failed to get secret {secret_path} from Vault: {e}")
            raise SecretManagerError(f"Failed to get secret: {e}")
    
    async def get_secret_value(self, secret_path: str, key: str) -> Optional[str]:
        """Get specific value from Vault secret."""
        secret = await self.get_secret(secret_path)
        return secret.get(key)


class DevelopmentProvider(SecretProvider):
    """Development provider that uses environment variables."""
    
    def __init__(self):
        import os
        self.env = os.environ
    
    async def get_secret(self, secret_name: str) -> Dict[str, Any]:
        """Get secret from environment variables (development only)."""
        # In development, we just return the environment variables
        # This is not secure and should only be used for development
        secrets = {}
        
        # Common secret keys
        secret_keys = [
            "GEMINI_API_KEY", "GOOGLE_GEMINI_API_KEY",
            "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY",
            "GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET",
            "SECRET_KEY", "DATABASE_URL"
        ]
        
        for key in secret_keys:
            value = self.env.get(key)
            if value:
                secrets[key] = value
        
        return secrets
    
    async def get_secret_value(self, secret_name: str, key: str) -> Optional[str]:
        """Get specific value from environment."""
        return self.env.get(key)


class SecretManager:
    """Unified secret manager that handles different providers."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self._provider: Optional[SecretProvider] = None
    
    def _get_provider(self) -> SecretProvider:
        """Get appropriate secret provider based on environment."""
        if self._provider:
            return self._provider
        
        if self.settings.ENVIRONMENT == Environment.DEVELOPMENT:
            self._provider = DevelopmentProvider()
        elif self.settings.AWS_SECRET_NAME and self.settings.AWS_REGION:
            self._provider = AWSSecretsManagerProvider(
                self.settings.AWS_REGION,
                self.settings.AWS_SECRET_NAME
            )
        elif self.settings.GCP_PROJECT_ID and self.settings.GCP_SECRET_NAME:
            self._provider = GCPSecretManagerProvider(
                self.settings.GCP_PROJECT_ID,
                self.settings.GCP_SECRET_NAME
            )
        elif self.settings.VAULT_URL and self.settings.VAULT_TOKEN:
            self._provider = VaultProvider(
                self.settings.VAULT_URL,
                self.settings.VAULT_TOKEN
            )
        else:
            # Fallback to development provider
            logger.warning("No secret provider configured, falling back to environment variables")
            self._provider = DevelopmentProvider()
        
        return self._provider
    
    async def get_api_keys(self) -> Dict[str, Optional[str]]:
        """Get all API keys from secret storage."""
        provider = self._get_provider()
        
        try:
            if isinstance(provider, DevelopmentProvider):
                secrets = await provider.get_secret("api_keys")
            else:
                # For production providers, get from configured secret
                secret_name = (
                    self.settings.AWS_SECRET_NAME or 
                    self.settings.GCP_SECRET_NAME or 
                    "api_keys"
                )
                secrets = await provider.get_secret(secret_name)
            
            return {
                "gemini_api_key": secrets.get("GEMINI_API_KEY") or secrets.get("GOOGLE_GEMINI_API_KEY"),
                "virustotal_api_key": secrets.get("VIRUSTOTAL_API_KEY"),
                "abuseipdb_api_key": secrets.get("ABUSEIPDB_API_KEY"),
                "gmail_client_id": secrets.get("GMAIL_CLIENT_ID"),
                "gmail_client_secret": secrets.get("GMAIL_CLIENT_SECRET"),
            }
        except Exception as e:
            logger.error(f"Failed to get API keys: {e}")
            return {
                "gemini_api_key": None,
                "virustotal_api_key": None,
                "abuseipdb_api_key": None,
                "gmail_client_id": None,
                "gmail_client_secret": None,
            }
    
    async def get_database_url(self) -> Optional[str]:
        """Get database URL from secret storage."""
        provider = self._get_provider()
        
        try:
            return await provider.get_secret_value("database", "DATABASE_URL")
        except Exception as e:
            logger.error(f"Failed to get database URL: {e}")
            return self.settings.DATABASE_URL
    
    async def get_jwt_secret(self) -> str:
        """Get JWT secret key from secret storage."""
        provider = self._get_provider()
        
        try:
            secret_key = await provider.get_secret_value("jwt", "SECRET_KEY")
            if secret_key and len(secret_key) >= 32:
                return secret_key
        except Exception as e:
            logger.error(f"Failed to get JWT secret: {e}")
        
        # Fallback to settings
        return self.settings.SECRET_KEY


# Global secret manager instance
_secret_manager: Optional[SecretManager] = None


def get_secret_manager(settings: Optional[Settings] = None) -> SecretManager:
    """Get global secret manager instance."""
    global _secret_manager
    
    if _secret_manager is None:
        from app.config.settings import get_settings
        settings = settings or get_settings()
        _secret_manager = SecretManager(settings)
    
    return _secret_manager
