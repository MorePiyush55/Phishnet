"""
Enhanced Feature Flags System - Dynamic feature toggling with advanced targeting
LaunchDarkly-style feature management with live configuration changes
"""

import json
import logging
import time
import asyncio
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import redis
from contextlib import asynccontextmanager

from app.core.redis_client import get_cache_manager
from app.config.logging import get_logger

logger = logging.getLogger(__name__)

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging" 
    PRODUCTION = "production"

class UserRole(Enum):
    USER = "user"
    ANALYST = "analyst"
    ADMIN = "admin"
    SYSTEM = "system"

@dataclass
class FeatureFlag:
    """Feature flag configuration"""
    key: str
    name: str
    description: str
    enabled: bool = False
    environments: List[Environment] = field(default_factory=list)
    roles: List[UserRole] = field(default_factory=list)
    rollout_percentage: float = 0.0  # 0-100%
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

class FeatureFlagManager:
    """
    Feature Flag Manager for PhishNet
    
    Manages dynamic feature toggles with:
    - Environment-based feature control
    - Role-based access control
    - Percentage-based rollouts
    - Time-based feature windows
    - Redis caching for performance
    - Safe defaults and fallbacks
    """
    
    def __init__(self, 
                 config_file: Optional[str] = None,
                 redis_url: Optional[str] = None,
                 current_env: Environment = Environment.DEVELOPMENT):
        self.config_file = config_file or "config/feature_flags.json"
        self.current_env = current_env
        self._flags: Dict[str, FeatureFlag] = {}
        self._redis_client = None
        self._cache_ttl = 300  # 5 minutes
        
        # Initialize Redis if available
        if redis_url:
            try:
                self._redis_client = redis.from_url(redis_url)
                self._redis_client.ping()
                logger.info("Feature flags Redis cache enabled")
            except Exception as e:
                logger.warning(f"Redis not available for feature flags: {e}")
        
        # Load feature flags
        self._load_flags()
        self._setup_default_flags()
    
    def _load_flags(self):
        """Load feature flags from configuration file"""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    
                for flag_data in data.get('flags', []):
                    flag = FeatureFlag(
                        key=flag_data['key'],
                        name=flag_data['name'],
                        description=flag_data['description'],
                        enabled=flag_data.get('enabled', False),
                        environments=[Environment(env) for env in flag_data.get('environments', [])],
                        roles=[UserRole(role) for role in flag_data.get('roles', [])],
                        rollout_percentage=flag_data.get('rollout_percentage', 0.0),
                        start_date=datetime.fromisoformat(flag_data['start_date']) if flag_data.get('start_date') else None,
                        end_date=datetime.fromisoformat(flag_data['end_date']) if flag_data.get('end_date') else None,
                        metadata=flag_data.get('metadata', {})
                    )
                    self._flags[flag.key] = flag
                    
                logger.info(f"Loaded {len(self._flags)} feature flags from {config_path}")
            else:
                logger.info(f"No feature flags config found at {config_path}, using defaults")
                
        except Exception as e:
            logger.error(f"Failed to load feature flags: {e}")
    
    def _setup_default_flags(self):
        """Setup default PhishNet feature flags"""
        default_flags = [
            FeatureFlag(
                key="auto_quarantine",
                name="Auto Quarantine",
                description="Automatically quarantine high-risk emails",
                enabled=False,
                environments=[Environment.STAGING, Environment.PRODUCTION],
                roles=[UserRole.ANALYST, UserRole.ADMIN],
                rollout_percentage=25.0,
                metadata={"risk_threshold": 80, "requires_approval": True}
            ),
            FeatureFlag(
                key="experimental_ml_heuristics",
                name="Experimental ML Heuristics",
                description="Advanced machine learning threat detection",
                enabled=False,
                environments=[Environment.DEVELOPMENT, Environment.STAGING],
                roles=[UserRole.ADMIN],
                rollout_percentage=10.0,
                metadata={"model_version": "v2.1", "confidence_threshold": 0.85}
            ),
            FeatureFlag(
                key="detonation_sandbox",
                name="Detonation Sandbox",
                description="Headless browser analysis of suspicious URLs",
                enabled=True,
                environments=[Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION],
                roles=[UserRole.ANALYST, UserRole.ADMIN],
                rollout_percentage=50.0,
                metadata={"timeout_seconds": 30, "max_concurrent": 5}
            ),
            FeatureFlag(
                key="realtime_threat_intel",
                name="Real-time Threat Intelligence",
                description="Live threat intelligence feeds integration",
                enabled=True,
                environments=[Environment.STAGING, Environment.PRODUCTION],
                roles=[UserRole.ANALYST, UserRole.ADMIN, UserRole.SYSTEM],
                rollout_percentage=75.0,
                metadata={"sources": ["virustotal", "abuseipdb"], "cache_ttl": 3600}
            ),
            FeatureFlag(
                key="advanced_analytics",
                name="Advanced Analytics Dashboard",
                description="Enhanced analytics and reporting features",
                enabled=True,
                environments=[Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION],
                roles=[UserRole.ANALYST, UserRole.ADMIN],
                rollout_percentage=100.0,
                metadata={"charts": ["risk_trends", "detection_rates"], "export_formats": ["pdf", "csv"]}
            ),
            FeatureFlag(
                key="gmail_integration",
                name="Gmail API Integration",
                description="Direct Gmail API integration for email ingestion",
                enabled=False,
                environments=[Environment.STAGING, Environment.PRODUCTION],
                roles=[UserRole.ADMIN, UserRole.SYSTEM],
                rollout_percentage=0.0,
                metadata={"requires_oauth": True, "batch_size": 50}
            ),
            FeatureFlag(
                key="websocket_notifications",
                name="WebSocket Notifications",
                description="Real-time notifications via WebSocket",
                enabled=True,
                environments=[Environment.DEVELOPMENT, Environment.STAGING, Environment.PRODUCTION],
                roles=[UserRole.USER, UserRole.ANALYST, UserRole.ADMIN],
                rollout_percentage=90.0,
                metadata={"heartbeat_interval": 30, "max_connections": 100}
            )
        ]
        
        # Add default flags if not already present
        for flag in default_flags:
            if flag.key not in self._flags:
                self._flags[flag.key] = flag
                logger.info(f"Added default feature flag: {flag.key}")
    
    def is_enabled(self, 
                   flag_key: str, 
                   user_role: Optional[UserRole] = None,
                   user_id: Optional[str] = None,
                   context: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if a feature flag is enabled for the given context
        
        Args:
            flag_key: Feature flag identifier
            user_role: User's role for role-based checks
            user_id: User ID for percentage rollouts
            context: Additional context for evaluation
            
        Returns:
            bool: True if feature is enabled
        """
        try:
            # Check cache first
            cache_key = f"flag:{flag_key}:{user_role}:{user_id}"
            if self._redis_client:
                cached = self._redis_client.get(cache_key)
                if cached is not None:
                    return json.loads(cached)
            
            # Get flag
            flag = self._flags.get(flag_key)
            if not flag:
                logger.warning(f"Feature flag not found: {flag_key}")
                return False
            
            # Check if flag is globally enabled
            if not flag.enabled:
                return False
            
            # Check environment
            if flag.environments and self.current_env not in flag.environments:
                return False
            
            # Check role
            if user_role and flag.roles and user_role not in flag.roles:
                return False
            
            # Check time window
            now = datetime.utcnow()
            if flag.start_date and now < flag.start_date:
                return False
            if flag.end_date and now > flag.end_date:
                return False
            
            # Check percentage rollout
            if flag.rollout_percentage < 100.0 and user_id:
                # Use consistent hash for user-based rollout
                import hashlib
                hash_input = f"{flag_key}:{user_id}".encode()
                hash_value = int(hashlib.md5(hash_input).hexdigest()[:8], 16)
                user_percentage = (hash_value % 100) + 1
                
                if user_percentage > flag.rollout_percentage:
                    return False
            
            result = True
            
            # Cache result
            if self._redis_client:
                self._redis_client.setex(
                    cache_key, 
                    self._cache_ttl, 
                    json.dumps(result)
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Feature flag evaluation error for {flag_key}: {e}")
            return False  # Fail closed for safety
    
    def get_flag(self, flag_key: str) -> Optional[FeatureFlag]:
        """Get feature flag configuration"""
        return self._flags.get(flag_key)
    
    def get_all_flags(self) -> Dict[str, FeatureFlag]:
        """Get all feature flags"""
        return self._flags.copy()
    
    def get_enabled_flags(self, 
                         user_role: Optional[UserRole] = None,
                         user_id: Optional[str] = None) -> Dict[str, FeatureFlag]:
        """Get all enabled flags for user context"""
        enabled = {}
        for key, flag in self._flags.items():
            if self.is_enabled(key, user_role, user_id):
                enabled[key] = flag
        return enabled
    
    def update_flag(self, flag_key: str, updates: Dict[str, Any]) -> bool:
        """Update feature flag configuration"""
        try:
            flag = self._flags.get(flag_key)
            if not flag:
                logger.error(f"Cannot update non-existent flag: {flag_key}")
                return False
            
            # Update flag properties
            if 'enabled' in updates:
                flag.enabled = updates['enabled']
            if 'rollout_percentage' in updates:
                flag.rollout_percentage = max(0.0, min(100.0, updates['rollout_percentage']))
            if 'environments' in updates:
                flag.environments = [Environment(env) for env in updates['environments']]
            if 'roles' in updates:
                flag.roles = [UserRole(role) for role in updates['roles']]
            if 'metadata' in updates:
                flag.metadata.update(updates['metadata'])
            
            flag.updated_at = datetime.utcnow()
            
            # Clear cache
            if self._redis_client:
                pattern = f"flag:{flag_key}:*"
                for key in self._redis_client.scan_iter(match=pattern):
                    self._redis_client.delete(key)
            
            logger.info(f"Updated feature flag: {flag_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update feature flag {flag_key}: {e}")
            return False
    
    def create_flag(self, flag: FeatureFlag) -> bool:
        """Create new feature flag"""
        try:
            if flag.key in self._flags:
                logger.error(f"Feature flag already exists: {flag.key}")
                return False
            
            self._flags[flag.key] = flag
            logger.info(f"Created feature flag: {flag.key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create feature flag {flag.key}: {e}")
            return False
    
    def delete_flag(self, flag_key: str) -> bool:
        """Delete feature flag"""
        try:
            if flag_key not in self._flags:
                logger.error(f"Cannot delete non-existent flag: {flag_key}")
                return False
            
            del self._flags[flag_key]
            
            # Clear cache
            if self._redis_client:
                pattern = f"flag:{flag_key}:*"
                for key in self._redis_client.scan_iter(match=pattern):
                    self._redis_client.delete(key)
            
            logger.info(f"Deleted feature flag: {flag_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete feature flag {flag_key}: {e}")
            return False
    
    def save_to_file(self) -> bool:
        """Save current flags to configuration file"""
        try:
            config_path = Path(self.config_file)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert flags to JSON format
            flags_data = []
            for flag in self._flags.values():
                flag_dict = {
                    'key': flag.key,
                    'name': flag.name,
                    'description': flag.description,
                    'enabled': flag.enabled,
                    'environments': [env.value for env in flag.environments],
                    'roles': [role.value for role in flag.roles],
                    'rollout_percentage': flag.rollout_percentage,
                    'metadata': flag.metadata
                }
                
                if flag.start_date:
                    flag_dict['start_date'] = flag.start_date.isoformat()
                if flag.end_date:
                    flag_dict['end_date'] = flag.end_date.isoformat()
                    
                flags_data.append(flag_dict)
            
            config_data = {
                'version': '1.0',
                'environment': self.current_env.value,
                'updated_at': datetime.utcnow().isoformat(),
                'flags': flags_data
            }
            
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Saved {len(self._flags)} feature flags to {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save feature flags: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feature flag statistics"""
        total_flags = len(self._flags)
        enabled_flags = sum(1 for flag in self._flags.values() if flag.enabled)
        
        by_env = {}
        by_role = {}
        
        for flag in self._flags.values():
            for env in flag.environments:
                by_env[env.value] = by_env.get(env.value, 0) + 1
            for role in flag.roles:
                by_role[role.value] = by_role.get(role.value, 0) + 1
        
        return {
            'total_flags': total_flags,
            'enabled_flags': enabled_flags,
            'disabled_flags': total_flags - enabled_flags,
            'by_environment': by_env,
            'by_role': by_role,
            'current_environment': self.current_env.value,
            'cache_enabled': self._redis_client is not None
        }

# Global feature flag manager instance
_feature_manager = None

def get_feature_manager() -> FeatureFlagManager:
    """Get global feature flag manager"""
    global _feature_manager
    if _feature_manager is None:
        _feature_manager = FeatureFlagManager()
    return _feature_manager

def is_feature_enabled(flag_key: str, 
                      user_role: Optional[UserRole] = None,
                      user_id: Optional[str] = None) -> bool:
    """Convenience function to check if feature is enabled"""
    return get_feature_manager().is_enabled(flag_key, user_role, user_id)

# Decorator for feature-gated functions
def feature_gate(flag_key: str, 
                default_return=None,
                user_role_param: str = 'user_role',
                user_id_param: str = 'user_id'):
    """
    Decorator to gate function execution behind feature flag
    
    Args:
        flag_key: Feature flag to check
        default_return: Value to return if feature is disabled
        user_role_param: Parameter name containing user role
        user_id_param: Parameter name containing user ID
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract user context from parameters
            user_role = kwargs.get(user_role_param)
            user_id = kwargs.get(user_id_param)
            
            # Check feature flag
            if not is_feature_enabled(flag_key, user_role, user_id):
                logger.info(f"Feature {flag_key} disabled, returning default")
                return default_return
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Async context manager for feature flags
@asynccontextmanager
async def feature_context(flag_key: str, 
                         user_role: Optional[UserRole] = None,
                         user_id: Optional[str] = None):
    """Context manager for feature-gated operations"""
    if is_feature_enabled(flag_key, user_role, user_id):
        yield True
    else:
        yield False

# Example usage
def example_feature_usage():
    """Example of using feature flags"""
    
    # Initialize feature manager
    manager = FeatureFlagManager(current_env=Environment.DEVELOPMENT)
    
    # Check if auto-quarantine is enabled for admin
    admin_role = UserRole.ADMIN
    user_id = "admin_123"
    
    if manager.is_enabled("auto_quarantine", admin_role, user_id):
        print("Auto-quarantine is enabled for admin")
    else:
        print("Auto-quarantine is disabled")
    
    # Get all enabled flags for user
    enabled_flags = manager.get_enabled_flags(admin_role, user_id)
    print(f"Enabled flags: {list(enabled_flags.keys())}")
    
    # Update flag
    manager.update_flag("auto_quarantine", {"rollout_percentage": 50.0})
    
    # Get statistics
    stats = manager.get_stats()
    print(f"Feature flag stats: {stats}")

# Example with decorator
@feature_gate("experimental_ml_heuristics", default_return=[])
def get_ml_predictions(email_content: str, user_role: UserRole, user_id: str):
    """ML predictions gated behind feature flag"""
    # This would only execute if experimental_ml_heuristics is enabled
    return ["phishing", "spam"]

if __name__ == "__main__":
    example_feature_usage()
