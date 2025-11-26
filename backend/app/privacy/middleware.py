"""
Privacy compliance middleware for automatic PII redaction and audit logging.
Integrates privacy controls into the request/response pipeline.
"""

import time
import json
from typing import Callable, Any, Dict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.privacy import PIIRedactor, redact_sensitive_data
from app.privacy.database import privacy_db
from app.observability import get_logger

logger = get_logger(__name__)

class PrivacyComplianceMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce privacy compliance across all API requests."""
    
    def __init__(
        self, 
        app, 
        enable_pii_redaction: bool = True,
        enable_audit_logging: bool = True,
        privacy_exempt_paths: list = None
    ):
        super().__init__(app)
        self.enable_pii_redaction = enable_pii_redaction
        self.enable_audit_logging = enable_audit_logging
        self.privacy_exempt_paths = privacy_exempt_paths or ['/health', '/metrics', '/docs', '/openapi.json']
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip privacy middleware for exempt paths
        if request.url.path in self.privacy_exempt_paths:
            return await call_next(request)
        
        # Extract user information
        user_id = getattr(request.state, 'user_id', None)
        ip_address = request.client.host
        
        # Process request
        start_time = time.time()
        
        try:
            # Capture request data for audit (with PII redaction)
            if self.enable_audit_logging and request.method in ['POST', 'PUT', 'PATCH']:
                await self._log_request_audit(request, user_id, ip_address)
            
            # Process the request
            response = await call_next(request)
            
            # Log data access for audit trail
            if self.enable_audit_logging and user_id:
                await self._log_response_audit(
                    request, response, user_id, ip_address, 
                    time.time() - start_time
                )
            
            # Redact PII from response if needed
            if self.enable_pii_redaction and hasattr(response, 'body'):
                response = await self._redact_response_pii(response)
            
            return response
            
        except Exception as e:
            # Log the error with privacy protection
            logger.error(
                "Privacy middleware error",
                path=request.url.path,
                method=request.method,
                error=str(e),
                user_id=user_id
            )
            raise
    
    async def _log_request_audit(self, request: Request, user_id: str, ip_address: str):
        """Log request data access for audit trail."""
        try:
            # Extract request data (limited for privacy)
            request_data = {
                "path": request.url.path,
                "method": request.method,
                "query_params": dict(request.query_params),
                "headers": {k: v for k, v in request.headers.items() 
                           if k.lower() not in ['authorization', 'cookie', 'x-api-key']}
            }
            
            # Redact PII from request data
            redacted_data = redact_sensitive_data(request_data)
            
            # Store audit log
            await privacy_db.store_audit_log({
                "event_id": f"req_{int(time.time() * 1000000)}",
                "event_type": "api_request",
                "user_id": user_id,
                "action": f"{request.method} {request.url.path}",
                "ip_address": PIIRedactor.redact_pii(ip_address),
                "legal_basis": "legitimate_interest",  # For security monitoring
                "details": redacted_data
            })
            
        except Exception as e:
            logger.warning("Failed to log request audit", error=str(e))
    
    async def _log_response_audit(
        self, 
        request: Request, 
        response: Response, 
        user_id: str, 
        ip_address: str, 
        duration: float
    ):
        """Log response data access for audit trail."""
        try:
            # Determine data types accessed based on endpoint
            data_types = self._identify_data_types(request.url.path)
            
            await privacy_db.store_audit_log({
                "event_id": f"resp_{int(time.time() * 1000000)}",
                "event_type": "data_access",
                "user_id": user_id,
                "action": "data_retrieval",
                "data_type": ",".join(data_types),
                "ip_address": PIIRedactor.redact_pii(ip_address),
                "legal_basis": self._determine_legal_basis(request.url.path),
                "details": {
                    "path": request.url.path,
                    "method": request.method,
                    "status_code": response.status_code,
                    "duration_ms": duration * 1000,
                    "data_types_accessed": data_types
                }
            })
            
        except Exception as e:
            logger.warning("Failed to log response audit", error=str(e))
    
    async def _redact_response_pii(self, response: Response) -> Response:
        """Redact PII from response body."""
        try:
            if hasattr(response, 'body') and response.body:
                # Only process JSON responses
                content_type = response.headers.get('content-type', '')
                if 'application/json' in content_type:
                    try:
                        # Parse JSON and redact
                        body_str = response.body.decode('utf-8')
                        body_data = json.loads(body_str)
                        redacted_data = redact_sensitive_data(body_data)
                        
                        # Update response body
                        redacted_body = json.dumps(redacted_data).encode('utf-8')
                        
                        # Create new response with redacted body
                        from fastapi.responses import JSONResponse
                        return JSONResponse(
                            content=redacted_data,
                            status_code=response.status_code,
                            headers=dict(response.headers)
                        )
                        
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # If not valid JSON, just redact as text
                        body_str = response.body.decode('utf-8', errors='ignore')
                        redacted_body = PIIRedactor.redact_pii(body_str)
                        response.body = redacted_body.encode('utf-8')
            
            return response
            
        except Exception as e:
            logger.warning("Failed to redact response PII", error=str(e))
            return response
    
    def _identify_data_types(self, path: str) -> list:
        """Identify data types accessed based on API path."""
        data_types = []
        
        if '/user' in path or '/profile' in path:
            data_types.append('user_profile')
        if '/email' in path or '/scan' in path:
            data_types.extend(['email_content', 'email_metadata'])
        if '/oauth' in path or '/token' in path:
            data_types.append('authentication_tokens')
        if '/privacy' in path or '/consent' in path:
            data_types.append('privacy_preferences')
        
        return data_types or ['general']
    
    def _determine_legal_basis(self, path: str) -> str:
        """Determine GDPR legal basis for data processing."""
        # Simplified legal basis determination
        if '/security' in path or '/scan' in path:
            return 'legitimate_interest'  # Security purposes
        elif '/privacy' in path or '/consent' in path:
            return 'consent'
        elif '/oauth' in path:
            return 'contract'  # Service provision
        else:
            return 'legitimate_interest'

class ConsentEnforcementMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce user consent before data processing."""
    
    def __init__(self, app, consent_required_paths: list = None):
        super().__init__(app)
        self.consent_required_paths = consent_required_paths or [
            '/api/v1/email/scan',
            '/api/v1/analyze',
            '/api/v1/ml/predict'
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if path requires consent
        requires_consent = any(
            request.url.path.startswith(path) 
            for path in self.consent_required_paths
        )
        
        if requires_consent:
            user_id = getattr(request.state, 'user_id', None)
            
            if user_id:
                # Check if user has granted data processing consent
                from app.privacy import ConsentType
                # This would check the database for consent
                # has_consent = await consent_manager.has_consent(user_id, ConsentType.DATA_PROCESSING)
                
                # For demo, assume consent exists
                has_consent = True
                
                if not has_consent:
                    from fastapi import HTTPException
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error": "consent_required",
                            "message": "User consent required for data processing",
                            "consent_url": "/privacy/consent"
                        }
                    )
        
        return await call_next(request)

class DataMinimizationMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce data minimization principles."""
    
    def __init__(self, app, field_restrictions: Dict[str, list] = None):
        super().__init__(app)
        self.field_restrictions = field_restrictions or {
            '/api/v1/user/profile': ['email', 'name', 'id'],  # Only allow necessary fields
            '/api/v1/email/metadata': ['subject', 'sender', 'timestamp'],
            '/api/v1/scan/results': ['threat_level', 'confidence', 'scan_id']
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        
        # Apply field restrictions to response
        if request.url.path in self.field_restrictions:
            allowed_fields = self.field_restrictions[request.url.path]
            response = await self._filter_response_fields(response, allowed_fields)
        
        return response
    
    async def _filter_response_fields(
        self, 
        response: Response, 
        allowed_fields: list
    ) -> Response:
        """Filter response to only include allowed fields."""
        try:
            if hasattr(response, 'body') and response.body:
                content_type = response.headers.get('content-type', '')
                
                if 'application/json' in content_type:
                    body_str = response.body.decode('utf-8')
                    body_data = json.loads(body_str)
                    
                    # Filter fields recursively
                    filtered_data = self._filter_dict_fields(body_data, allowed_fields)
                    
                    # Update response
                    from fastapi.responses import JSONResponse
                    return JSONResponse(
                        content=filtered_data,
                        status_code=response.status_code,
                        headers=dict(response.headers)
                    )
        
        except Exception as e:
            logger.warning("Failed to filter response fields", error=str(e))
        
        return response
    
    def _filter_dict_fields(self, data: Any, allowed_fields: list) -> Any:
        """Recursively filter dictionary fields."""
        if isinstance(data, dict):
            return {
                key: self._filter_dict_fields(value, allowed_fields)
                for key, value in data.items()
                if key in allowed_fields or key.startswith('_')  # Allow metadata fields
            }
        elif isinstance(data, list):
            return [
                self._filter_dict_fields(item, allowed_fields)
                for item in data
            ]
        else:
            return data