"""
Typed API Client - Type-safe client for PhishNet API
Provides strongly typed interfaces for all API operations
"""

from typing import Dict, List, Optional, Any, Union, TypeVar, Generic
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import httpx
import asyncio
from urllib.parse import urljoin

# Type definitions
T = TypeVar('T')

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"

class EmailStatus(Enum):
    PENDING = "pending"
    ANALYZED = "analyzed"
    QUARANTINED = "quarantined"
    APPROVED = "approved"

@dataclass
class ApiResponse(Generic[T]):
    """Generic API response wrapper"""
    success: bool
    data: Optional[T] = None
    error: Optional[str] = None
    message: Optional[str] = None
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class PaginatedResponse(Generic[T]):
    """Paginated API response"""
    items: List[T]
    total: int
    page: int
    limit: int
    has_next: bool
    has_prev: bool

@dataclass
class EmailData:
    """Email data structure"""
    id: int
    subject: str
    sender: str
    recipient: str
    content: str
    received_at: datetime
    status: EmailStatus
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    analyzed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class LinkData:
    """Link analysis data structure"""
    id: int
    email_id: int
    original_url: str
    final_url: str
    redirect_chain: List[str]
    risk_score: float
    risk_level: RiskLevel
    analyzed_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DetectionData:
    """Detection result data structure"""
    id: int
    email_id: int
    detection_type: str
    confidence: float
    details: Dict[str, Any]
    created_at: datetime

@dataclass
class UserData:
    """User data structure"""
    id: int
    email: str
    role: str
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True

@dataclass
class StatsData:
    """Statistics data structure"""
    total_emails: int
    analyzed_emails: int
    high_risk_emails: int
    total_links: int
    suspicious_links: int
    detection_rate: float
    last_updated: datetime

@dataclass
class HealthData:
    """Health check data structure"""
    status: str
    timestamp: str
    version: str
    database: str
    users_count: int
    emails_count: int

@dataclass
class AuthToken:
    """Authentication token"""
    access_token: str
    token_type: str
    expires_in: Optional[int] = None

class ApiError(Exception):
    """API error exception"""
    def __init__(self, message: str, status_code: int = 500, response_data: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_data = response_data or {}

class PhishNetApiClient:
    """
    Type-safe API client for PhishNet
    
    Features:
    - Strongly typed request/response handling
    - Automatic serialization/deserialization
    - Authentication management
    - Error handling and retries
    - Connection pooling
    - Request/response logging
    """
    
    def __init__(self, 
                 base_url: str = "http://localhost:8080",
                 timeout: float = 30.0,
                 max_retries: int = 3,
                 auth_token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self._auth_token = auth_token
        self._client: Optional[httpx.AsyncClient] = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._get_headers()
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._client:
            await self._client.aclose()
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers"""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "PhishNet-Client/1.0",
        }
        
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
            
        return headers
    
    async def _make_request(self, 
                           method: str, 
                           endpoint: str, 
                           data: Optional[Dict] = None,
                           params: Optional[Dict] = None) -> httpx.Response:
        """Make HTTP request with retries"""
        if not self._client:
            raise ApiError("Client not initialized. Use async context manager.")
        
        url = endpoint if endpoint.startswith('http') else f"/api/v1{endpoint}"
        
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params
                )
                
                # Check for HTTP errors
                if response.status_code >= 400:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    raise ApiError(
                        message=error_data.get('detail', f'HTTP {response.status_code}'),
                        status_code=response.status_code,
                        response_data=error_data
                    )
                
                return response
                
            except httpx.RequestError as e:
                if attempt == self.max_retries:
                    raise ApiError(f"Request failed after {self.max_retries} retries: {e}")
                
                # Exponential backoff
                await asyncio.sleep(2 ** attempt)
    
    def _parse_response(self, response: httpx.Response, expected_type: type) -> Any:
        """Parse response data to expected type"""
        try:
            data = response.json()
            
            # Handle different response formats
            if isinstance(data, dict) and 'data' in data:
                data = data['data']
            
            # Convert to expected type if it's a dataclass
            if hasattr(expected_type, '__dataclass_fields__'):
                if isinstance(data, list):
                    return [expected_type(**item) for item in data]
                elif isinstance(data, dict):
                    return expected_type(**data)
            
            return data
            
        except Exception as e:
            raise ApiError(f"Response parsing failed: {e}")
    
    # Authentication
    async def login(self, username: str, password: str) -> ApiResponse[AuthToken]:
        """Authenticate user and get token"""
        try:
            response = await self._make_request(
                "POST", 
                "/auth/login",
                data={"username": username, "password": password}
            )
            
            token_data = self._parse_response(response, AuthToken)
            self._auth_token = token_data.access_token
            
            # Update client headers
            if self._client:
                self._client.headers.update(self._get_headers())
            
            return ApiResponse(success=True, data=token_data)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    # Email Operations
    async def get_emails(self, 
                        page: int = 1, 
                        limit: int = 10,
                        status: Optional[EmailStatus] = None) -> ApiResponse[PaginatedResponse[EmailData]]:
        """Get paginated list of emails"""
        try:
            params = {"page": page, "limit": limit}
            if status:
                params["status"] = status.value
            
            response = await self._make_request("GET", "/emails", params=params)
            data = response.json()
            
            # Parse emails
            emails = [EmailData(
                id=item['id'],
                subject=item['subject'],
                sender=item['sender'],
                recipient=item['recipient'],
                content=item['content'],
                received_at=datetime.fromisoformat(item['received_at'].replace('Z', '+00:00')),
                status=EmailStatus(item['status']),
                risk_score=item.get('risk_score'),
                risk_level=RiskLevel(item['risk_level']) if item.get('risk_level') else None,
                analyzed_at=datetime.fromisoformat(item['analyzed_at'].replace('Z', '+00:00')) if item.get('analyzed_at') else None,
                metadata=item.get('metadata', {})
            ) for item in data.get('emails', [])]
            
            paginated = PaginatedResponse(
                items=emails,
                total=data.get('total', 0),
                page=data.get('page', 1),
                limit=data.get('limit', 10),
                has_next=data.get('has_next', False),
                has_prev=data.get('has_prev', False)
            )
            
            return ApiResponse(success=True, data=paginated)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    async def get_email(self, email_id: int) -> ApiResponse[EmailData]:
        """Get single email by ID"""
        try:
            response = await self._make_request("GET", f"/emails/{email_id}")
            email_data = self._parse_response(response, EmailData)
            
            return ApiResponse(success=True, data=email_data)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    async def create_email(self, email_data: Dict[str, Any]) -> ApiResponse[EmailData]:
        """Create new email"""
        try:
            response = await self._make_request("POST", "/emails", data=email_data)
            created_email = self._parse_response(response, EmailData)
            
            return ApiResponse(success=True, data=created_email)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    async def update_email(self, email_id: int, updates: Dict[str, Any]) -> ApiResponse[EmailData]:
        """Update email"""
        try:
            response = await self._make_request("PUT", f"/emails/{email_id}", data=updates)
            updated_email = self._parse_response(response, EmailData)
            
            return ApiResponse(success=True, data=updated_email)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    async def delete_email(self, email_id: int) -> ApiResponse[Dict[str, str]]:
        """Delete email"""
        try:
            response = await self._make_request("DELETE", f"/emails/{email_id}")
            result = {"message": "Email deleted successfully"}
            
            return ApiResponse(success=True, data=result)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    # Statistics
    async def get_email_stats(self) -> ApiResponse[StatsData]:
        """Get email statistics"""
        try:
            response = await self._make_request("GET", "/emails/stats")
            stats_data = self._parse_response(response, StatsData)
            
            return ApiResponse(success=True, data=stats_data)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    # Health Check
    async def get_health(self) -> ApiResponse[HealthData]:
        """Get API health status"""
        try:
            response = await self._make_request("GET", "/health")
            health_data = self._parse_response(response, HealthData)
            
            return ApiResponse(success=True, data=health_data)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    # Link Operations
    async def get_links(self, email_id: Optional[int] = None) -> ApiResponse[List[LinkData]]:
        """Get links, optionally filtered by email ID"""
        try:
            params = {}
            if email_id:
                params["email_id"] = email_id
            
            response = await self._make_request("GET", "/links", params=params)
            links_data = self._parse_response(response, List[LinkData])
            
            return ApiResponse(success=True, data=links_data)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)
    
    async def analyze_link(self, url: str) -> ApiResponse[LinkData]:
        """Analyze a URL for threats"""
        try:
            response = await self._make_request("POST", "/links/analyze", data={"url": url})
            link_data = self._parse_response(response, LinkData)
            
            return ApiResponse(success=True, data=link_data)
            
        except ApiError as e:
            return ApiResponse(success=False, error=e.message, status_code=e.status_code)

# Convenience functions
async def create_authenticated_client(username: str, password: str, 
                                    base_url: str = "http://localhost:8080") -> PhishNetApiClient:
    """Create and authenticate API client"""
    async with PhishNetApiClient(base_url=base_url) as client:
        auth_result = await client.login(username, password)
        if not auth_result.success:
            raise ApiError(f"Authentication failed: {auth_result.error}")
        return client

# Example usage
async def example_usage():
    """Example of using the typed API client"""
    
    # Create authenticated client
    async with PhishNetApiClient() as client:
        # Login
        auth_result = await client.login("admin@phishnet.local", "admin")
        if not auth_result.success:
            print(f"Login failed: {auth_result.error}")
            return
        
        print(f"Authenticated with token: {auth_result.data.access_token}")
        
        # Get emails with type safety
        emails_result = await client.get_emails(page=1, limit=5)
        if emails_result.success:
            emails = emails_result.data
            print(f"Found {emails.total} emails (showing {len(emails.items)})")
            
            for email in emails.items:
                print(f"  - {email.subject} from {email.sender} (Risk: {email.risk_level})")
        
        # Get statistics
        stats_result = await client.get_email_stats()
        if stats_result.success:
            stats = stats_result.data
            print(f"Stats: {stats.total_emails} emails, {stats.detection_rate:.1%} detection rate")
        
        # Check health
        health_result = await client.get_health()
        if health_result.success:
            health = health_result.data
            print(f"API Status: {health.status} (v{health.version})")

if __name__ == "__main__":
    asyncio.run(example_usage())
