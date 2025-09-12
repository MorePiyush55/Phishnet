"""WebSocket authentication and connection management."""

import json
import logging
from datetime import datetime
from typing import Dict, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect, WebSocketException, status
from sqlalchemy.orm import Session

from app.core.auth import TokenPayload, get_auth_service
from app.core.auth_deps import authenticate_websocket
from app.core.database import get_db

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections with authentication."""
    
    def __init__(self):
        # Active connections by user ID
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Connection metadata (user info, connected time, etc.)
        self.connection_info: Dict[WebSocket, Dict] = {}
    
    async def connect(self, websocket: WebSocket, token: str, db: Session) -> TokenPayload:
        """Accept WebSocket connection with JWT authentication."""
        try:
            # Authenticate the WebSocket connection
            user_payload = await authenticate_websocket(token, db)
            
            # Accept the connection
            await websocket.accept()
            
            # Track the connection
            user_id = user_payload.sub
            if user_id not in self.active_connections:
                self.active_connections[user_id] = set()
            
            self.active_connections[user_id].add(websocket)
            self.connection_info[websocket] = {
                "user_id": user_id,
                "user_role": user_payload.role,
                "permissions": user_payload.permissions,
                "connected_at": datetime.utcnow(),
                "jti": user_payload.jti
            }
            
            logger.info(f"WebSocket connected: user_id={user_id}, role={user_payload.role}")
            
            # Send welcome message
            await self.send_personal_message({
                "type": "connection_established",
                "message": "Successfully connected",
                "user_id": user_id,
                "permissions": user_payload.permissions
            }, websocket)
            
            return user_payload
            
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            raise WebSocketException(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="Authentication failed"
            )
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        if websocket in self.connection_info:
            user_id = self.connection_info[websocket]["user_id"]
            
            # Remove from active connections
            if user_id in self.active_connections:
                self.active_connections[user_id].discard(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
            
            # Remove connection info
            del self.connection_info[websocket]
            
            logger.info(f"WebSocket disconnected: user_id={user_id}")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to specific WebSocket."""
        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send message to WebSocket: {e}")
            self.disconnect(websocket)
    
    async def send_to_user(self, message: dict, user_id: str):
        """Send message to all connections of a specific user."""
        if user_id in self.active_connections:
            disconnected = []
            for websocket in self.active_connections[user_id].copy():
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to send message to user {user_id}: {e}")
                    disconnected.append(websocket)
            
            # Clean up disconnected websockets
            for websocket in disconnected:
                self.disconnect(websocket)
    
    async def send_to_role(self, message: dict, role: str):
        """Send message to all users with specific role."""
        for websocket, info in self.connection_info.items():
            if info["user_role"] == role:
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to send message to role {role}: {e}")
                    self.disconnect(websocket)
    
    async def send_to_permission(self, message: dict, permission: str):
        """Send message to all users with specific permission."""
        for websocket, info in self.connection_info.items():
            if permission in info["permissions"] or info["user_role"] == "admin":
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to send message to permission {permission}: {e}")
                    self.disconnect(websocket)
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected users."""
        disconnected = []
        for websocket in self.connection_info.keys():
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Failed to broadcast message: {e}")
                disconnected.append(websocket)
        
        # Clean up disconnected websockets
        for websocket in disconnected:
            self.disconnect(websocket)
    
    def get_user_connections(self, user_id: str) -> Set[WebSocket]:
        """Get all connections for a user."""
        return self.active_connections.get(user_id, set())
    
    def get_connection_count(self) -> int:
        """Get total number of active connections."""
        return len(self.connection_info)
    
    def get_user_count(self) -> int:
        """Get number of unique connected users."""
        return len(self.active_connections)
    
    def is_user_connected(self, user_id: str) -> bool:
        """Check if user has any active connections."""
        return user_id in self.active_connections and len(self.active_connections[user_id]) > 0
    
    async def validate_token_freshness(self, websocket: WebSocket, db: Session) -> bool:
        """Validate that the WebSocket token is still valid."""
        if websocket not in self.connection_info:
            return False
        
        try:
            info = self.connection_info[websocket]
            jti = info.get("jti")
            
            if not jti:
                return False
            
            # Check if token is revoked
            auth_service = get_auth_service()
            is_revoked = await auth_service.jwt_service.is_token_revoked(jti, db)
            
            if is_revoked:
                await self.send_personal_message({
                    "type": "token_revoked",
                    "message": "Authentication token has been revoked",
                    "action": "reconnect_required"
                }, websocket)
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False


# Global connection manager instance
manager = ConnectionManager()


class WebSocketAuthHandler:
    """Handler for WebSocket authentication and message routing."""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.manager = connection_manager
    
    async def handle_connection(self, websocket: WebSocket, token: str):
        """Handle new WebSocket connection with authentication."""
        db = next(get_db())
        
        try:
            user_payload = await self.manager.connect(websocket, token, db)
            
            # Handle messages
            await self._handle_messages(websocket, user_payload, db)
            
        except WebSocketDisconnect:
            self.manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket handler error: {e}")
            self.manager.disconnect(websocket)
        finally:
            db.close()
    
    async def _handle_messages(self, websocket: WebSocket, user_payload: TokenPayload, db: Session):
        """Handle incoming WebSocket messages."""
        try:
            while True:
                # Receive message
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Validate token freshness periodically
                if not await self.manager.validate_token_freshness(websocket, db):
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    break
                
                # Route message based on type
                await self._route_message(message, websocket, user_payload)
                
        except WebSocketDisconnect:
            pass
        except json.JSONDecodeError:
            await self.manager.send_personal_message({
                "type": "error",
                "message": "Invalid JSON format"
            }, websocket)
        except Exception as e:
            logger.error(f"Message handling error: {e}")
            await self.manager.send_personal_message({
                "type": "error", 
                "message": "Message processing failed"
            }, websocket)
    
    async def _route_message(self, message: dict, websocket: WebSocket, user_payload: TokenPayload):
        """Route message based on type and permissions."""
        message_type = message.get("type")
        
        if message_type == "ping":
            await self.manager.send_personal_message({
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat()
            }, websocket)
        
        elif message_type == "subscribe":
            await self._handle_subscription(message, websocket, user_payload)
        
        elif message_type == "unsubscribe":
            await self._handle_unsubscription(message, websocket, user_payload)
        
        elif message_type == "admin_broadcast":
            await self._handle_admin_broadcast(message, websocket, user_payload)
        
        else:
            await self.manager.send_personal_message({
                "type": "error",
                "message": f"Unknown message type: {message_type}"
            }, websocket)
    
    async def _handle_subscription(self, message: dict, websocket: WebSocket, user_payload: TokenPayload):
        """Handle subscription requests."""
        channel = message.get("channel")
        
        # Define channel permissions
        channel_permissions = {
            "email_alerts": "email:read",
            "detection_updates": "detection:read", 
            "system_status": "system:monitor",
            "admin_notifications": "system:configure"
        }
        
        required_permission = channel_permissions.get(channel)
        
        if required_permission:
            if required_permission in user_payload.permissions or user_payload.role == "admin":
                # Store subscription info (implementation depends on your needs)
                await self.manager.send_personal_message({
                    "type": "subscription_confirmed",
                    "channel": channel,
                    "message": f"Subscribed to {channel}"
                }, websocket)
            else:
                await self.manager.send_personal_message({
                    "type": "subscription_denied",
                    "channel": channel,
                    "message": f"Insufficient permissions for {channel}"
                }, websocket)
        else:
            await self.manager.send_personal_message({
                "type": "error",
                "message": f"Unknown channel: {channel}"
            }, websocket)
    
    async def _handle_unsubscription(self, message: dict, websocket: WebSocket, user_payload: TokenPayload):
        """Handle unsubscription requests."""
        channel = message.get("channel")
        
        # Remove subscription (implementation depends on your needs)
        await self.manager.send_personal_message({
            "type": "unsubscription_confirmed",
            "channel": channel,
            "message": f"Unsubscribed from {channel}"
        }, websocket)
    
    async def _handle_admin_broadcast(self, message: dict, websocket: WebSocket, user_payload: TokenPayload):
        """Handle admin broadcast messages."""
        if user_payload.role != "admin":
            await self.manager.send_personal_message({
                "type": "error",
                "message": "Admin privileges required for broadcast"
            }, websocket)
            return
        
        broadcast_message = {
            "type": "admin_broadcast",
            "message": message.get("message", ""),
            "from_user": user_payload.sub,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.manager.broadcast(broadcast_message)


# Global WebSocket handler
websocket_handler = WebSocketAuthHandler(manager)
