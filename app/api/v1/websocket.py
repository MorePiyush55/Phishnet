"""
WebSocket API v1 - Real-time event streaming
"""

from typing import List, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from datetime import datetime
import json
import asyncio
import jwt

from app.config.settings import settings

router = APIRouter()

class ConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[str, List[str]] = {}  # user_id -> [connection_ids]
    
    async def connect(self, websocket: WebSocket, connection_id: str, user_id: str):
        """Accept WebSocket connection and register user"""
        await websocket.accept()
        self.active_connections[connection_id] = websocket
        
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(connection_id)
        
        print(f"WebSocket connected: {connection_id} for user {user_id}")
    
    def disconnect(self, connection_id: str, user_id: str):
        """Remove WebSocket connection"""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
        
        if user_id in self.user_connections:
            if connection_id in self.user_connections[user_id]:
                self.user_connections[user_id].remove(connection_id)
            
            # Remove user entry if no connections
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
        
        print(f"WebSocket disconnected: {connection_id}")
    
    async def send_personal_message(self, message: str, connection_id: str):
        """Send message to specific connection"""
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                await websocket.send_text(message)
            except:
                # Connection is broken, remove it
                self.disconnect(connection_id, "unknown")
    
    async def send_to_user(self, message: str, user_id: str):
        """Send message to all connections for a specific user"""
        if user_id in self.user_connections:
            for connection_id in self.user_connections[user_id].copy():
                await self.send_personal_message(message, connection_id)
    
    async def broadcast(self, message: str):
        """Send message to all connected clients"""
        disconnected = []
        
        for connection_id, websocket in self.active_connections.items():
            try:
                await websocket.send_text(message)
            except:
                disconnected.append(connection_id)
        
        # Clean up broken connections
        for connection_id in disconnected:
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]

# Global connection manager
manager = ConnectionManager()

def verify_websocket_token(token: str) -> str:
    """Verify JWT token and return user email"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        return email
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token for authentication")
):
    """
    WebSocket endpoint for real-time events
    
    **Contract**: GET /ws?token=... → events: email_ingested, analysis_complete, action_taken, stats_updated
    """
    
    # Verify authentication
    try:
        user_email = verify_websocket_token(token)
    except HTTPException as e:
        await websocket.close(code=1008, reason=f"Authentication failed: {e.detail}")
        return
    
    # Generate connection ID
    import uuid
    connection_id = str(uuid.uuid4())
    
    # Connect
    await manager.connect(websocket, connection_id, user_email)
    
    # Send welcome message
    welcome_event = {
        "type": "connection_established",
        "data": {
            "connection_id": connection_id,
            "user": user_email,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.send_personal_message(json.dumps(welcome_event), connection_id)
    
    try:
        # Keep connection alive and handle incoming messages
        while True:
            # Wait for client messages (ping/pong, subscriptions, etc.)
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                
                # Handle client message
                try:
                    message = json.loads(data)
                    await handle_client_message(message, connection_id, user_email)
                except json.JSONDecodeError:
                    error_event = {
                        "type": "error",
                        "data": {"message": "Invalid JSON format"}
                    }
                    await manager.send_personal_message(json.dumps(error_event), connection_id)
                
            except asyncio.TimeoutError:
                # Send ping to keep connection alive
                ping_event = {
                    "type": "ping",
                    "data": {"timestamp": datetime.utcnow().isoformat()}
                }
                await manager.send_personal_message(json.dumps(ping_event), connection_id)
                
    except WebSocketDisconnect:
        manager.disconnect(connection_id, user_email)

async def handle_client_message(message: dict, connection_id: str, user_email: str):
    """Handle incoming WebSocket messages from client"""
    
    message_type = message.get("type", "")
    
    if message_type == "pong":
        # Client responded to ping
        return
    
    elif message_type == "subscribe":
        # Client wants to subscribe to specific event types
        event_types = message.get("data", {}).get("events", [])
        
        response = {
            "type": "subscription_confirmed",
            "data": {
                "subscribed_events": event_types,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        await manager.send_personal_message(json.dumps(response), connection_id)
    
    elif message_type == "get_stats":
        # Client requests current stats
        stats_event = {
            "type": "stats_updated",
            "data": {
                "emails_today": 156,
                "threats_detected": 23,
                "emails_quarantined": 12,
                "active_users": len(manager.user_connections),
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        await manager.send_personal_message(json.dumps(stats_event), connection_id)

# Event broadcasting functions
async def broadcast_email_ingested(email_data: dict):
    """Broadcast when new email is ingested"""
    event = {
        "type": "email_ingested",
        "data": {
            "email_id": email_data.get("id"),
            "sender": email_data.get("sender"),
            "subject": email_data.get("subject", "")[:50] + "..." if len(email_data.get("subject", "")) > 50 else email_data.get("subject", ""),
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast(json.dumps(event))

async def broadcast_analysis_complete(analysis_data: dict):
    """Broadcast when email analysis is complete"""
    event = {
        "type": "analysis_complete",
        "data": {
            "email_id": analysis_data.get("email_id"),
            "risk_level": analysis_data.get("risk_level"),
            "risk_score": analysis_data.get("risk_score"),
            "confidence": analysis_data.get("confidence"),
            "processing_time_ms": analysis_data.get("processing_time_ms"),
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast(json.dumps(event))

async def broadcast_action_taken(action_data: dict):
    """Broadcast when action is taken on email"""
    event = {
        "type": "action_taken",
        "data": {
            "email_id": action_data.get("email_id"),
            "action": action_data.get("action"),
            "actor": action_data.get("actor"),
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast(json.dumps(event))

async def broadcast_stats_updated(stats_data: dict):
    """Broadcast updated system statistics"""
    event = {
        "type": "stats_updated", 
        "data": {
            **stats_data,
            "timestamp": datetime.utcnow().isoformat()
        }
    }
    await manager.broadcast(json.dumps(event))

# Export the manager and broadcast functions for use in other modules
__all__ = [
    "manager", 
    "broadcast_email_ingested",
    "broadcast_analysis_complete", 
    "broadcast_action_taken",
    "broadcast_stats_updated"
]
