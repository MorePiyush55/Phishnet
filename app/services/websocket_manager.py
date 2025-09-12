"""WebSocket manager for real-time dashboard updates."""

import json
import asyncio
import uuid
from datetime import datetime
from typing import Dict, Set, Any, Optional, List
import logging
from collections import defaultdict

from fastapi import WebSocket, WebSocketDisconnect
from app.config.logging import get_logger

logger = get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        """Initialize connection manager."""
        self.active_connections: Dict[str, WebSocket] = {}
        self.user_connections: Dict[int, Set[str]] = defaultdict(set)
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}
        self.lock = asyncio.Lock()
    
    async def connect(
        self, 
        websocket: WebSocket, 
        user_id: int, 
        client_ip: str = None,
        user_agent: str = None
    ) -> str:
        """Accept a new WebSocket connection."""
        try:
            await websocket.accept()
            
            # Generate unique connection ID
            connection_id = f"ws_{user_id}_{uuid.uuid4().hex[:8]}"
            
            async with self.lock:
                self.active_connections[connection_id] = websocket
                self.user_connections[user_id].add(connection_id)
                
                self.connection_metadata[connection_id] = {
                    "user_id": user_id,
                    "connected_at": datetime.utcnow(),
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "last_ping": datetime.utcnow()
                }
            
            logger.info(f"WebSocket connected: {connection_id} for user {user_id}")
            
            # Send initial connection confirmation
            await self._send_to_connection(connection_id, {
                "type": "connection_established",
                "connection_id": connection_id,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return connection_id
            
        except Exception as e:
            logger.error(f"WebSocket connection failed for user {user_id}: {e}")
            raise
    
    async def disconnect(self, connection_id: str):
        """Handle WebSocket disconnection."""
        try:
            async with self.lock:
                if connection_id in self.active_connections:
                    metadata = self.connection_metadata.get(connection_id, {})
                    user_id = metadata.get("user_id")
                    
                    # Remove from active connections
                    del self.active_connections[connection_id]
                    
                    # Remove from user connections
                    if user_id and user_id in self.user_connections:
                        self.user_connections[user_id].discard(connection_id)
                        if not self.user_connections[user_id]:
                            del self.user_connections[user_id]
                    
                    # Clean up metadata
                    if connection_id in self.connection_metadata:
                        del self.connection_metadata[connection_id]
                    
                    logger.info(f"WebSocket disconnected: {connection_id} for user {user_id}")
                    
        except Exception as e:
            logger.error(f"Error handling WebSocket disconnection {connection_id}: {e}")
    
    async def send_to_user(self, user_id: int, message: Dict[str, Any]):
        """Send message to all connections for a specific user."""
        try:
            if user_id not in self.user_connections:
                logger.debug(f"No active connections for user {user_id}")
                return 0
            
            connection_ids = list(self.user_connections[user_id])
            successful_sends = 0
            
            # Send to all user connections
            for connection_id in connection_ids:
                try:
                    await self._send_to_connection(connection_id, message)
                    successful_sends += 1
                except Exception as e:
                    logger.error(f"Failed to send to connection {connection_id}: {e}")
                    # Schedule cleanup for failed connection
                    asyncio.create_task(self.disconnect(connection_id))
            
            logger.debug(f"Sent message to {successful_sends}/{len(connection_ids)} connections for user {user_id}")
            return successful_sends
            
        except Exception as e:
            logger.error(f"Error sending message to user {user_id}: {e}")
            return 0
    
    async def send_to_connection(self, connection_id: str, message: Dict[str, Any]):
        """Send message to specific connection."""
        try:
            await self._send_to_connection(connection_id, message)
            return True
        except Exception as e:
            logger.error(f"Failed to send to connection {connection_id}: {e}")
            await self.disconnect(connection_id)
            return False
    
    async def _send_to_connection(self, connection_id: str, message: Dict[str, Any]):
        """Internal method to send message to connection."""
        if connection_id not in self.active_connections:
            raise ValueError(f"Connection {connection_id} not found")
        
        websocket = self.active_connections[connection_id]
        
        # Add timestamp to message
        message["timestamp"] = message.get("timestamp", datetime.utcnow().isoformat())
        
        await websocket.send_text(json.dumps(message))
    
    async def broadcast_to_all(self, message: Dict[str, Any]):
        """Broadcast message to all connected users."""
        try:
            connection_ids = list(self.active_connections.keys())
            successful_sends = 0
            
            for connection_id in connection_ids:
                try:
                    await self._send_to_connection(connection_id, message)
                    successful_sends += 1
                except Exception as e:
                    logger.error(f"Broadcast failed to connection {connection_id}: {e}")
                    asyncio.create_task(self.disconnect(connection_id))
            
            logger.info(f"Broadcast sent to {successful_sends}/{len(connection_ids)} connections")
            return successful_sends
            
        except Exception as e:
            logger.error(f"Broadcast error: {e}")
            return 0
    
    async def send_system_notification(
        self, 
        user_id: int, 
        notification_type: str,
        title: str,
        message: str,
        level: str = "info"
    ):
        """Send system notification to user."""
        notification = {
            "type": "system_notification",
            "notification_type": notification_type,
            "title": title,
            "message": message,
            "level": level,  # "info", "warning", "error", "success"
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        return await self.send_to_user(user_id, notification)
    
    async def handle_ping(self, connection_id: str):
        """Handle ping from client to maintain connection."""
        try:
            if connection_id in self.connection_metadata:
                self.connection_metadata[connection_id]["last_ping"] = datetime.utcnow()
            
            await self._send_to_connection(connection_id, {
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Ping handling error for {connection_id}: {e}")
            await self.disconnect(connection_id)
    
    async def handle_message(self, connection_id: str, message: Dict[str, Any]):
        """Handle incoming message from client."""
        try:
            message_type = message.get("type")
            
            if message_type == "ping":
                await self.handle_ping(connection_id)
            
            elif message_type == "subscribe":
                # Handle subscription to specific channels/topics
                await self._handle_subscription(connection_id, message)
            
            elif message_type == "unsubscribe":
                # Handle unsubscription
                await self._handle_unsubscription(connection_id, message)
            
            else:
                logger.warning(f"Unknown message type '{message_type}' from {connection_id}")
                
        except Exception as e:
            logger.error(f"Message handling error for {connection_id}: {e}")
    
    async def _handle_subscription(self, connection_id: str, message: Dict[str, Any]):
        """Handle client subscription to channels."""
        # TODO: Implement channel subscription logic
        pass
    
    async def _handle_unsubscription(self, connection_id: str, message: Dict[str, Any]):
        """Handle client unsubscription from channels."""
        # TODO: Implement channel unsubscription logic
        pass
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get current connection statistics."""
        try:
            total_connections = len(self.active_connections)
            unique_users = len(self.user_connections)
            
            # Calculate connections per user
            connections_per_user = {}
            for user_id, connections in self.user_connections.items():
                connections_per_user[user_id] = len(connections)
            
            # Get oldest and newest connections
            oldest_connection = None
            newest_connection = None
            
            if self.connection_metadata:
                sorted_connections = sorted(
                    self.connection_metadata.items(),
                    key=lambda x: x[1]["connected_at"]
                )
                oldest_connection = sorted_connections[0][1]["connected_at"]
                newest_connection = sorted_connections[-1][1]["connected_at"]
            
            return {
                "total_connections": total_connections,
                "unique_users": unique_users,
                "connections_per_user": connections_per_user,
                "oldest_connection": oldest_connection.isoformat() if oldest_connection else None,
                "newest_connection": newest_connection.isoformat() if newest_connection else None,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting connection stats: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def cleanup_stale_connections(self, timeout_minutes: int = 30):
        """Clean up connections that haven't pinged recently."""
        try:
            cutoff_time = datetime.utcnow().timestamp() - (timeout_minutes * 60)
            stale_connections = []
            
            for connection_id, metadata in self.connection_metadata.items():
                last_ping = metadata.get("last_ping", metadata.get("connected_at"))
                if last_ping.timestamp() < cutoff_time:
                    stale_connections.append(connection_id)
            
            for connection_id in stale_connections:
                logger.info(f"Cleaning up stale connection: {connection_id}")
                await self.disconnect(connection_id)
            
            if stale_connections:
                logger.info(f"Cleaned up {len(stale_connections)} stale connections")
            
        except Exception as e:
            logger.error(f"Error cleaning up stale connections: {e}")


# Global WebSocket manager instance
websocket_manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket, user_id: int):
    """WebSocket endpoint handler."""
    connection_id = None
    
    try:
        # Get client info
        client_ip = websocket.client.host if websocket.client else "unknown"
        user_agent = websocket.headers.get("user-agent", "unknown")
        
        # Connect
        connection_id = await websocket_manager.connect(
            websocket, user_id, client_ip, user_agent
        )
        
        logger.info(f"WebSocket connection established: {connection_id}")
        
        # Handle messages
        while True:
            try:
                # Receive message
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle message
                await websocket_manager.handle_message(connection_id, message)
                
            except WebSocketDisconnect:
                logger.info(f"WebSocket client disconnected: {connection_id}")
                break
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON from {connection_id}: {e}")
                await websocket_manager.send_to_connection(connection_id, {
                    "type": "error",
                    "error": "Invalid JSON format"
                })
            except Exception as e:
                logger.error(f"WebSocket message error for {connection_id}: {e}")
                await websocket_manager.send_to_connection(connection_id, {
                    "type": "error",
                    "error": "Message processing failed"
                })
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket connection closed during handshake for user {user_id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
    finally:
        # Clean up connection
        if connection_id:
            await websocket_manager.disconnect(connection_id)


# Periodic cleanup task
async def periodic_cleanup():
    """Periodically clean up stale connections."""
    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            await websocket_manager.cleanup_stale_connections()
        except Exception as e:
            logger.error(f"Periodic cleanup error: {e}")
            await asyncio.sleep(60)  # Wait 1 minute before retry


# Start cleanup task when module is imported
cleanup_task = asyncio.create_task(periodic_cleanup())
