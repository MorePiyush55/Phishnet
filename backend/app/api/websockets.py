"""
WebSocket Support for Real-time Job Status Updates
Provides real-time notifications for background job progress.
"""

import json
import asyncio
from typing import Dict, List
from datetime import datetime
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from fastapi.websockets import WebSocketState

from backend.app.workers.celery_config import celery_app
from backend.app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSocket"])

class ConnectionManager:
    """Manages WebSocket connections and broadcasts."""
    
    def __init__(self):
        # Store active connections by job_id
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Store connection metadata
        self.connection_metadata: Dict[WebSocket, Dict[str, str]] = {}
    
    async def connect(self, websocket: WebSocket, job_id: str, user_id: str = None):
        """Accept a new WebSocket connection for a specific job."""
        await websocket.accept()
        
        if job_id not in self.active_connections:
            self.active_connections[job_id] = []
        
        self.active_connections[job_id].append(websocket)
        self.connection_metadata[websocket] = {
            "job_id": job_id,
            "user_id": user_id or "anonymous",
            "connected_at": datetime.utcnow().isoformat()
        }
        
        logger.info(f"WebSocket connected for job {job_id}, user {user_id}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if websocket in self.connection_metadata:
            metadata = self.connection_metadata.pop(websocket)
            job_id = metadata.get("job_id")
            
            if job_id and job_id in self.active_connections:
                try:
                    self.active_connections[job_id].remove(websocket)
                    if not self.active_connections[job_id]:
                        del self.active_connections[job_id]
                except ValueError:
                    pass
            
            logger.info(f"WebSocket disconnected for job {job_id}")
    
    async def send_personal_message(self, message: Dict, websocket: WebSocket):
        """Send a message to a specific WebSocket."""
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send personal message: {str(e)}")
    
    async def broadcast_to_job(self, job_id: str, message: Dict):
        """Broadcast a message to all connections for a specific job."""
        if job_id not in self.active_connections:
            return
        
        disconnected_connections = []
        
        for connection in self.active_connections[job_id]:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_text(json.dumps(message))
                else:
                    disconnected_connections.append(connection)
            except Exception as e:
                logger.error(f"Failed to broadcast to job {job_id}: {str(e)}")
                disconnected_connections.append(connection)
        
        # Clean up disconnected connections
        for connection in disconnected_connections:
            self.disconnect(connection)
    
    async def broadcast_to_all(self, message: Dict):
        """Broadcast a message to all active connections."""
        for job_id in list(self.active_connections.keys()):
            await self.broadcast_to_job(job_id, message)
    
    def get_active_connections_count(self) -> int:
        """Get the total number of active connections."""
        return sum(len(connections) for connections in self.active_connections.values())
    
    def get_job_connections_count(self, job_id: str) -> int:
        """Get the number of connections for a specific job."""
        return len(self.active_connections.get(job_id, []))

# Global connection manager
manager = ConnectionManager()

@router.websocket("/jobs/{job_id}")
async def websocket_job_status(websocket: WebSocket, job_id: str):
    """WebSocket endpoint for real-time job status updates."""
    try:
        # Extract user info from query params or headers if needed
        user_id = websocket.query_params.get("user_id", "anonymous")
        
        await manager.connect(websocket, job_id, user_id)
        
        # Send initial connection confirmation
        await manager.send_personal_message({
            "type": "connection_established",
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Connected to job status updates"
        }, websocket)
        
        # Get initial job status
        try:
            task_result = celery_app.AsyncResult(job_id)
            redis_client = get_redis_client()
            job_data = redis_client.hgetall(f"job:{job_id}")
            
            # Send initial status
            initial_status = {
                "type": "status_update",
                "job_id": job_id,
                "status": _map_celery_state(task_result.state),
                "progress": _calculate_progress(task_result.state, job_data),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await manager.send_personal_message(initial_status, websocket)
        except Exception as e:
            logger.error(f"Failed to send initial status for job {job_id}: {str(e)}")
        
        # Keep connection alive and handle incoming messages
        try:
            while True:
                # Wait for messages from client
                data = await websocket.receive_text()
                
                try:
                    message = json.loads(data)
                    await handle_client_message(websocket, job_id, message)
                except json.JSONDecodeError:
                    await manager.send_personal_message({
                        "type": "error",
                        "message": "Invalid JSON message",
                        "timestamp": datetime.utcnow().isoformat()
                    }, websocket)
                    
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for job {job_id}")
        
    except Exception as e:
        logger.error(f"WebSocket error for job {job_id}: {str(e)}")
    finally:
        manager.disconnect(websocket)

@router.websocket("/system")
async def websocket_system_status(websocket: WebSocket):
    """WebSocket endpoint for system-wide status updates."""
    try:
        await websocket.accept()
        
        # Send system stats periodically
        while True:
            try:
                # Get system statistics
                system_stats = await get_system_stats()
                
                await websocket.send_text(json.dumps({
                    "type": "system_status",
                    "data": system_stats,
                    "timestamp": datetime.utcnow().isoformat()
                }))
                
                # Wait 30 seconds before next update
                await asyncio.sleep(30)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"System WebSocket error: {str(e)}")
                break
                
    except Exception as e:
        logger.error(f"System WebSocket initialization error: {str(e)}")

async def handle_client_message(websocket: WebSocket, job_id: str, message: Dict):
    """Handle incoming messages from WebSocket clients."""
    try:
        message_type = message.get("type")
        
        if message_type == "ping":
            # Respond to ping with pong
            await manager.send_personal_message({
                "type": "pong",
                "timestamp": datetime.utcnow().isoformat()
            }, websocket)
            
        elif message_type == "get_status":
            # Send current job status
            task_result = celery_app.AsyncResult(job_id)
            redis_client = get_redis_client()
            job_data = redis_client.hgetall(f"job:{job_id}")
            
            status_update = {
                "type": "status_update",
                "job_id": job_id,
                "status": _map_celery_state(task_result.state),
                "progress": _calculate_progress(task_result.state, job_data),
                "result": task_result.result if task_result.ready() else None,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await manager.send_personal_message(status_update, websocket)
            
        elif message_type == "subscribe_to_logs":
            # Enable log streaming (implementation would depend on requirements)
            await manager.send_personal_message({
                "type": "log_subscription",
                "status": "enabled",
                "message": "Log streaming enabled for this job",
                "timestamp": datetime.utcnow().isoformat()
            }, websocket)
            
        else:
            await manager.send_personal_message({
                "type": "error",
                "message": f"Unknown message type: {message_type}",
                "timestamp": datetime.utcnow().isoformat()
            }, websocket)
            
    except Exception as e:
        logger.error(f"Error handling client message: {str(e)}")
        await manager.send_personal_message({
            "type": "error",
            "message": "Failed to process message",
            "timestamp": datetime.utcnow().isoformat()
        }, websocket)

def _map_celery_state(celery_state: str) -> str:
    """Map Celery task states to our WebSocket status."""
    mapping = {
        "PENDING": "pending",
        "STARTED": "processing",
        "RETRY": "processing", 
        "SUCCESS": "completed",
        "FAILURE": "failed",
        "REVOKED": "cancelled"
    }
    return mapping.get(celery_state, "unknown")

def _calculate_progress(celery_state: str, job_data: Dict) -> int:
    """Calculate progress percentage based on state and metadata."""
    if celery_state == "SUCCESS":
        return 100
    elif celery_state == "STARTED":
        # Could extract actual progress from job_data if tasks report it
        return 50
    elif celery_state == "PENDING":
        return 0
    else:
        return 0

async def get_system_stats() -> Dict:
    """Get current system statistics."""
    try:
        # Get basic stats (this would be expanded with real metrics)
        redis_client = get_redis_client()
        
        stats = {
            "active_jobs": 0,  # Would query Celery for active tasks
            "pending_jobs": 0,  # Would query queues
            "completed_jobs_today": int(redis_client.get(f"jobs:completed:daily:{datetime.utcnow().strftime('%Y-%m-%d')}") or 0),
            "failed_jobs_today": int(redis_client.get(f"failures:daily:{datetime.utcnow().strftime('%Y-%m-%d')}") or 0),
            "active_connections": manager.get_active_connections_count(),
            "system_health": "healthy"
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get system stats: {str(e)}")
        return {"error": "Failed to get system stats"}

# Functions to be called from task completion/failure
async def notify_job_progress(job_id: str, progress: int, message: str = None):
    """Notify WebSocket clients of job progress."""
    try:
        update_message = {
            "type": "progress_update",
            "job_id": job_id,
            "progress": progress,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await manager.broadcast_to_job(job_id, update_message)
        
    except Exception as e:
        logger.error(f"Failed to notify job progress for {job_id}: {str(e)}")

async def notify_job_completion(job_id: str, result: Dict, success: bool = True):
    """Notify WebSocket clients of job completion."""
    try:
        completion_message = {
            "type": "job_completed" if success else "job_failed",
            "job_id": job_id,
            "result": result if success else None,
            "error": result if not success else None,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await manager.broadcast_to_job(job_id, completion_message)
        
    except Exception as e:
        logger.error(f"Failed to notify job completion for {job_id}: {str(e)}")

async def notify_system_alert(alert_type: str, message: str, severity: str = "info"):
    """Broadcast system-wide alerts."""
    try:
        alert_message = {
            "type": "system_alert",
            "alert_type": alert_type,
            "message": message,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await manager.broadcast_to_all(alert_message)
        
    except Exception as e:
        logger.error(f"Failed to send system alert: {str(e)}")

# Export connection manager for use in other modules
__all__ = ["router", "manager", "notify_job_progress", "notify_job_completion", "notify_system_alert"]