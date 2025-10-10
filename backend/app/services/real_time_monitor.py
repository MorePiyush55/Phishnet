"""
Real-time Threat Monitoring Service for PhishNet
Provides WebSocket-based real-time threat feed and live monitoring capabilities
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from fastapi import WebSocket, WebSocketDisconnect
import websockets
from websockets.exceptions import ConnectionClosed

from app.config.logging import get_logger
from app.intelligence.threat_intel import threat_intelligence_manager
from app.workflows.incident_manager import incident_manager
from app.models.mongodb_models import Detection, Incident, ThreatIntelligence

logger = get_logger(__name__)


@dataclass
class RealTimeEvent:
    """Real-time security event"""
    event_id: str
    event_type: str  # threat_detected, incident_created, intel_updated, etc.
    severity: str
    title: str
    description: str
    source: str
    timestamp: datetime
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class ThreatFeedUpdate:
    """Threat intelligence feed update"""
    update_id: str
    feed_source: str
    ioc_type: str
    ioc_value: str
    threat_type: str
    confidence: float
    reputation_score: float
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['first_seen'] = self.first_seen.isoformat()
        data['last_seen'] = self.last_seen.isoformat()
        return data


class ConnectionManager:
    """WebSocket connection manager for real-time monitoring"""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {}  # client_id -> event_types
        
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.subscriptions[client_id] = set()
        logger.info(f"Client {client_id} connected to real-time monitoring")
        
    def disconnect(self, client_id: str):
        """Remove a WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.subscriptions:
            del self.subscriptions[client_id]
        logger.info(f"Client {client_id} disconnected from real-time monitoring")
        
    async def send_personal_message(self, message: str, client_id: str):
        """Send a message to a specific client"""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_text(message)
            except (WebSocketDisconnect, ConnectionClosed):
                self.disconnect(client_id)
                
    async def broadcast_event(self, event: RealTimeEvent):
        """Broadcast an event to all subscribed clients"""
        message = json.dumps({
            "type": "security_event",
            "data": event.to_dict()
        })
        
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            # Check if client is subscribed to this event type
            if event.event_type in self.subscriptions.get(client_id, set()):
                try:
                    await websocket.send_text(message)
                except (WebSocketDisconnect, ConnectionClosed):
                    disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
            
    async def broadcast_threat_feed(self, update: ThreatFeedUpdate):
        """Broadcast threat intelligence feed update"""
        message = json.dumps({
            "type": "threat_feed_update",
            "data": update.to_dict()
        })
        
        disconnected_clients = []
        
        for client_id, websocket in self.active_connections.items():
            # Check if client is subscribed to threat feeds
            if "threat_intel" in self.subscriptions.get(client_id, set()):
                try:
                    await websocket.send_text(message)
                except (WebSocketDisconnect, ConnectionClosed):
                    disconnected_clients.append(client_id)
        
        for client_id in disconnected_clients:
            self.disconnect(client_id)
            
    def subscribe_to_events(self, client_id: str, event_types: List[str]):
        """Subscribe a client to specific event types"""
        if client_id not in self.subscriptions:
            self.subscriptions[client_id] = set()
        
        self.subscriptions[client_id].update(event_types)
        logger.info(f"Client {client_id} subscribed to events: {event_types}")
        
    def unsubscribe_from_events(self, client_id: str, event_types: List[str]):
        """Unsubscribe a client from specific event types"""
        if client_id in self.subscriptions:
            self.subscriptions[client_id].difference_update(event_types)
            logger.info(f"Client {client_id} unsubscribed from events: {event_types}")


class RealTimeMonitor:
    """Real-time security monitoring service"""
    
    def __init__(self):
        self.connection_manager = ConnectionManager()
        self.event_buffer: List[RealTimeEvent] = []
        self.threat_feed_buffer: List[ThreatFeedUpdate] = []
        self.max_buffer_size = 1000
        self.monitoring_active = False
        
    async def start_monitoring(self):
        """Start real-time monitoring services"""
        if self.monitoring_active:
            return
            
        self.monitoring_active = True
        logger.info("Starting real-time security monitoring")
        
        # Start monitoring tasks
        tasks = [
            asyncio.create_task(self._monitor_threat_detections()),
            asyncio.create_task(self._monitor_incidents()),
            asyncio.create_task(self._monitor_threat_intelligence()),
            asyncio.create_task(self._monitor_system_health()),
            asyncio.create_task(self._cleanup_buffers())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Error in real-time monitoring: {e}")
            self.monitoring_active = False
            
    async def stop_monitoring(self):
        """Stop real-time monitoring services"""
        self.monitoring_active = False
        logger.info("Stopped real-time security monitoring")
        
    async def handle_websocket_connection(self, websocket: WebSocket, client_id: str):
        """Handle a new WebSocket connection"""
        await self.connection_manager.connect(websocket, client_id)
        
        try:
            while True:
                # Receive messages from client
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get("type") == "subscribe":
                    event_types = message.get("event_types", [])
                    self.connection_manager.subscribe_to_events(client_id, event_types)
                    
                elif message.get("type") == "unsubscribe":
                    event_types = message.get("event_types", [])
                    self.connection_manager.unsubscribe_from_events(client_id, event_types)
                    
                elif message.get("type") == "get_recent_events":
                    await self._send_recent_events(client_id)
                    
        except WebSocketDisconnect:
            self.connection_manager.disconnect(client_id)
        except Exception as e:
            logger.error(f"Error handling WebSocket connection for {client_id}: {e}")
            self.connection_manager.disconnect(client_id)
            
    async def _monitor_threat_detections(self):
        """Monitor for new threat detections"""
        last_check = datetime.utcnow()
        
        while self.monitoring_active:
            try:
                current_time = datetime.utcnow()
                
                # Query for new detections since last check
                new_detections = await Detection.find({
                    "created_at": {"$gte": last_check},
                    "is_phishing": True
                }).to_list()
                
                for detection in new_detections:
                    event = RealTimeEvent(
                        event_id=f"threat_{detection.id}_{current_time.timestamp()}",
                        event_type="threat_detected",
                        severity=self._map_risk_to_severity(detection.risk_level),
                        title="Phishing Threat Detected",
                        description=f"Phishing email detected with {detection.confidence_score:.1%} confidence",
                        source="PhishNet Detection Engine",
                        timestamp=detection.created_at,
                        metadata={
                            "detection_id": str(detection.id),
                            "confidence_score": detection.confidence_score,
                            "risk_level": detection.risk_level,
                            "model_type": detection.model_type,
                            "risk_factors": detection.risk_factors or []
                        }
                    )
                    
                    await self._add_event_to_buffer(event)
                    await self.connection_manager.broadcast_event(event)
                
                last_check = current_time
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring threat detections: {e}")
                await asyncio.sleep(10)
                
    async def _monitor_incidents(self):
        """Monitor for new incidents"""
        last_check = datetime.utcnow()
        
        while self.monitoring_active:
            try:
                current_time = datetime.utcnow()
                
                # Query for new incidents
                new_incidents = await Incident.find({
                    "created_at": {"$gte": last_check}
                }).to_list()
                
                for incident in new_incidents:
                    event = RealTimeEvent(
                        event_id=f"incident_{incident.id}_{current_time.timestamp()}",
                        event_type="incident_created",
                        severity=incident.severity,
                        title=f"Security Incident: {incident.title}",
                        description=incident.description,
                        source="PhishNet Incident Manager",
                        timestamp=incident.created_at,
                        metadata={
                            "incident_id": str(incident.id),
                            "incident_type": incident.incident_type,
                            "status": incident.status,
                            "assigned_to": incident.assigned_to,
                            "escalated": incident.escalated
                        }
                    )
                    
                    await self._add_event_to_buffer(event)
                    await self.connection_manager.broadcast_event(event)
                
                last_check = current_time
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring incidents: {e}")
                await asyncio.sleep(15)
                
    async def _monitor_threat_intelligence(self):
        """Monitor threat intelligence feed updates"""
        last_check = datetime.utcnow()
        
        while self.monitoring_active:
            try:
                current_time = datetime.utcnow()
                
                # Query for new threat intelligence
                new_intel = await ThreatIntelligence.find({
                    "last_updated": {"$gte": last_check}
                }).to_list()
                
                for intel in new_intel:
                    # Create threat feed update
                    feed_update = ThreatFeedUpdate(
                        update_id=f"intel_{intel.id}_{current_time.timestamp()}",
                        feed_source=intel.source or "Unknown",
                        ioc_type=intel.ioc_type,
                        ioc_value=intel.ioc_value,
                        threat_type=intel.threat_type,
                        confidence=intel.confidence or 0.5,
                        reputation_score=intel.reputation_score or 5.0,
                        first_seen=intel.first_seen or current_time,
                        last_seen=intel.last_seen or current_time,
                        tags=intel.tags or []
                    )
                    
                    await self._add_threat_feed_to_buffer(feed_update)
                    await self.connection_manager.broadcast_threat_feed(feed_update)
                    
                    # Also create a general event for high-risk intel
                    if intel.reputation_score and intel.reputation_score >= 8.0:
                        event = RealTimeEvent(
                            event_id=f"high_risk_intel_{intel.id}_{current_time.timestamp()}",
                            event_type="threat_intel",
                            severity="high",
                            title="High-Risk Threat Intelligence",
                            description=f"New high-risk {intel.ioc_type}: {intel.ioc_value}",
                            source=f"Threat Intel Feed: {intel.source}",
                            timestamp=intel.last_updated or current_time,
                            metadata={
                                "intel_id": str(intel.id),
                                "ioc_type": intel.ioc_type,
                                "ioc_value": intel.ioc_value,
                                "reputation_score": intel.reputation_score,
                                "threat_type": intel.threat_type
                            }
                        )
                        
                        await self._add_event_to_buffer(event)
                        await self.connection_manager.broadcast_event(event)
                
                last_check = current_time
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error monitoring threat intelligence: {e}")
                await asyncio.sleep(30)
                
    async def _monitor_system_health(self):
        """Monitor system health and performance"""
        while self.monitoring_active:
            try:
                # Check system metrics (mock data for now)
                cpu_usage = 75.5  # In real implementation, get from system monitoring
                memory_usage = 82.3
                disk_usage = 65.1
                
                # Generate alerts for high resource usage
                if cpu_usage > 80:
                    event = RealTimeEvent(
                        event_id=f"cpu_alert_{datetime.utcnow().timestamp()}",
                        event_type="system_alert",
                        severity="warning",
                        title="High CPU Usage Alert",
                        description=f"CPU usage is at {cpu_usage:.1f}%",
                        source="PhishNet System Monitor",
                        timestamp=datetime.utcnow(),
                        metadata={
                            "metric_type": "cpu_usage",
                            "value": cpu_usage,
                            "threshold": 80
                        }
                    )
                    
                    await self._add_event_to_buffer(event)
                    await self.connection_manager.broadcast_event(event)
                
                if memory_usage > 85:
                    event = RealTimeEvent(
                        event_id=f"memory_alert_{datetime.utcnow().timestamp()}",
                        event_type="system_alert",
                        severity="warning",
                        title="High Memory Usage Alert",
                        description=f"Memory usage is at {memory_usage:.1f}%",
                        source="PhishNet System Monitor",
                        timestamp=datetime.utcnow(),
                        metadata={
                            "metric_type": "memory_usage",
                            "value": memory_usage,
                            "threshold": 85
                        }
                    )
                    
                    await self._add_event_to_buffer(event)
                    await self.connection_manager.broadcast_event(event)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error monitoring system health: {e}")
                await asyncio.sleep(60)
                
    async def _cleanup_buffers(self):
        """Clean up old events from buffers"""
        while self.monitoring_active:
            try:
                # Keep only recent events (last 24 hours)
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                
                self.event_buffer = [
                    event for event in self.event_buffer 
                    if event.timestamp > cutoff_time
                ]
                
                self.threat_feed_buffer = [
                    update for update in self.threat_feed_buffer 
                    if update.last_seen > cutoff_time
                ]
                
                # Limit buffer sizes
                if len(self.event_buffer) > self.max_buffer_size:
                    self.event_buffer = self.event_buffer[-self.max_buffer_size:]
                    
                if len(self.threat_feed_buffer) > self.max_buffer_size:
                    self.threat_feed_buffer = self.threat_feed_buffer[-self.max_buffer_size:]
                
                await asyncio.sleep(300)  # Cleanup every 5 minutes
                
            except Exception as e:
                logger.error(f"Error cleaning up buffers: {e}")
                await asyncio.sleep(300)
                
    async def _add_event_to_buffer(self, event: RealTimeEvent):
        """Add event to buffer"""
        self.event_buffer.append(event)
        if len(self.event_buffer) > self.max_buffer_size:
            self.event_buffer.pop(0)
            
    async def _add_threat_feed_to_buffer(self, update: ThreatFeedUpdate):
        """Add threat feed update to buffer"""
        self.threat_feed_buffer.append(update)
        if len(self.threat_feed_buffer) > self.max_buffer_size:
            self.threat_feed_buffer.pop(0)
            
    async def _send_recent_events(self, client_id: str):
        """Send recent events to a specific client"""
        recent_events = self.event_buffer[-50:]  # Last 50 events
        
        for event in recent_events:
            message = json.dumps({
                "type": "historical_event",
                "data": event.to_dict()
            })
            await self.connection_manager.send_personal_message(message, client_id)
            
    def _map_risk_to_severity(self, risk_level: str) -> str:
        """Map risk level to severity"""
        mapping = {
            "LOW": "low",
            "MEDIUM": "medium",
            "HIGH": "high",
            "CRITICAL": "critical"
        }
        return mapping.get(risk_level.upper(), "medium")
        
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            "active_connections": len(self.connection_manager.active_connections),
            "total_subscriptions": sum(len(subs) for subs in self.connection_manager.subscriptions.values()),
            "event_buffer_size": len(self.event_buffer),
            "threat_feed_buffer_size": len(self.threat_feed_buffer),
            "monitoring_active": self.monitoring_active
        }


# Global instance
real_time_monitor = RealTimeMonitor()