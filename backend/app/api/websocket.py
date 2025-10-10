"""
WebSocket endpoints for real-time security monitoring
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse
import uuid
import json

from app.config.logging import get_logger
from app.services.real_time_monitor import real_time_monitor

logger = get_logger(__name__)

router = APIRouter(prefix="/ws", tags=["WebSocket"])


@router.websocket("/monitor")
async def websocket_monitor_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time security monitoring"""
    client_id = str(uuid.uuid4())
    
    try:
        await real_time_monitor.handle_websocket_connection(websocket, client_id)
    except WebSocketDisconnect:
        logger.info(f"Client {client_id} disconnected")
    except Exception as e:
        logger.error(f"Error in WebSocket connection {client_id}: {e}")


@router.get("/monitor-test")
async def get_websocket_test_page():
    """Test page for WebSocket monitoring"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishNet Real-time Monitor Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
            .connected { background-color: #d4edda; color: #155724; }
            .disconnected { background-color: #f8d7da; color: #721c24; }
            .event { padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 5px; }
            .event.threat_detected { border-left: 4px solid #dc3545; }
            .event.incident_created { border-left: 4px solid #fd7e14; }
            .event.threat_intel { border-left: 4px solid #6f42c1; }
            .event.system_alert { border-left: 4px solid #ffc107; }
            .controls { margin: 20px 0; }
            .controls button { margin: 5px; padding: 10px 15px; border: none; border-radius: 5px; cursor: pointer; }
            .controls .btn-primary { background-color: #007bff; color: white; }
            .controls .btn-success { background-color: #28a745; color: white; }
            .controls .btn-warning { background-color: #ffc107; color: black; }
            .controls .btn-danger { background-color: #dc3545; color: white; }
            .events-container { max-height: 600px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; }
            .metadata { font-size: 0.9em; color: #666; margin-top: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PhishNet Real-time Security Monitor</h1>
            
            <div id="status" class="status disconnected">
                Disconnected
            </div>
            
            <div class="controls">
                <button id="connect-btn" class="btn-primary" onclick="connectWebSocket()">Connect</button>
                <button id="disconnect-btn" class="btn-danger" onclick="disconnectWebSocket()" disabled>Disconnect</button>
                <button class="btn-success" onclick="subscribeToAll()">Subscribe to All Events</button>
                <button class="btn-warning" onclick="subscribeToThreats()">Subscribe to Threats Only</button>
                <button class="btn-warning" onclick="getRecentEvents()">Get Recent Events</button>
                <button class="btn-danger" onclick="clearEvents()">Clear Events</button>
            </div>
            
            <div class="controls">
                <label>Event Types:</label>
                <input type="checkbox" id="threat_detected" checked> Threat Detected
                <input type="checkbox" id="incident_created" checked> Incident Created  
                <input type="checkbox" id="threat_intel" checked> Threat Intelligence
                <input type="checkbox" id="system_alert" checked> System Alerts
            </div>
            
            <h2>Live Events <span id="event-count">(0)</span></h2>
            <div id="events" class="events-container">
                <!-- Events will appear here -->
            </div>
        </div>

        <script>
            let socket = null;
            let eventCount = 0;
            
            function connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;
                
                socket = new WebSocket(wsUrl);
                
                socket.onopen = function(event) {
                    console.log('Connected to WebSocket');
                    document.getElementById('status').className = 'status connected';
                    document.getElementById('status').textContent = 'Connected';
                    document.getElementById('connect-btn').disabled = true;
                    document.getElementById('disconnect-btn').disabled = false;
                    
                    // Subscribe to all events by default
                    subscribeToAll();
                };
                
                socket.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    displayEvent(data);
                };
                
                socket.onclose = function(event) {
                    console.log('Disconnected from WebSocket');
                    document.getElementById('status').className = 'status disconnected';
                    document.getElementById('status').textContent = 'Disconnected';
                    document.getElementById('connect-btn').disabled = false;
                    document.getElementById('disconnect-btn').disabled = true;
                };
                
                socket.onerror = function(error) {
                    console.error('WebSocket error:', error);
                };
            }
            
            function disconnectWebSocket() {
                if (socket) {
                    socket.close();
                    socket = null;
                }
            }
            
            function subscribeToAll() {
                if (socket && socket.readyState === WebSocket.OPEN) {
                    const message = {
                        type: 'subscribe',
                        event_types: ['threat_detected', 'incident_created', 'threat_intel', 'system_alert']
                    };
                    socket.send(JSON.stringify(message));
                    console.log('Subscribed to all events');
                }
            }
            
            function subscribeToThreats() {
                if (socket && socket.readyState === WebSocket.OPEN) {
                    const message = {
                        type: 'subscribe',
                        event_types: ['threat_detected', 'threat_intel']
                    };
                    socket.send(JSON.stringify(message));
                    console.log('Subscribed to threat events only');
                }
            }
            
            function getRecentEvents() {
                if (socket && socket.readyState === WebSocket.OPEN) {
                    const message = {
                        type: 'get_recent_events'
                    };
                    socket.send(JSON.stringify(message));
                    console.log('Requested recent events');
                }
            }
            
            function clearEvents() {
                document.getElementById('events').innerHTML = '';
                eventCount = 0;
                document.getElementById('event-count').textContent = `(${eventCount})`;
            }
            
            function displayEvent(data) {
                const eventsContainer = document.getElementById('events');
                const eventDiv = document.createElement('div');
                
                if (data.type === 'security_event' || data.type === 'historical_event') {
                    const event = data.data;
                    eventDiv.className = `event ${event.event_type}`;
                    
                    const timestamp = new Date(event.timestamp).toLocaleString();
                    const severity = event.severity.toUpperCase();
                    
                    eventDiv.innerHTML = `
                        <strong>[${severity}] ${event.title}</strong>
                        <div>${event.description}</div>
                        <div class="metadata">
                            <strong>Source:</strong> ${event.source} | 
                            <strong>Time:</strong> ${timestamp} |
                            <strong>Type:</strong> ${event.event_type} |
                            <strong>ID:</strong> ${event.event_id}
                        </div>
                        ${event.metadata ? '<div class="metadata"><strong>Metadata:</strong> ' + JSON.stringify(event.metadata, null, 2) + '</div>' : ''}
                    `;
                } else if (data.type === 'threat_feed_update') {
                    const update = data.data;
                    eventDiv.className = 'event threat_intel';
                    
                    const timestamp = new Date(update.last_seen).toLocaleString();
                    
                    eventDiv.innerHTML = `
                        <strong>[THREAT FEED] ${update.ioc_type.toUpperCase()}: ${update.ioc_value}</strong>
                        <div>Threat Type: ${update.threat_type} | Confidence: ${(update.confidence * 100).toFixed(1)}%</div>
                        <div class="metadata">
                            <strong>Source:</strong> ${update.feed_source} | 
                            <strong>Reputation:</strong> ${update.reputation_score}/10 |
                            <strong>Last Seen:</strong> ${timestamp}
                        </div>
                    `;
                }
                
                // Insert at the top
                eventsContainer.insertBefore(eventDiv, eventsContainer.firstChild);
                
                // Limit to 100 events
                while (eventsContainer.children.length > 100) {
                    eventsContainer.removeChild(eventsContainer.lastChild);
                }
                
                eventCount++;
                document.getElementById('event-count').textContent = `(${eventCount})`;
                
                // Auto-scroll to top for new events
                if (data.type !== 'historical_event') {
                    eventsContainer.scrollTop = 0;
                }
            }
            
            // Auto-connect on page load
            window.addEventListener('load', function() {
                connectWebSocket();
            });
            
            // Cleanup on page unload
            window.addEventListener('beforeunload', function() {
                if (socket) {
                    socket.close();
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.get("/stats")
async def get_monitoring_stats():
    """Get real-time monitoring statistics"""
    return real_time_monitor.get_connection_stats()