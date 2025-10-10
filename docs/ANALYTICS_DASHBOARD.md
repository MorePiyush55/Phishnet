# PhishNet Analytics Dashboard Documentation

## Overview

The PhishNet Analytics Dashboard is a comprehensive security operations center that provides real-time monitoring, threat analysis, and incident management capabilities. Built with modern web technologies, it offers enterprise-grade security analytics with intuitive visualizations.

## Features

### 📊 Real-time Analytics
- **Live Threat Monitoring**: Real-time detection and analysis of phishing threats
- **Interactive Dashboard**: Comprehensive security metrics with customizable views
- **Multi-timeframe Analysis**: Support for 1h, 24h, 7d, and 30d time ranges
- **Trend Analysis**: Historical data trends with forecasting capabilities

### 🔴 Live Monitoring
- **WebSocket Integration**: Real-time event streaming without page refresh
- **Alert Management**: Configurable alert subscriptions and filtering
- **Performance Metrics**: Live system performance and resource monitoring
- **Connection Management**: Client connection tracking and statistics

### 📈 Data Visualization
- **Interactive Charts**: Line charts, bar charts, pie charts, and area charts
- **Threat Distribution**: Visual representation of risk levels and threat types
- **Performance Dashboards**: System metrics and API performance tracking
- **Custom Time Ranges**: Flexible date range selection and analysis

## API Endpoints

### Analytics Endpoints

#### Get Dashboard Metrics
```http
GET /api/analytics/dashboard?time_range=24h&include_trends=true
```

**Response:**
```json
{
  "threat_overview": {
    "total_threats_detected": 150,
    "phishing_emails_blocked": 125,
    "risk_distribution": {"LOW": 30, "MEDIUM": 50, "HIGH": 45, "CRITICAL": 25}
  },
  "email_analysis": {
    "total_emails_analyzed": 2340,
    "phishing_detection_rate": 0.923,
    "accuracy_score": 0.956
  },
  "real_time_alerts": [...],
  "performance_metrics": {...},
  "trend_analysis": {...}
}
```

#### Get Threat Overview
```http
GET /api/analytics/threat-overview?time_range=7d
```

#### Get Real-time Alerts
```http
GET /api/analytics/real-time-alerts?severity=high&limit=50
```

#### Get Performance Metrics
```http
GET /api/analytics/performance-metrics?time_range=24h
```

### WebSocket Endpoints

#### Real-time Monitoring
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/monitor');

// Subscribe to events
ws.send(JSON.stringify({
  type: 'subscribe',
  event_types: ['threat_detected', 'incident_created', 'threat_intel']
}));

// Handle incoming events
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  if (data.type === 'security_event') {
    console.log('New security event:', data.data);
  }
};
```

## Frontend Components

### SecurityDashboard Component

The main dashboard component provides:

- **Threat Overview Cards**: Key metrics and status indicators
- **Interactive Charts**: Real-time data visualization
- **Alert Feed**: Live security alerts and notifications
- **Performance Monitoring**: System health and metrics
- **Time Range Controls**: Flexible time period selection

### Key Features:

1. **Auto-refresh**: Configurable automatic data refresh
2. **Responsive Design**: Mobile-friendly layout
3. **Real-time Updates**: WebSocket-based live data
4. **Interactive Elements**: Clickable charts and filters
5. **Export Capabilities**: Data export and reporting

## Configuration

### Environment Variables

```bash
# Analytics Dashboard Configuration
ANALYTICS_REFRESH_INTERVAL=30  # seconds
WEBSOCKET_HEARTBEAT_INTERVAL=20  # seconds
MAX_ALERT_BUFFER_SIZE=1000
DASHBOARD_CACHE_TTL=300  # seconds

# Real-time Monitoring
REALTIME_MONITORING_ENABLED=true
EVENT_RETENTION_HOURS=24
MAX_CONCURRENT_CONNECTIONS=100
```

### Database Setup

The analytics dashboard requires additional MongoDB collections:

```javascript
// Required collections
db.createCollection("emails");
db.createCollection("detections");
db.createCollection("incidents");
db.createCollection("workflow_executions");
db.createCollection("file_analyses");

// Indexes for performance
db.emails.createIndex({"received_at": -1});
db.detections.createIndex({"created_at": -1});
db.incidents.createIndex({"created_at": -1, "status": 1});
```

## Usage Examples

### Dashboard Integration

```typescript
import SecurityDashboard from './components/SecurityDashboard';

function App() {
  return (
    <div className="App">
      <SecurityDashboard />
    </div>
  );
}
```

### Custom Analytics

```python
from app.services.analytics_service import analytics_service

# Get comprehensive metrics
metrics = await analytics_service.get_comprehensive_metrics(
    start_time=datetime.utcnow() - timedelta(days=7),
    end_time=datetime.utcnow()
)

# Get specific threat analytics
threat_data = await analytics_service.get_threat_analytics(
    start_time, end_time
)
```

### Real-time Event Handling

```python
from app.services.real_time_monitor import real_time_monitor, RealTimeEvent

# Create a security event
event = RealTimeEvent(
    event_id="custom_001",
    event_type="custom_threat",
    severity="high",
    title="Custom Security Alert",
    description="Custom threat detected",
    source="Custom Detector",
    timestamp=datetime.utcnow(),
    metadata={"custom_data": "value"}
)

# Broadcast the event
await real_time_monitor.connection_manager.broadcast_event(event)
```

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failures**
   - Check firewall settings
   - Verify WebSocket endpoint accessibility
   - Ensure proper CORS configuration

2. **Slow Dashboard Loading**
   - Check database indexes
   - Verify MongoDB connection
   - Monitor memory usage

3. **Missing Data**
   - Verify data retention settings
   - Check database connectivity
   - Ensure proper time zone handling

### Performance Optimization

1. **Database Optimization**
   ```javascript
   // Compound indexes for analytics queries
   db.detections.createIndex({"created_at": -1, "is_phishing": 1});
   db.incidents.createIndex({"status": 1, "severity": 1, "created_at": -1});
   ```

2. **Caching Strategy**
   ```python
   # Enable analytics caching
   analytics_service.cache_duration = timedelta(minutes=5)
   ```

3. **Connection Management**
   ```python
   # Limit concurrent WebSocket connections
   real_time_monitor.max_connections = 50
   ```

## Security Considerations

1. **Authentication**: Ensure proper user authentication for dashboard access
2. **Authorization**: Implement role-based access control for sensitive metrics
3. **Data Privacy**: Redact sensitive information in logs and alerts
4. **Rate Limiting**: Implement rate limiting for API endpoints
5. **HTTPS**: Use secure connections for WebSocket and API communications

## Monitoring and Alerts

### Health Checks

```http
GET /ws/stats
```

Returns connection statistics:
```json
{
  "active_connections": 5,
  "total_subscriptions": 15,
  "event_buffer_size": 100,
  "monitoring_active": true
}
```

### Log Monitoring

Monitor these log patterns:
- `Real-time monitoring started`
- `Client connected to real-time monitoring`
- `Error in real-time monitoring: {error}`
- `Analytics service error: {error}`

## Future Enhancements

1. **Advanced Filtering**: More granular alert filtering options
2. **Custom Dashboards**: User-configurable dashboard layouts
3. **Report Generation**: Automated security reports and exports
4. **Machine Learning**: Predictive analytics and anomaly detection
5. **Integration**: Third-party SIEM and security tool integration