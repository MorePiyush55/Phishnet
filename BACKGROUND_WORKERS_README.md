# PhishNet Background Workers & Queue Management

This document describes the comprehensive background processing system implemented for PhishNet, providing scalable, asynchronous email analysis with real-time monitoring and intelligent task routing.

## 🏗️ System Architecture

### Core Components

1. **Celery Task Queue System** - Distributed task processing with Redis broker
2. **Dynamic Task Prioritization** - Intelligent routing based on system load and task characteristics
3. **Dead Letter Queue (DLQ)** - Robust error handling with retry policies and failure classification
4. **Worker Dashboard** - Real-time monitoring and management interface
5. **WebSocket Updates** - Real-time job status and progress notifications
6. **Frontend Integration** - React components for job tracking and management

### Queue Structure

```
┌─────────────────┐    ┌──────────────────┐    ┌────────────────┐
│   realtime      │───▶│   standard       │───▶│     heavy      │
│   (<10s tasks)  │    │  (10-60s tasks)  │    │  (>60s tasks)  │
└─────────────────┘    └──────────────────┘    └────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────┐
│   background    │    │       dlq        │    │   monitoring   │
│  (low priority) │    │ (failed tasks)   │    │    (metrics)   │
└─────────────────┘    └──────────────────┘    └────────────────┘
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Backend dependencies
pip install celery[redis] flower redis kombu billiard

# Start Redis server
redis-server

# Start Celery workers
celery -A backend.app.workers.celery_config worker --loglevel=info

# Start Celery beat scheduler (for periodic tasks)
celery -A backend.app.workers.celery_config beat --loglevel=info

# Optional: Start Flower monitoring (Web UI)
celery -A backend.app.workers.celery_config flower
```

### 2. Start the Application

```bash
# Start the FastAPI backend
cd backend
python main.py

# Start the React frontend
cd frontend
npm run dev
```

### 3. Access the Interfaces

- **Main Application**: http://localhost:3000
- **Worker Dashboard**: http://localhost:8000/api/v1/workers/dashboard
- **API Documentation**: http://localhost:8000/docs
- **Flower Monitoring**: http://localhost:5555 (if running)

## 📋 API Endpoints

### Job Submission

```http
POST /api/v1/analysis/submit
Content-Type: application/json

{
  "subject": "Email subject",
  "sender": "sender@example.com",
  "content": "Email content...",
  "analysis_type": "quick|standard|comprehensive"
}

Response:
{
  "job_id": "uuid",
  "status": "submitted",
  "estimated_completion": "30 seconds",
  "polling_url": "/api/v1/analysis/status/{job_id}",
  "websocket_url": "/ws/jobs/{job_id}"
}
```

### Bulk Job Submission

```http
POST /api/v1/analysis/submit-bulk
Content-Type: application/json

{
  "emails": [...],
  "analysis_type": "quick|standard|comprehensive",
  "priority": "low|normal|high|urgent"
}

Response:
{
  "batch_id": "uuid",
  "job_ids": ["uuid1", "uuid2", ...],
  "total_jobs": 100
}
```

### Job Status

```http
GET /api/v1/analysis/status/{job_id}

Response:
{
  "job_id": "uuid",
  "status": "pending|processing|completed|failed",
  "progress": 75,
  "result": {...},
  "processing_time": 45.2
}
```

### Worker Management

```http
GET /api/v1/workers/stats          # System statistics
GET /api/v1/workers/status         # Worker status
GET /api/v1/workers/queues         # Queue status
GET /api/v1/workers/dlq            # Dead Letter Queue status
POST /api/v1/workers/scale         # Scale workers
```

## 🔌 WebSocket Integration

### Job Status Updates

```javascript
// Connect to job-specific WebSocket
const ws = new WebSocket(`ws://localhost:8000/ws/jobs/${jobId}`);

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  
  switch (update.type) {
    case 'progress_update':
      console.log(`Job ${update.job_id}: ${update.progress}%`);
      break;
    case 'job_completed':
      console.log('Job completed:', update.result);
      break;
    case 'job_failed':
      console.log('Job failed:', update.error);
      break;
  }
};

// Send ping to keep connection alive
ws.send(JSON.stringify({ type: 'ping' }));
```

### System Status Updates

```javascript
// Connect to system-wide WebSocket
const systemWs = new WebSocket('ws://localhost:8000/ws/system');

systemWs.onmessage = (event) => {
  const update = JSON.parse(event.data);
  
  if (update.type === 'system_status') {
    console.log('System stats:', update.data);
  }
};
```

## 📊 Task Types & Queues

### Analysis Types

| Type | Queue | Duration | Use Case |
|------|--------|----------|----------|
| `quick` | realtime | <10s | Basic threat detection, header analysis |
| `standard` | standard | 30-60s | Full email scan, ML analysis |
| `comprehensive` | heavy | 2-5min | Deep analysis, sandbox, threat intelligence |

### Background Tasks

| Task | Queue | Description |
|------|--------|-------------|
| `quick_email_scan` | realtime | Fast header and content analysis |
| `full_email_scan` | standard | Complete email security scan |
| `sandbox_analysis` | heavy | Attachment sandboxing |
| `link_safety_check` | realtime | URL safety verification |
| `deep_attachment_scan` | heavy | Comprehensive attachment analysis |
| `ml_threat_detection` | standard | Machine learning threat analysis |
| `threat_intelligence_lookup` | standard | External threat feed queries |

## 🛠️ Configuration

### Celery Configuration

```python
# backend/app/workers/celery_config.py

CELERY_CONFIG = {
    'broker_url': 'redis://localhost:6379/1',
    'result_backend': 'redis://localhost:6379/2',
    'task_serializer': 'json',
    'accept_content': ['json'],
    'result_serializer': 'json',
    'timezone': 'UTC',
    'enable_utc': True,
    'task_track_started': True,
    'task_time_limit': 600,  # 10 minutes
    'worker_prefetch_multiplier': 1,
    'task_acks_late': True,
    'worker_disable_rate_limits': False
}
```

### Queue Routing

```python
TASK_ROUTES = {
    'backend.app.tasks.scan_tasks.quick_email_scan': {'queue': 'realtime'},
    'backend.app.tasks.scan_tasks.full_email_scan': {'queue': 'standard'},
    'backend.app.tasks.scan_tasks.sandbox_analysis': {'queue': 'heavy'},
    # ... more routes
}
```

### Retry Policies

```python
RETRY_POLICIES = {
    'temporary_failures': {
        'max_retries': 3,
        'countdown': 60,  # 1 minute
        'backoff': True
    },
    'permanent_failures': {
        'max_retries': 0  # No retry
    }
}
```

## 📈 Monitoring & Metrics

### Dashboard Features

- **Real-time Statistics**: Active workers, pending jobs, completion rates
- **Queue Monitoring**: Depth, processing rates, wait times
- **Worker Health**: Status, heartbeat, active tasks
- **DLQ Management**: Failed jobs, retry options, error classification
- **Performance Charts**: Queue depths over time, throughput metrics

### Key Metrics

```python
# System metrics available via API
{
  "active_workers": 5,
  "total_pending": 150,
  "jobs_processed_24h": 5420,
  "jobs_failed_24h": 23,
  "avg_processing_time": 34.7,
  "success_rate": 99.6,
  "queue_depths": {
    "realtime": 5,
    "standard": 45,
    "heavy": 8
  }
}
```

## 🧪 Testing & Validation

### Quick Validation

```bash
# Run basic functionality tests
python scripts/test_workers.py

# Test with custom base URL
python scripts/test_workers.py --base-url http://production-server.com
```

### Scalability Testing

```bash
# Run comprehensive scalability tests
python -m pytest backend/tests/test_scalability.py

# Test with 1000 jobs
python backend/tests/test_scalability.py --jobs 1000 --output results.json
```

### Test Coverage

- ✅ Bulk job submission (1000+ jobs)
- ✅ Queue performance under load
- ✅ Worker auto-scaling
- ✅ Error handling and DLQ functionality
- ✅ WebSocket connection management
- ✅ System resource limits

## 🔧 Frontend Integration

### React Components

```typescript
import { JobManagementDashboard } from '@/components/job-management-dashboard';
import { JobTracker } from '@/components/job-progress';
import { useJobWebSocket } from '@/hooks/useJobWebSocket';

// Full dashboard
<JobManagementDashboard apiBaseUrl="/api/v1" />

// Individual job tracker
<JobTracker 
  jobs={jobs}
  onRefresh={refreshJobs}
  onCancelJob={cancelJob}
  onViewResult={viewResult}
/>
```

### WebSocket Hook

```typescript
const { isConnected, lastUpdate } = useJobWebSocket({
  url: 'ws://localhost:8000/ws',
  jobId: 'job-uuid',
  onUpdate: (update) => {
    console.log('Job update:', update);
  }
});
```

## 🚨 Error Handling

### DLQ Categories

| Category | Description | Retry Policy |
|----------|-------------|--------------|
| `temporary` | Network/timeout errors | Exponential backoff |
| `permanent` | Invalid input/validation | No retry |
| `resource` | Memory/disk issues | Linear backoff |
| `external` | External service failures | Exponential backoff |
| `infrastructure` | Database/Redis issues | Exponential backoff |

### Error Recovery

```python
# Replay failed jobs from DLQ
POST /api/v1/workers/dlq/{task_id}/replay

# Bulk DLQ operations
GET /api/v1/workers/dlq  # List failed jobs
POST /api/v1/workers/dlq/replay-all  # Replay all
DELETE /api/v1/workers/dlq/clear  # Clear DLQ
```

## 🔄 Auto-scaling

### Scaling Triggers

- Queue depth thresholds
- Worker utilization rates
- System resource usage
- Processing time metrics

### Configuration

```python
SCALING_CONFIG = {
    'min_workers': 2,
    'max_workers': 20,
    'scale_up_threshold': 10,  # Queue depth
    'scale_down_threshold': 2,
    'cooldown_period': 300  # 5 minutes
}
```

## 🛡️ Security Considerations

- **Input Validation**: All email content is sanitized
- **Rate Limiting**: Per-user job submission limits
- **Authentication**: JWT-based API access
- **Network Security**: Redis and worker communications secured
- **Resource Limits**: Memory and CPU constraints per task

## 🚀 Deployment

### Production Setup

```bash
# Use multiple worker processes
celery -A backend.app.workers.celery_config worker --concurrency=4 --loglevel=info

# Run workers on different queues
celery -A backend.app.workers.celery_config worker --queues=realtime --concurrency=2
celery -A backend.app.workers.celery_config worker --queues=standard --concurrency=3
celery -A backend.app.workers.celery_config worker --queues=heavy --concurrency=1

# Production Redis configuration
redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

### Docker Deployment

```dockerfile
# Worker service
FROM python:3.11
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["celery", "-A", "backend.app.workers.celery_config", "worker"]
```

### Environment Variables

```bash
# Redis configuration
REDIS_URL=redis://redis-server:6379/0
CELERY_BROKER_URL=redis://redis-server:6379/1
CELERY_RESULT_BACKEND=redis://redis-server:6379/2

# Worker scaling
CELERY_WORKER_CONCURRENCY=4
CELERY_MAX_WORKERS=20

# Monitoring
FLOWER_PORT=5555
ENABLE_WORKER_DASHBOARD=true
```

## 📚 Additional Resources

- [Celery Documentation](https://docs.celeryproject.org/)
- [Redis Documentation](https://redis.io/documentation)
- [FastAPI WebSockets](https://fastapi.tiangolo.com/advanced/websockets/)
- [React Hooks Guide](https://reactjs.org/docs/hooks-intro.html)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Built with ❤️ by the PhishNet Team**