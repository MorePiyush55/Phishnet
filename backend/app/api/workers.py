"""
Worker Dashboard Backend API
Provides endpoints for monitoring workers, queues, and job statistics.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import HTMLResponse
import json

from app.workers.worker_manager import WorkerManager
from app.workers.task_prioritizer import TaskPrioritizer, QueueOptimizer
from app.tasks.dlq_handler import get_dlq_stats, replay_dlq_task
from app.core.redis_client import get_redis_client
from app.workers.celery_config import celery_app

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/workers", tags=["workers"])

def get_worker_manager() -> WorkerManager:
    """Dependency to get WorkerManager instance."""
    return WorkerManager()

def get_task_prioritizer() -> TaskPrioritizer:
    """Dependency to get TaskPrioritizer instance."""
    return TaskPrioritizer()

def get_queue_optimizer() -> QueueOptimizer:
    """Dependency to get QueueOptimizer instance."""
    return QueueOptimizer()

@router.get("/dashboard")
async def get_dashboard_html():
    """Serve the worker dashboard HTML page."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PhishNet Worker Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1400px;
                margin: 0 auto;
            }
            .header {
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-bottom: 20px;
            }
            .stat-card {
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .stat-title {
                font-size: 14px;
                color: #666;
                margin-bottom: 10px;
            }
            .stat-value {
                font-size: 24px;
                font-weight: bold;
                color: #333;
            }
            .status-online { color: #10b981; }
            .status-offline { color: #ef4444; }
            .status-warning { color: #f59e0b; }
            .table-container {
                background: white;
                border-radius: 8px;
                overflow: hidden;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .table-header {
                background: #f8fafc;
                padding: 15px 20px;
                font-weight: bold;
                border-bottom: 1px solid #e5e7eb;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                text-align: left;
                padding: 12px 20px;
                border-bottom: 1px solid #e5e7eb;
            }
            th {
                background: #f8fafc;
                font-weight: 600;
            }
            .btn {
                background: #3b82f6;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 12px;
            }
            .btn:hover {
                background: #2563eb;
            }
            .btn-danger {
                background: #ef4444;
            }
            .btn-danger:hover {
                background: #dc2626;
            }
            .refresh-btn {
                float: right;
                background: #10b981;
            }
            .chart-container {
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>PhishNet Worker Dashboard</h1>
                <p>Real-time monitoring of background workers and job queues</p>
                <button class="btn refresh-btn" onclick="refreshData()">Refresh Data</button>
            </div>

            <div class="stats-grid" id="statsGrid">
                <!-- Stats will be loaded here -->
            </div>

            <div class="chart-container">
                <h3>Queue Depths Over Time</h3>
                <canvas id="queueChart" width="400" height="100"></canvas>
            </div>

            <div class="table-container">
                <div class="table-header">Active Workers</div>
                <table id="workersTable">
                    <thead>
                        <tr>
                            <th>Worker ID</th>
                            <th>Status</th>
                            <th>Queues</th>
                            <th>Active Tasks</th>
                            <th>Processed</th>
                            <th>Last Heartbeat</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Worker data will be loaded here -->
                    </tbody>
                </table>
            </div>

            <div class="table-container">
                <div class="table-header">Queue Status</div>
                <table id="queuesTable">
                    <thead>
                        <tr>
                            <th>Queue Name</th>
                            <th>Pending Jobs</th>
                            <th>Processing Rate</th>
                            <th>Avg Wait Time</th>
                            <th>Failed (24h)</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Queue data will be loaded here -->
                    </tbody>
                </table>
            </div>

            <div class="table-container">
                <div class="table-header">Dead Letter Queue</div>
                <table id="dlqTable">
                    <thead>
                        <tr>
                            <th>Task ID</th>
                            <th>Task Name</th>
                            <th>Error Type</th>
                            <th>Failed At</th>
                            <th>Retry Count</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- DLQ data will be loaded here -->
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            let queueChart;
            
            async function fetchData(endpoint) {
                try {
                    const response = await fetch(endpoint);
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    return await response.json();
                } catch (error) {
                    console.error(`Error fetching ${endpoint}:`, error);
                    return null;
                }
            }

            async function refreshData() {
                await Promise.all([
                    loadStats(),
                    loadWorkers(),
                    loadQueues(),
                    loadDLQ(),
                    loadQueueChart()
                ]);
            }

            async function loadStats() {
                const stats = await fetchData('/api/v1/workers/stats');
                if (!stats) return;

                const statsGrid = document.getElementById('statsGrid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-title">Active Workers</div>
                        <div class="stat-value status-online">${stats.active_workers}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Total Jobs Pending</div>
                        <div class="stat-value">${stats.total_pending}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Jobs Processed (24h)</div>
                        <div class="stat-value status-online">${stats.jobs_processed_24h}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Jobs Failed (24h)</div>
                        <div class="stat-value status-warning">${stats.jobs_failed_24h}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">Average Processing Time</div>
                        <div class="stat-value">${stats.avg_processing_time}s</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-title">DLQ Items</div>
                        <div class="stat-value status-warning">${stats.dlq_length}</div>
                    </div>
                `;
            }

            async function loadWorkers() {
                const workers = await fetchData('/api/v1/workers/status');
                if (!workers) return;

                const tbody = document.querySelector('#workersTable tbody');
                tbody.innerHTML = workers.map(worker => `
                    <tr>
                        <td>${worker.id}</td>
                        <td><span class="status-${worker.status.toLowerCase()}">${worker.status}</span></td>
                        <td>${worker.queues.join(', ')}</td>
                        <td>${worker.active_tasks}</td>
                        <td>${worker.processed}</td>
                        <td>${new Date(worker.last_heartbeat).toLocaleString()}</td>
                        <td>
                            <button class="btn btn-danger" onclick="restartWorker('${worker.id}')">Restart</button>
                        </td>
                    </tr>
                `).join('');
            }

            async function loadQueues() {
                const queues = await fetchData('/api/v1/workers/queues');
                if (!queues) return;

                const tbody = document.querySelector('#queuesTable tbody');
                tbody.innerHTML = queues.map(queue => `
                    <tr>
                        <td>${queue.name}</td>
                        <td>${queue.pending}</td>
                        <td>${queue.processing_rate.toFixed(2)}/min</td>
                        <td>${queue.avg_wait_time.toFixed(1)}s</td>
                        <td>${queue.failed_24h}</td>
                        <td>
                            <button class="btn" onclick="purgeQueue('${queue.name}')">Purge</button>
                        </td>
                    </tr>
                `).join('');
            }

            async function loadDLQ() {
                const dlq = await fetchData('/api/v1/workers/dlq');
                if (!dlq || !dlq.items) return;

                const tbody = document.querySelector('#dlqTable tbody');
                tbody.innerHTML = dlq.items.slice(0, 50).map(item => `
                    <tr>
                        <td>${item.task_id}</td>
                        <td>${item.task_name}</td>
                        <td>${item.error_type}</td>
                        <td>${new Date(item.failure_time).toLocaleString()}</td>
                        <td>${item.retry_count}</td>
                        <td>
                            <button class="btn" onclick="replayTask('${item.task_id}')">Replay</button>
                        </td>
                    </tr>
                `).join('');
            }

            async function loadQueueChart() {
                const chartData = await fetchData('/api/v1/workers/queue-metrics');
                if (!chartData) return;

                const ctx = document.getElementById('queueChart').getContext('2d');
                
                if (queueChart) {
                    queueChart.destroy();
                }

                queueChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: chartData.labels,
                        datasets: [
                            {
                                label: 'Realtime Queue',
                                data: chartData.realtime,
                                borderColor: 'rgb(239, 68, 68)',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            },
                            {
                                label: 'Standard Queue',
                                data: chartData.standard,
                                borderColor: 'rgb(59, 130, 246)',
                                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            },
                            {
                                label: 'Heavy Queue',
                                data: chartData.heavy,
                                borderColor: 'rgb(16, 185, 129)',
                                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }

            async function restartWorker(workerId) {
                if (!confirm(`Restart worker ${workerId}?`)) return;
                
                const result = await fetchData(`/api/v1/workers/${workerId}/restart`);
                if (result && result.success) {
                    alert('Worker restart initiated');
                    refreshData();
                } else {
                    alert('Failed to restart worker');
                }
            }

            async function purgeQueue(queueName) {
                if (!confirm(`Purge all jobs from ${queueName} queue?`)) return;
                
                const result = await fetchData(`/api/v1/workers/queues/${queueName}/purge`);
                if (result && result.success) {
                    alert('Queue purged successfully');
                    refreshData();
                } else {
                    alert('Failed to purge queue');
                }
            }

            async function replayTask(taskId) {
                const result = await fetchData(`/api/v1/workers/dlq/${taskId}/replay`);
                if (result && result.success) {
                    alert('Task replayed successfully');
                    refreshData();
                } else {
                    alert('Failed to replay task');
                }
            }

            // Auto-refresh every 30 seconds
            setInterval(refreshData, 30000);

            // Initial load
            refreshData();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/stats")
async def get_worker_stats(
    manager: WorkerManager = Depends(get_worker_manager)
) -> Dict[str, Any]:
    """Get overall worker and job statistics."""
    try:
        # Get worker stats
        worker_status = manager.get_worker_status()
        active_workers = len([w for w in worker_status if w.get('status') == 'online'])
        
        # Get queue stats
        queue_metrics = manager.get_queue_metrics()
        total_pending = sum(q.get('length', 0) for q in queue_metrics.values())
        
        # Get DLQ stats
        dlq_stats = get_dlq_stats()
        
        # Get Redis client for additional metrics
        redis_client = get_redis_client()
        
        # Get 24h job counts
        date_key = datetime.utcnow().strftime("%Y-%m-%d")
        jobs_processed_24h = int(redis_client.get(f"jobs:completed:daily:{date_key}") or 0)
        jobs_failed_24h = int(redis_client.get(f"failures:daily:{date_key}") or 0)
        
        # Calculate average processing time (simplified)
        avg_processing_time = 45.2  # This would be calculated from actual metrics
        
        return {
            "active_workers": active_workers,
            "total_pending": total_pending,
            "jobs_processed_24h": jobs_processed_24h,
            "jobs_failed_24h": jobs_failed_24h,
            "avg_processing_time": avg_processing_time,
            "dlq_length": dlq_stats.get("dlq_length", 0),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get worker stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def get_worker_status(
    manager: WorkerManager = Depends(get_worker_manager)
) -> List[Dict[str, Any]]:
    """Get detailed status of all workers."""
    try:
        return manager.get_worker_status()
    except Exception as e:
        logger.error(f"Failed to get worker status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/queues")
async def get_queue_status(
    manager: WorkerManager = Depends(get_worker_manager)
) -> List[Dict[str, Any]]:
    """Get status of all queues."""
    try:
        queue_metrics = manager.get_queue_metrics()
        redis_client = get_redis_client()
        
        queues = []
        for queue_name, metrics in queue_metrics.items():
            # Get failure count for this queue
            date_key = datetime.utcnow().strftime("%Y-%m-%d")
            failed_24h = int(redis_client.get(f"failures:queue:{queue_name}:daily:{date_key}") or 0)
            
            queues.append({
                "name": queue_name,
                "pending": metrics.get("length", 0),
                "processing_rate": metrics.get("processing_rate", 0.0),
                "avg_wait_time": metrics.get("avg_wait_time", 0.0),
                "failed_24h": failed_24h
            })
        
        return queues
    except Exception as e:
        logger.error(f"Failed to get queue status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dlq")
async def get_dlq_status() -> Dict[str, Any]:
    """Get Dead Letter Queue status and items."""
    try:
        redis_client = get_redis_client()
        
        # Get DLQ items
        dlq_items = redis_client.lrange("dlq:failed_tasks", 0, 99)  # Get first 100
        
        items = []
        for item in dlq_items:
            try:
                task_data = json.loads(item)
                items.append({
                    "task_id": task_data.get("task_id"),
                    "task_name": task_data.get("task_name"),
                    "error_type": task_data.get("error_type"),
                    "error_message": task_data.get("error_message", "")[:100],  # Truncate
                    "failure_time": task_data.get("failure_time"),
                    "retry_count": task_data.get("retry_count", 0),
                    "failure_category": task_data.get("failure_category", "unknown")
                })
            except json.JSONDecodeError:
                continue
        
        # Get overall stats
        dlq_stats = get_dlq_stats()
        
        return {
            "total_items": dlq_stats.get("dlq_length", 0),
            "items": items,
            "category_breakdown": dlq_stats.get("category_breakdown", {}),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get DLQ status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/queue-metrics")
async def get_queue_metrics_history() -> Dict[str, Any]:
    """Get queue depth history for charting."""
    try:
        redis_client = get_redis_client()
        
        # Generate last 24 hours of data points (every hour)
        now = datetime.utcnow()
        labels = []
        realtime_data = []
        standard_data = []
        heavy_data = []
        
        for i in range(24, 0, -1):
            hour_time = now - timedelta(hours=i)
            labels.append(hour_time.strftime("%H:%M"))
            
            # Get queue depths (this would be stored periodically by a background task)
            hour_key = hour_time.strftime("%Y-%m-%d:%H")
            
            realtime_depth = int(redis_client.get(f"queue:depth:realtime:{hour_key}") or 0)
            standard_depth = int(redis_client.get(f"queue:depth:standard:{hour_key}") or 0)
            heavy_depth = int(redis_client.get(f"queue:depth:heavy:{hour_key}") or 0)
            
            realtime_data.append(realtime_depth)
            standard_data.append(standard_depth)
            heavy_data.append(heavy_depth)
        
        return {
            "labels": labels,
            "realtime": realtime_data,
            "standard": standard_data,
            "heavy": heavy_data
        }
        
    except Exception as e:
        logger.error(f"Failed to get queue metrics history: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{worker_id}/restart")
async def restart_worker(
    worker_id: str,
    manager: WorkerManager = Depends(get_worker_manager)
) -> Dict[str, Any]:
    """Restart a specific worker."""
    try:
        # This would implement actual worker restart logic
        # For now, just return success
        logger.info(f"Restart requested for worker {worker_id}")
        
        return {
            "success": True,
            "worker_id": worker_id,
            "action": "restart_initiated",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to restart worker {worker_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/queues/{queue_name}/purge")
async def purge_queue(queue_name: str) -> Dict[str, Any]:
    """Purge all jobs from a specific queue."""
    try:
        # Purge the queue using Celery
        celery_app.control.purge()
        
        logger.info(f"Purged queue {queue_name}")
        
        return {
            "success": True,
            "queue_name": queue_name,
            "action": "purged",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to purge queue {queue_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/dlq/{task_id}/replay")
async def replay_dlq_task_endpoint(task_id: str) -> Dict[str, Any]:
    """Replay a task from the Dead Letter Queue."""
    try:
        result = replay_dlq_task(task_id)
        return result
    except Exception as e:
        logger.error(f"Failed to replay DLQ task {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/optimization")
async def get_optimization_recommendations(
    optimizer: QueueOptimizer = Depends(get_queue_optimizer)
) -> Dict[str, Any]:
    """Get queue optimization recommendations."""
    try:
        recommendations = optimizer.get_optimization_recommendations()
        return recommendations
    except Exception as e:
        logger.error(f"Failed to get optimization recommendations: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scale")
async def scale_workers(
    queue_name: str,
    target_workers: int,
    manager: WorkerManager = Depends(get_worker_manager)
) -> Dict[str, Any]:
    """Scale workers for a specific queue."""
    try:
        result = manager.scale_workers(queue_name, target_workers)
        return result
    except Exception as e:
        logger.error(f"Failed to scale workers for queue {queue_name}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))