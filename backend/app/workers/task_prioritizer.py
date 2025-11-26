"""
Task Prioritization and Queue Management
Implements dynamic task routing, priority assignment, and queue optimization.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass
from app.workers.celery_config import celery_app
from app.core.redis_client import get_redis_client

logger = logging.getLogger(__name__)

class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = 10    # Real-time user-facing tasks
    HIGH = 7         # Important but not immediate
    NORMAL = 5       # Standard processing
    LOW = 3          # Background tasks
    BULK = 1         # Bulk processing tasks

class QueueType(Enum):
    """Queue types with processing characteristics."""
    REALTIME = "realtime"      # <10s processing time
    STANDARD = "standard"      # 10-60s processing time
    HEAVY = "heavy"           # >60s processing time
    BACKGROUND = "background"  # Low priority tasks
    DLQ = "dlq"               # Dead letter queue

@dataclass
class TaskClassification:
    """Task classification with routing information."""
    queue: QueueType
    priority: TaskPriority
    estimated_duration: int  # seconds
    max_retries: int
    retry_delay: int
    timeout: int
    rate_limit: Optional[str] = None

class TaskPrioritizer:
    """Manages task prioritization and queue routing."""
    
    def __init__(self):
        self.redis_client = get_redis_client()
        self.task_classifications = self._define_task_classifications()
        
    def _define_task_classifications(self) -> Dict[str, TaskClassification]:
        """Define task classifications and routing rules."""
        return {
            # Real-time tasks (highest priority, fastest processing)
            "backend.app.tasks.scan_tasks.quick_email_scan": TaskClassification(
                queue=QueueType.REALTIME,
                priority=TaskPriority.CRITICAL,
                estimated_duration=5,
                max_retries=2,
                retry_delay=10,
                timeout=15,
                rate_limit="50/m"
            ),
            
            "backend.app.tasks.scan_tasks.link_safety_check": TaskClassification(
                queue=QueueType.REALTIME,
                priority=TaskPriority.HIGH,
                estimated_duration=3,
                max_retries=2,
                retry_delay=5,
                timeout=10,
                rate_limit="100/m"
            ),
            
            "backend.app.tasks.analysis_tasks.basic_threat_analysis": TaskClassification(
                queue=QueueType.REALTIME,
                priority=TaskPriority.HIGH,
                estimated_duration=8,
                max_retries=2,
                retry_delay=15,
                timeout=20
            ),
            
            # Standard processing tasks
            "backend.app.tasks.scan_tasks.full_email_scan": TaskClassification(
                queue=QueueType.STANDARD,
                priority=TaskPriority.NORMAL,
                estimated_duration=30,
                max_retries=3,
                retry_delay=60,
                timeout=120
            ),
            
            "backend.app.tasks.analysis_tasks.ml_threat_detection": TaskClassification(
                queue=QueueType.STANDARD,
                priority=TaskPriority.NORMAL,
                estimated_duration=25,
                max_retries=3,
                retry_delay=45,
                timeout=90
            ),
            
            "backend.app.tasks.analysis_tasks.reputation_lookup": TaskClassification(
                queue=QueueType.STANDARD,
                priority=TaskPriority.NORMAL,
                estimated_duration=20,
                max_retries=3,
                retry_delay=30,
                timeout=60,
                rate_limit="100/m"
            ),
            
            # Heavy processing tasks
            "backend.app.tasks.scan_tasks.sandbox_analysis": TaskClassification(
                queue=QueueType.HEAVY,
                priority=TaskPriority.LOW,
                estimated_duration=180,
                max_retries=2,
                retry_delay=300,
                timeout=600,
                rate_limit="10/m"
            ),
            
            "backend.app.tasks.scan_tasks.deep_attachment_scan": TaskClassification(
                queue=QueueType.HEAVY,
                priority=TaskPriority.LOW,
                estimated_duration=120,
                max_retries=2,
                retry_delay=200,
                timeout=300
            ),
            
            "backend.app.tasks.analysis_tasks.advanced_ml_analysis": TaskClassification(
                queue=QueueType.HEAVY,
                priority=TaskPriority.LOW,
                estimated_duration=150,
                max_retries=2,
                retry_delay=240,
                timeout=400
            ),
            
            # Background tasks
            "backend.app.tasks.cleanup_tasks.*": TaskClassification(
                queue=QueueType.BACKGROUND,
                priority=TaskPriority.BULK,
                estimated_duration=60,
                max_retries=1,
                retry_delay=600,
                timeout=300
            ),
            
            "backend.app.tasks.notification_tasks.*": TaskClassification(
                queue=QueueType.BACKGROUND,
                priority=TaskPriority.BULK,
                estimated_duration=10,
                max_retries=3,
                retry_delay=120,
                timeout=60
            )
        }
    
    def classify_task(self, task_name: str, **kwargs) -> TaskClassification:
        """
        Classify a task and determine its routing.
        
        Args:
            task_name: Name of the task
            **kwargs: Task arguments for dynamic classification
            
        Returns:
            Task classification with routing information
        """
        # Direct mapping
        if task_name in self.task_classifications:
            classification = self.task_classifications[task_name]
        else:
            # Pattern matching for wildcard rules
            classification = self._match_task_pattern(task_name)
        
        # Dynamic adjustments based on system load
        return self._adjust_for_system_load(classification, task_name, **kwargs)
    
    def _match_task_pattern(self, task_name: str) -> TaskClassification:
        """Match task name against patterns."""
        for pattern, classification in self.task_classifications.items():
            if "*" in pattern:
                prefix = pattern.replace("*", "")
                if task_name.startswith(prefix):
                    return classification
        
        # Default classification for unknown tasks
        return TaskClassification(
            queue=QueueType.STANDARD,
            priority=TaskPriority.NORMAL,
            estimated_duration=30,
            max_retries=3,
            retry_delay=60,
            timeout=120
        )
    
    def _adjust_for_system_load(self, base_classification: TaskClassification, 
                               task_name: str, **kwargs) -> TaskClassification:
        """Dynamically adjust classification based on system load."""
        try:
            # Get current system metrics
            system_metrics = self._get_system_metrics()
            
            # Adjust priority based on queue depths
            adjusted_classification = base_classification
            
            # If high-priority queues are backed up, promote some tasks
            if (base_classification.queue == QueueType.STANDARD and 
                system_metrics.get("realtime_queue_depth", 0) < 10):
                
                # Check if this task can be promoted to realtime
                if base_classification.estimated_duration < 15:
                    adjusted_classification = TaskClassification(
                        queue=QueueType.REALTIME,
                        priority=TaskPriority.HIGH,
                        estimated_duration=base_classification.estimated_duration,
                        max_retries=base_classification.max_retries,
                        retry_delay=base_classification.retry_delay // 2,
                        timeout=base_classification.timeout
                    )
            
            # If heavy queues are overloaded, defer some tasks
            elif (base_classification.queue == QueueType.HEAVY and 
                  system_metrics.get("heavy_queue_depth", 0) > 100):
                
                # Move to background processing
                adjusted_classification = TaskClassification(
                    queue=QueueType.BACKGROUND,
                    priority=TaskPriority.LOW,
                    estimated_duration=base_classification.estimated_duration * 2,
                    max_retries=base_classification.max_retries,
                    retry_delay=base_classification.retry_delay * 2,
                    timeout=base_classification.timeout * 2
                )
            
            return adjusted_classification
            
        except Exception as e:
            logger.warning(f"Failed to adjust classification for {task_name}: {str(e)}")
            return base_classification
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics for dynamic routing."""
        try:
            metrics = {}
            
            # Get queue depths
            for queue_type in QueueType:
                queue_key = f"celery.{queue_type.value}"
                depth = self.redis_client.llen(queue_key)
                metrics[f"{queue_type.value}_queue_depth"] = depth
            
            # Get worker counts and load
            inspect = celery_app.control.inspect()
            stats = inspect.stats() or {}
            
            metrics.update({
                "active_workers": len(stats),
                "total_active_tasks": sum(
                    worker_stats.get("total", {}).get("celery.worker.request.process", 0)
                    for worker_stats in stats.values()
                ),
                "system_load": self._calculate_system_load(stats)
            })
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {str(e)}")
            return {}
    
    def _calculate_system_load(self, worker_stats: Dict) -> float:
        """Calculate overall system load factor."""
        if not worker_stats:
            return 0.0
        
        total_capacity = len(worker_stats) * 10  # Assume max 10 concurrent tasks per worker
        active_tasks = sum(
            worker_stats.get("total", {}).get("celery.worker.request.process", 0)
            for worker_stats in worker_stats.values()
        )
        
        return active_tasks / total_capacity if total_capacity > 0 else 0.0
    
    def get_optimal_routing(self, task_name: str, **kwargs) -> Dict[str, Any]:
        """
        Get optimal routing configuration for a task.
        
        Args:
            task_name: Task name
            **kwargs: Task arguments
            
        Returns:
            Routing configuration dictionary
        """
        classification = self.classify_task(task_name, **kwargs)
        
        return {
            "queue": classification.queue.value,
            "priority": classification.priority.value,
            "routing_key": classification.queue.value,
            "options": {
                "max_retries": classification.max_retries,
                "default_retry_delay": classification.retry_delay,
                "time_limit": classification.timeout,
                "soft_time_limit": classification.timeout * 0.8,
                "rate_limit": classification.rate_limit
            },
            "metadata": {
                "estimated_duration": classification.estimated_duration,
                "classification_time": datetime.utcnow().isoformat()
            }
        }

class QueueOptimizer:
    """Optimizes queue performance and worker allocation."""
    
    def __init__(self):
        self.redis_client = get_redis_client()
        self.prioritizer = TaskPrioritizer()
    
    def optimize_worker_allocation(self) -> Dict[str, Any]:
        """
        Optimize worker allocation based on queue depths and task priorities.
        
        Returns:
            Optimization recommendations
        """
        try:
            # Get current queue status
            queue_status = self._get_queue_status()
            
            # Analyze queue performance
            performance_metrics = self._analyze_queue_performance()
            
            # Generate recommendations
            recommendations = self._generate_allocation_recommendations(
                queue_status, performance_metrics
            )
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "queue_status": queue_status,
                "performance_metrics": performance_metrics,
                "recommendations": recommendations,
                "optimization_score": self._calculate_optimization_score(
                    queue_status, performance_metrics
                )
            }
            
        except Exception as e:
            logger.error(f"Queue optimization failed: {str(e)}")
            return {"error": str(e)}
    
    def _get_queue_status(self) -> Dict[str, Any]:
        """Get current status of all queues."""
        queue_status = {}
        
        for queue_type in QueueType:
            queue_key = f"celery.{queue_type.value}"
            depth = self.redis_client.llen(queue_key)
            
            # Get processing rate (tasks per minute)
            rate_key = f"queue_rate:{queue_type.value}"
            recent_rate = self.redis_client.get(rate_key) or 0
            
            queue_status[queue_type.value] = {
                "depth": depth,
                "processing_rate": float(recent_rate),
                "priority_level": self._get_queue_priority_level(queue_type),
                "estimated_wait_time": self._estimate_wait_time(depth, float(recent_rate))
            }
        
        return queue_status
    
    def _analyze_queue_performance(self) -> Dict[str, Any]:
        """Analyze queue performance metrics."""
        performance = {}
        
        for queue_type in QueueType:
            # Get recent performance data
            perf_key = f"queue_perf:{queue_type.value}"
            perf_data = self.redis_client.hgetall(perf_key)
            
            performance[queue_type.value] = {
                "avg_processing_time": float(perf_data.get("avg_time", 0)),
                "success_rate": float(perf_data.get("success_rate", 100)),
                "error_rate": float(perf_data.get("error_rate", 0)),
                "throughput": float(perf_data.get("throughput", 0)),
                "worker_utilization": float(perf_data.get("utilization", 0))
            }
        
        return performance
    
    def _generate_allocation_recommendations(self, queue_status: Dict, 
                                           performance_metrics: Dict) -> List[Dict[str, Any]]:
        """Generate worker allocation recommendations."""
        recommendations = []
        
        for queue_name, status in queue_status.items():
            if status["depth"] > 50 and status["processing_rate"] < 10:
                recommendations.append({
                    "type": "scale_up",
                    "queue": queue_name,
                    "current_workers": self._count_queue_workers(queue_name),
                    "recommended_workers": self._calculate_optimal_workers(status, performance_metrics.get(queue_name, {})),
                    "reason": "High queue depth with low processing rate",
                    "priority": "high"
                })
            
            elif status["depth"] < 5 and status["processing_rate"] > 20:
                recommendations.append({
                    "type": "scale_down",
                    "queue": queue_name,
                    "current_workers": self._count_queue_workers(queue_name),
                    "recommended_workers": max(1, self._count_queue_workers(queue_name) - 1),
                    "reason": "Low queue depth with high processing capacity",
                    "priority": "low"
                })
        
        return recommendations
    
    def _get_queue_priority_level(self, queue_type: QueueType) -> int:
        """Get priority level for queue type."""
        priority_map = {
            QueueType.REALTIME: 10,
            QueueType.STANDARD: 5,
            QueueType.HEAVY: 3,
            QueueType.BACKGROUND: 1,
            QueueType.DLQ: 0
        }
        return priority_map.get(queue_type, 0)
    
    def _estimate_wait_time(self, queue_depth: int, processing_rate: float) -> float:
        """Estimate wait time based on queue depth and processing rate."""
        if processing_rate <= 0:
            return float('inf')
        return queue_depth / processing_rate * 60  # Convert to seconds
    
    def _count_queue_workers(self, queue_name: str) -> int:
        """Count workers assigned to a specific queue."""
        try:
            inspect = celery_app.control.inspect()
            active_queues = inspect.active_queues() or {}
            
            worker_count = 0
            for worker, queues in active_queues.items():
                if any(q.get("name") == queue_name for q in queues):
                    worker_count += 1
            
            return worker_count
        except Exception:
            return 0
    
    def _calculate_optimal_workers(self, queue_status: Dict, performance_metrics: Dict) -> int:
        """Calculate optimal number of workers for a queue."""
        depth = queue_status["depth"]
        current_rate = queue_status["processing_rate"]
        avg_processing_time = performance_metrics.get("avg_processing_time", 30)
        
        # Target: process queue within 5 minutes
        target_time = 300  # seconds
        required_rate = depth / target_time * 60  # tasks per minute
        
        # Calculate workers needed (assuming each worker processes 2 tasks/minute on average)
        worker_capacity = 60 / avg_processing_time
        optimal_workers = max(1, int(required_rate / worker_capacity))
        
        # Cap at reasonable limits
        return min(optimal_workers, 20)
    
    def _calculate_optimization_score(self, queue_status: Dict, performance_metrics: Dict) -> float:
        """Calculate overall queue optimization score (0-100)."""
        scores = []
        
        for queue_name, status in queue_status.items():
            # Queue health score based on depth and processing rate
            depth_score = max(0, 100 - status["depth"])  # Lower depth is better
            rate_score = min(100, status["processing_rate"] * 5)  # Higher rate is better
            
            # Performance score
            perf = performance_metrics.get(queue_name, {})
            perf_score = perf.get("success_rate", 100) - perf.get("error_rate", 0)
            
            queue_score = (depth_score + rate_score + perf_score) / 3
            scores.append(queue_score)
        
        return sum(scores) / len(scores) if scores else 0

# Singleton instances
task_prioritizer = TaskPrioritizer()
queue_optimizer = QueueOptimizer()

def get_task_prioritizer() -> TaskPrioritizer:
    """Get the task prioritizer instance."""
    return task_prioritizer

def get_queue_optimizer() -> QueueOptimizer:
    """Get the queue optimizer instance."""
    return queue_optimizer