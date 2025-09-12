"""
Scalable Message Queue System for PhishNet
Implements Redis Streams for distributed email processing with horizontal scaling
"""

import asyncio
import json
import time
import uuid
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from app.core.redis_client import get_redis_client
from app.config.logging import get_logger
from app.config.settings import settings

logger = get_logger(__name__)

class QueuePriority(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class MessageStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRY = "retry"

@dataclass
class QueueMessage:
    """Message structure for queue operations"""
    id: str
    queue_name: str
    payload: Dict[str, Any]
    priority: QueuePriority = QueuePriority.MEDIUM
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = None
    processed_at: Optional[float] = None
    status: MessageStatus = MessageStatus.PENDING
    worker_id: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()

class ScalableMessageQueue:
    """Redis Streams-based message queue for horizontal scaling"""
    
    def __init__(self, queue_name: str = "phishnet"):
        self.queue_name = queue_name
        self.redis_client = get_redis_client()
        self.consumer_group = f"{queue_name}_workers"
        self.worker_id = f"worker_{uuid.uuid4().hex[:8]}"
        self.dead_letter_queue = f"{queue_name}_dlq"
        
        # Queue configurations
        self.max_len = 10000  # Maximum queue length
        self.retry_delay = 60  # Seconds before retry
        self.processing_timeout = 300  # 5 minutes
        
    async def initialize(self):
        """Initialize queue infrastructure"""
        try:
            redis = await self.redis_client.async_client
            
            # Create consumer group if it doesn't exist
            try:
                await redis.xgroup_create(
                    self.queue_name, 
                    self.consumer_group, 
                    id='0', 
                    mkstream=True
                )
                logger.info(f"Created consumer group: {self.consumer_group}")
            except Exception as e:
                if "BUSYGROUP" not in str(e):
                    logger.error(f"Failed to create consumer group: {e}")
                    raise
                
            # Create dead letter queue
            try:
                await redis.xgroup_create(
                    self.dead_letter_queue,
                    f"{self.consumer_group}_dlq",
                    id='0',
                    mkstream=True
                )
            except Exception as e:
                if "BUSYGROUP" not in str(e):
                    logger.error(f"Failed to create DLQ: {e}")
                    
            logger.info(f"Message queue {self.queue_name} initialized for worker {self.worker_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize message queue: {e}")
            raise
    
    async def enqueue(self, message: QueueMessage) -> str:
        """Add message to queue with priority handling"""
        try:
            redis = await self.redis_client.async_client
            
            # Serialize message
            message_data = {
                'id': message.id,
                'payload': json.dumps(message.payload),
                'priority': message.priority.value,
                'retry_count': str(message.retry_count),
                'max_retries': str(message.max_retries),
                'created_at': str(message.created_at),
                'status': message.status.value
            }
            
            # Add to appropriate priority stream
            stream_name = f"{self.queue_name}:{message.priority.value}"
            
            message_id = await redis.xadd(
                stream_name,
                message_data,
                maxlen=self.max_len,
                approximate=True
            )
            
            # Update metrics
            await self._update_queue_metrics("enqueued", message.priority.value)
            
            logger.info(f"Message enqueued", message_id=message_id, queue=stream_name)
            return message_id
            
        except Exception as e:
            logger.error(f"Failed to enqueue message: {e}")
            raise
    
    async def dequeue(self, count: int = 1, block_ms: int = 1000) -> List[QueueMessage]:
        """Dequeue messages with priority handling"""
        try:
            redis = await self.redis_client.async_client
            
            # Read from high priority first, then medium, then low
            priority_streams = [
                f"{self.queue_name}:high",
                f"{self.queue_name}:medium", 
                f"{self.queue_name}:low"
            ]
            
            messages = []
            
            for stream in priority_streams:
                try:
                    # Ensure consumer group exists for this stream
                    try:
                        await redis.xgroup_create(stream, self.consumer_group, id='0', mkstream=True)
                    except Exception:
                        pass  # Group already exists
                    
                    # Read messages from stream
                    stream_messages = await redis.xreadgroup(
                        self.consumer_group,
                        self.worker_id,
                        {stream: '>'},
                        count=count,
                        block=block_ms if not messages else 0  # Don't block if we have messages
                    )
                    
                    for stream_name, stream_msgs in stream_messages:
                        for msg_id, fields in stream_msgs:
                            message = self._deserialize_message(msg_id, fields, stream_name.decode())
                            if message:
                                messages.append(message)
                                
                                # Mark as processing
                                message.status = MessageStatus.PROCESSING
                                message.worker_id = self.worker_id
                                message.processed_at = time.time()
                                
                                await self._update_message_status(message)
                    
                    if len(messages) >= count:
                        break
                        
                except Exception as e:
                    logger.warning(f"Error reading from stream {stream}: {e}")
                    continue
            
            if messages:
                await self._update_queue_metrics("dequeued", len(messages))
                logger.info(f"Dequeued {len(messages)} messages", worker=self.worker_id)
            
            return messages
            
        except Exception as e:
            logger.error(f"Failed to dequeue messages: {e}")
            return []
    
    async def acknowledge(self, message: QueueMessage, success: bool = True):
        """Acknowledge message processing completion"""
        try:
            redis = await self.redis_client.async_client
            stream_name = f"{self.queue_name}:{message.priority.value}"
            
            if success:
                # Mark as completed and acknowledge
                message.status = MessageStatus.COMPLETED
                await redis.xack(stream_name, self.consumer_group, message.id)
                await self._update_queue_metrics("completed")
                
                logger.info(f"Message acknowledged", message_id=message.id, worker=self.worker_id)
                
            else:
                # Handle failure - retry or move to DLQ
                message.retry_count += 1
                
                if message.retry_count <= message.max_retries:
                    # Schedule for retry
                    message.status = MessageStatus.RETRY
                    retry_message = QueueMessage(
                        id=f"{message.id}_retry_{message.retry_count}",
                        queue_name=message.queue_name,
                        payload=message.payload,
                        priority=message.priority,
                        retry_count=message.retry_count,
                        max_retries=message.max_retries
                    )
                    
                    # Delay retry
                    await asyncio.sleep(self.retry_delay)
                    await self.enqueue(retry_message)
                    
                    logger.info(f"Message scheduled for retry", 
                              message_id=message.id, retry_count=message.retry_count)
                else:
                    # Move to dead letter queue
                    await self._move_to_dlq(message)
                    logger.warning(f"Message moved to DLQ", message_id=message.id)
                
                # Acknowledge original message
                await redis.xack(stream_name, self.consumer_group, message.id)
                await self._update_queue_metrics("failed")
                
        except Exception as e:
            logger.error(f"Failed to acknowledge message: {e}")
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        try:
            redis = await self.redis_client.async_client
            
            stats = {
                "worker_id": self.worker_id,
                "queues": {},
                "consumer_group": self.consumer_group,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Get stats for each priority queue
            for priority in ["high", "medium", "low"]:
                stream_name = f"{self.queue_name}:{priority}"
                
                try:
                    # Get stream info
                    stream_info = await redis.xinfo_stream(stream_name)
                    
                    # Get consumer group info
                    group_info = await redis.xinfo_groups(stream_name)
                    
                    # Get pending messages
                    pending_info = await redis.xpending(stream_name, self.consumer_group)
                    
                    stats["queues"][priority] = {
                        "length": stream_info.get('length', 0),
                        "pending_messages": pending_info[0] if pending_info else 0,
                        "consumers": len(group_info) if group_info else 0,
                        "last_entry_id": stream_info.get('last-generated-id', '0-0')
                    }
                    
                except Exception as e:
                    logger.warning(f"Failed to get stats for {stream_name}: {e}")
                    stats["queues"][priority] = {"error": str(e)}
            
            # Get DLQ stats
            try:
                dlq_info = await redis.xinfo_stream(self.dead_letter_queue)
                stats["dead_letter_queue"] = {
                    "length": dlq_info.get('length', 0)
                }
            except Exception:
                stats["dead_letter_queue"] = {"length": 0}
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {"error": str(e)}
    
    def _deserialize_message(self, msg_id: str, fields: Dict, stream_name: str) -> Optional[QueueMessage]:
        """Deserialize message from Redis stream"""
        try:
            # Extract priority from stream name
            priority = stream_name.split(':')[-1]
            
            return QueueMessage(
                id=msg_id,
                queue_name=self.queue_name,
                payload=json.loads(fields[b'payload'].decode()),
                priority=QueuePriority(priority),
                retry_count=int(fields[b'retry_count'].decode()),
                max_retries=int(fields[b'max_retries'].decode()),
                created_at=float(fields[b'created_at'].decode()),
                status=MessageStatus(fields[b'status'].decode())
            )
            
        except Exception as e:
            logger.error(f"Failed to deserialize message {msg_id}: {e}")
            return None
    
    async def _update_message_status(self, message: QueueMessage):
        """Update message status in Redis"""
        try:
            redis = await self.redis_client.async_client
            status_key = f"message_status:{message.id}"
            
            await redis.hset(status_key, mapping={
                'status': message.status.value,
                'worker_id': message.worker_id or '',
                'processed_at': str(message.processed_at or ''),
                'retry_count': str(message.retry_count)
            })
            
            # Set expiration
            await redis.expire(status_key, 86400)  # 24 hours
            
        except Exception as e:
            logger.error(f"Failed to update message status: {e}")
    
    async def _move_to_dlq(self, message: QueueMessage):
        """Move failed message to dead letter queue"""
        try:
            redis = await self.redis_client.async_client
            
            dlq_data = {
                'original_id': message.id,
                'payload': json.dumps(message.payload),
                'priority': message.priority.value,
                'retry_count': str(message.retry_count),
                'failed_at': str(time.time()),
                'worker_id': message.worker_id or '',
                'reason': 'max_retries_exceeded'
            }
            
            await redis.xadd(self.dead_letter_queue, dlq_data)
            logger.warning(f"Message moved to DLQ", message_id=message.id)
            
        except Exception as e:
            logger.error(f"Failed to move message to DLQ: {e}")
    
    async def _update_queue_metrics(self, operation: str, priority: str = None):
        """Update queue metrics for monitoring"""
        try:
            redis = await self.redis_client.async_client
            
            # Update operation counters
            await redis.hincrby(f"queue_metrics:{self.queue_name}", operation, 1)
            
            if priority:
                await redis.hincrby(f"queue_metrics:{self.queue_name}:{priority}", operation, 1)
            
            # Update worker metrics
            await redis.hincrby(f"worker_metrics:{self.worker_id}", operation, 1)
            
        except Exception as e:
            logger.error(f"Failed to update queue metrics: {e}")

class EmailProcessingQueue(ScalableMessageQueue):
    """Specialized queue for email processing with auto-scaling"""
    
    def __init__(self):
        super().__init__("email_processing")
        self.processor_registry: Dict[str, Callable] = {}
    
    def register_processor(self, message_type: str, processor: Callable):
        """Register message processor for specific message types"""
        self.processor_registry[message_type] = processor
        logger.info(f"Registered processor for {message_type}")
    
    async def process_email_batch(self, emails: List[Dict[str, Any]], priority: QueuePriority = QueuePriority.MEDIUM):
        """Enqueue batch of emails for processing"""
        messages = []
        
        for email_data in emails:
            message = QueueMessage(
                id=f"email_{uuid.uuid4().hex}",
                queue_name=self.queue_name,
                payload={
                    "type": "email_analysis",
                    "email_data": email_data,
                    "timestamp": time.time()
                },
                priority=priority
            )
            messages.append(message)
        
        # Enqueue all messages
        for message in messages:
            await self.enqueue(message)
        
        logger.info(f"Enqueued {len(messages)} emails for processing")
        return [msg.id for msg in messages]
    
    async def start_worker(self):
        """Start worker loop for processing messages"""
        logger.info(f"Starting email processing worker: {self.worker_id}")
        
        while True:
            try:
                # Dequeue messages
                messages = await self.dequeue(count=5, block_ms=1000)
                
                if not messages:
                    continue
                
                # Process messages concurrently
                tasks = [self._process_message(msg) for msg in messages]
                await asyncio.gather(*tasks, return_exceptions=True)
                
            except Exception as e:
                logger.error(f"Worker error: {e}")
                await asyncio.sleep(5)  # Brief delay before retry
    
    async def _process_message(self, message: QueueMessage):
        """Process individual message"""
        try:
            message_type = message.payload.get("type")
            processor = self.processor_registry.get(message_type)
            
            if not processor:
                logger.error(f"No processor registered for {message_type}")
                await self.acknowledge(message, success=False)
                return
            
            # Process the message
            start_time = time.time()
            result = await processor(message.payload)
            processing_time = (time.time() - start_time) * 1000
            
            logger.info(f"Message processed", 
                       message_id=message.id, 
                       processing_time_ms=processing_time,
                       result=result)
            
            await self.acknowledge(message, success=True)
            
        except Exception as e:
            logger.error(f"Failed to process message {message.id}: {e}")
            await self.acknowledge(message, success=False)

# Global queue instances
email_queue = EmailProcessingQueue()

async def init_message_queues():
    """Initialize all message queues"""
    await email_queue.initialize()
    logger.info("Message queues initialized")

async def cleanup_message_queues():
    """Cleanup message queues"""
    logger.info("Message queues cleaned up")
