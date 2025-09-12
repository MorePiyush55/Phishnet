"""Gmail Pub/Sub webhook server for real-time email notifications."""

import base64
import json
import hashlib
import hmac
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.responses import JSONResponse
import asyncio
import uvicorn

from app.config.settings import settings
from app.config.logging import get_logger
from app.services.gmail_secure import gmail_service
from app.core.redis_client import redis_client

logger = get_logger(__name__)

# Create webhook app
webhook_app = FastAPI(
    title="PhishNet Gmail Webhook",
    description="Handles Gmail push notifications via Google Pub/Sub",
    version="1.0.0"
)


def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str
) -> bool:
    """Verify webhook signature for security."""
    try:
        expected_signature = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(f"sha256={expected_signature}", signature)
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


@webhook_app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all webhook requests for security monitoring."""
    start_time = datetime.utcnow()
    
    # Get client IP
    client_ip = request.client.host
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # Log request
    logger.info(f"Webhook request from {client_ip}: {request.method} {request.url}")
    
    # Process request
    response = await call_next(request)
    
    # Log response
    duration = (datetime.utcnow() - start_time).total_seconds()
    logger.info(f"Webhook response {response.status_code} in {duration:.3f}s")
    
    return response


@webhook_app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "gmail-webhook", "timestamp": datetime.utcnow().isoformat()}


@webhook_app.post("/webhook/gmail/pubsub")
async def handle_pubsub_notification(
    request: Request,
    x_goog_channel_id: Optional[str] = Header(None),
    x_goog_channel_token: Optional[str] = Header(None),
    x_goog_resource_state: Optional[str] = Header(None),
    x_goog_message_number: Optional[str] = Header(None)
):
    """Handle Gmail Pub/Sub push notification."""
    try:
        # Get request body
        body = await request.body()
        
        # Verify webhook signature if configured
        if settings.WEBHOOK_SECRET:
            signature = request.headers.get("X-Hub-Signature-256", "")
            if not verify_webhook_signature(body, signature, settings.WEBHOOK_SECRET):
                logger.error("Invalid webhook signature")
                raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse Pub/Sub message
        try:
            pubsub_message = json.loads(body.decode())
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in webhook payload: {e}")
            raise HTTPException(status_code=400, detail="Invalid JSON")
        
        # Extract message data
        message = pubsub_message.get("message", {})
        if not message:
            logger.error("No message in Pub/Sub payload")
            raise HTTPException(status_code=400, detail="No message in payload")
        
        # Decode and process Gmail notification
        if "data" in message:
            try:
                # Decode base64 data
                decoded_data = base64.b64decode(message["data"]).decode('utf-8')
                gmail_notification = json.loads(decoded_data)
            except Exception as e:
                logger.error(f"Failed to decode Gmail notification data: {e}")
                raise HTTPException(status_code=400, detail="Invalid message data")
        else:
            gmail_notification = message
        
        # Log notification details
        email_address = gmail_notification.get("emailAddress")
        history_id = gmail_notification.get("historyId")
        
        logger.info(f"Received Gmail notification for {email_address}, history_id: {history_id}")
        
        # Rate limiting check
        rate_limit_key = f"webhook_rate_limit:{email_address}"
        current_count = await redis_client.incr(rate_limit_key)
        if current_count == 1:
            await redis_client.expire(rate_limit_key, 60)  # 1 minute window
        
        if current_count > 100:  # Max 100 notifications per minute per user
            logger.warning(f"Rate limit exceeded for {email_address}")
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded"}
            )
        
        # Queue notification for processing
        notification_id = f"notification_{email_address}_{history_id}_{int(datetime.utcnow().timestamp())}"
        
        notification_job = {
            "id": notification_id,
            "email_address": email_address,
            "history_id": history_id,
            "timestamp": datetime.utcnow().isoformat(),
            "headers": {
                "channel_id": x_goog_channel_id,
                "channel_token": x_goog_channel_token,
                "resource_state": x_goog_resource_state,
                "message_number": x_goog_message_number
            }
        }
        
        # Add to high-priority queue for immediate processing
        await redis_client.lpush("gmail_notifications_queue", json.dumps(notification_job))
        
        # Also add to processing queue for the Gmail service
        asyncio.create_task(process_notification_async(gmail_notification))
        
        logger.info(f"Queued Gmail notification {notification_id}")
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "notification_id": notification_id,
                "processed_at": datetime.utcnow().isoformat()
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def process_notification_async(gmail_notification: dict):
    """Process Gmail notification asynchronously."""
    try:
        await gmail_service.process_pubsub_notification(gmail_notification)
    except Exception as e:
        logger.error(f"Async notification processing failed: {e}")


@webhook_app.post("/webhook/gmail/watch")
async def handle_gmail_watch_notification(
    request: Request
):
    """Handle direct Gmail watch notifications (alternative to Pub/Sub)."""
    try:
        # Get headers
        channel_id = request.headers.get("X-Goog-Channel-ID")
        channel_token = request.headers.get("X-Goog-Channel-Token")
        resource_state = request.headers.get("X-Goog-Resource-State")
        resource_id = request.headers.get("X-Goog-Resource-ID")
        resource_uri = request.headers.get("X-Goog-Resource-URI")
        message_number = request.headers.get("X-Goog-Message-Number")
        
        logger.info(f"Gmail watch notification: {resource_state} for resource {resource_id}")
        
        # Handle different resource states
        if resource_state == "sync":
            # Initial sync message - acknowledge
            return JSONResponse(status_code=200, content={"status": "sync_acknowledged"})
        
        elif resource_state == "exists":
            # New message exists - process
            # Extract user info from channel_token if available
            if channel_token:
                try:
                    user_data = json.loads(base64.b64decode(channel_token.encode()).decode())
                    user_id = user_data.get("user_id")
                    
                    if user_id:
                        # Create synthetic notification for processing
                        notification = {
                            "emailAddress": user_data.get("email_address"),
                            "historyId": message_number  # Use message number as history ID approximation
                        }
                        
                        await gmail_service.process_pubsub_notification(notification)
                        
                        return JSONResponse(
                            status_code=200,
                            content={"status": "processed", "user_id": user_id}
                        )
                        
                except Exception as e:
                    logger.error(f"Failed to process channel token: {e}")
        
        return JSONResponse(status_code=200, content={"status": "acknowledged"})
        
    except Exception as e:
        logger.error(f"Gmail watch notification processing failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@webhook_app.get("/metrics")
async def get_webhook_metrics():
    """Get webhook processing metrics."""
    try:
        # Get queue lengths
        email_queue_length = await redis_client.llen("email_processing_queue")
        notification_queue_length = await redis_client.llen("gmail_notifications_queue")
        
        # Get processing stats from Redis
        stats_key = "webhook_stats"
        stats = await redis_client.hgetall(stats_key)
        
        return {
            "queues": {
                "email_processing": email_queue_length,
                "gmail_notifications": notification_queue_length
            },
            "stats": {
                "total_notifications": int(stats.get(b"total_notifications", 0)),
                "successful_processes": int(stats.get(b"successful_processes", 0)),
                "failed_processes": int(stats.get(b"failed_processes", 0)),
                "rate_limited": int(stats.get(b"rate_limited", 0))
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get metrics")


async def update_webhook_stats(stat_name: str, increment: int = 1):
    """Update webhook statistics in Redis."""
    try:
        await redis_client.hincrby("webhook_stats", stat_name, increment)
    except Exception as e:
        logger.error(f"Failed to update stat {stat_name}: {e}")


# Add middleware to track stats
@webhook_app.middleware("http")
async def track_webhook_stats(request: Request, call_next):
    """Track webhook statistics."""
    if request.url.path.startswith("/webhook/"):
        await update_webhook_stats("total_notifications")
    
    response = await call_next(request)
    
    if request.url.path.startswith("/webhook/") and response.status_code == 200:
        await update_webhook_stats("successful_processes")
    elif request.url.path.startswith("/webhook/") and response.status_code >= 400:
        await update_webhook_stats("failed_processes")
    
    return response


if __name__ == "__main__":
    """Run webhook server directly."""
    uvicorn.run(
        "app.services.webhook_server:webhook_app",
        host="0.0.0.0",
        port=8001,
        reload=settings.ENVIRONMENT == "development",
        log_level="info"
    )
