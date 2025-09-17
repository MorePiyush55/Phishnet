"""Minimal webhook handlers used during test collection.

Provides a simple `gmail_webhook_handler` function that tests import and
patch as needed.
"""

from fastapi import APIRouter, Request

router = APIRouter()

async def gmail_webhook_handler(request: Request):
    # Minimal placeholder for webhook processing
    return {"status": "ok"}

__all__ = ["router", "gmail_webhook_handler"]
