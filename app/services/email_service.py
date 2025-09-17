"""Minimal Gmail email fetching service.
This service uses HTTP calls to Gmail APIs with an OAuth2 access token.

Note: In production, prefer using the official google-api-python-client for robust handling.
"""
from typing import List, Dict, Any, Optional
import httpx
import logging
import asyncio

logger = logging.getLogger(__name__)

GMAIL_API_BASE = 'https://gmail.googleapis.com/gmail/v1'


async def _request_with_retries(method: str, url: str, headers: Dict[str, str], params: Dict[str, Any] = None, retries: int = 3, backoff: float = 0.5):
    attempt = 0
    while True:
        try:
            async with httpx.AsyncClient() as client:
                if method.lower() == 'get':
                    resp = await client.get(url, headers=headers, params=params)
                else:
                    resp = await client.request(method, url, headers=headers, params=params)

            if resp.status_code >= 500 and attempt < retries:
                # retry on server errors
                attempt += 1
                await asyncio.sleep(backoff * (2 ** (attempt - 1)))
                continue

            return resp
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            attempt += 1
            if attempt > retries:
                logger.error(f"HTTP request failed after {retries} attempts: {e}")
                raise
            await asyncio.sleep(backoff * (2 ** (attempt - 1)))


async def list_messages(access_token: str, user_id: str = 'me', q: Optional[str] = None, page_token: Optional[str] = None, max_results: int = 100) -> Dict[str, Any]:
    """List message ids for a user. Returns the raw Gmail API response (messages + nextPageToken).

    Args:
        access_token: OAuth2 access token with gmail.readonly scope
        user_id: 'me' or user email
        q: optional query string (Gmail search query)
        page_token: optional page token for pagination
        max_results: number of messages to request (max 500)
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"maxResults": max_results}
    if q:
        params['q'] = q
    if page_token:
        params['pageToken'] = page_token

    url = f"{GMAIL_API_BASE}/users/{user_id}/messages"
    resp = await _request_with_retries('get', url, headers, params=params)
    if resp.status_code != 200:
        logger.error(f"Failed list messages: {resp.status_code} {resp.text}")
        raise Exception('Failed to list messages')
    return resp.json()

async def get_message(access_token: str, message_id: str, user_id: str = 'me', format: str = 'full') -> Dict[str, Any]:
    """Get a single message by id. Format 'minimal','full','raw' or 'metadata'."""
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{GMAIL_API_BASE}/users/{user_id}/messages/{message_id}"
    resp = await _request_with_retries('get', url, headers, params={"format": format})
    if resp.status_code != 200:
        logger.error(f"Failed get message: {resp.status_code} {resp.text}")
        raise Exception('Failed to get message')
    return resp.json()

async def fetch_and_parse_messages(access_token: str, max_messages: int = 50) -> List[Dict[str, Any]]:
    """Convenience function to list recent messages and fetch their full content.

    Note: This is basic and should be adapted for rate limits and pagination.
    """
    results = []
    try:
        listed = await list_messages(access_token, max_results=max_messages)
        messages = listed.get('messages', [])
        for m in messages:
            msg = await get_message(access_token, m['id'], format='full')
            # Basic parse: headers and snippet
            parsed = {
                'id': msg.get('id'),
                'threadId': msg.get('threadId'),
                'snippet': msg.get('snippet'),
                'headers': {h['name']: h['value'] for h in msg.get('payload', {}).get('headers', [])}
            }
            results.append(parsed)
        return results
    except Exception as e:
        logger.error(f"Failed fetch_and_parse_messages: {e}")
        raise
