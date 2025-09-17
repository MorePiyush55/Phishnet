"""Compatibility shim for Gemini integration used in tests.
Provides minimal client and adapter classes.
"""
from typing import Any

class GeminiClient:
    def __init__(self, api_key: str = ""):
        self.api_key = api_key

    async def generate(self, prompt: str) -> str:
        return ""

class GeminiAdapter:
    def __init__(self, client: GeminiClient):
        self.client = client

    async def call(self, prompt: str) -> str:
        return ""
