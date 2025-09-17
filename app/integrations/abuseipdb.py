"""Shim for AbuseIPDB integration required by tests."""

class AbuseIPDBClient:
    def lookup(self, ip: str) -> dict:
        return {"ip": ip, "abuse_score": 0.0}

class AbuseIPDBAdapter:
    def __init__(self, client: AbuseIPDBClient):
        self.client = client

    def get_reputation(self, ip: str) -> dict:
        return self.client.lookup(ip)

__all__ = ["AbuseIPDBClient", "AbuseIPDBAdapter"]
