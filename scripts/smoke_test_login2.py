from fastapi.testclient import TestClient
from fastapi import FastAPI
from app.api import google_oauth

app = FastAPI()
# router already defines prefix /api/v1/auth
app.include_router(google_oauth.router)
client = TestClient(app)
resp = client.get('/api/v1/auth/login')
print('status', resp.status_code)
print('len', len(resp.text))
print(resp.text[:240])
