from fastapi.testclient import TestClient
from fastapi import FastAPI
from app.api.google_oauth import router

app = FastAPI()
app.include_router(router, prefix="/api/v1/auth")
client = TestClient(app)
resp = client.get('/api/v1/auth/login')
print('status', resp.status_code)
print('len', len(resp.text))
print(resp.text[:240])
