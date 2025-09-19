import os

# Set temporary test env vars so the router uses a predictable client id
os.environ['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID', 'test-client-id-123')
os.environ['GOOGLE_REDIRECT_URI'] = os.environ.get('GOOGLE_REDIRECT_URI', 'https://your-vercel-app.vercel.app/auth/callback')

from fastapi import FastAPI
from fastapi.testclient import TestClient
from app.api import google_oauth

app = FastAPI()
app.include_router(google_oauth.router)
client = TestClient(app)

# Request the login page
resp_login = client.get('/api/v1/auth/login')
print('login status', resp_login.status_code)
print('login length', len(resp_login.text))
print('contains config injection:', '__PHISHNET_CONFIG__' in resp_login.text)

# Initiate OAuth but do not follow the redirect; inspect Location header
resp_init = client.get('/api/v1/auth/google', follow_redirects=False)
print('init status', resp_init.status_code)
location = resp_init.headers.get('location')
print('redirect location exists:', bool(location))
if location:
	print('location contains client_id:', 'client_id=test-client-id-123' in location)
	print('location contains redirect_uri:', 'redirect_uri=' in location)
	print('location (truncated):', location[:240])
