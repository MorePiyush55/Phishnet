import requests

try:
    response = requests.get('http://127.0.0.1:8001/api/test/oauth/callback?code=test_code', allow_redirects=False)
    print(f'Status: {response.status_code}')
    print(f'Location: {response.headers.get("Location", "Not found")}')
except Exception as e:
    print(f'Error: {e}')