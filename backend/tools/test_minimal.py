import requests
import json

def test_minimal():
    url = "http://localhost:8001/"
    try:
        print(f"Checking {url}...")
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    test_minimal()
