import requests
import json

def check_health_8002():
    url = "http://localhost:8002/health"
    try:
        print(f"Checking {url}...")
        response = requests.get(url)
        print(f"Status Code: {response.status_code}")
        try:
            data = response.json()
            print("Response JSON:")
            print(json.dumps(data, indent=2))
        except ValueError:
            print("Response is NOT JSON.")
            print(f"Response Text Prefix: {response.text[:200]}")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    check_health_8002()
