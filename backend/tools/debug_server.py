import requests
import json

def debug_server():
    base_url = "http://localhost:8000"
    
    # Check Health
    try:
        resp = requests.get(f"{base_url}/health")
        print(f"Health Check: {resp.status_code}")
        print(resp.text)
    except Exception as e:
        print(f"Health Check Failed: {e}")

    # Check OpenAPI
    try:
        resp = requests.get(f"{base_url}/openapi.json")
        print(f"OpenAPI Check: {resp.status_code}")
        if resp.status_code == 200:
            schema = resp.json()
            paths = schema.get("paths", {}).keys()
            print("Available Paths:")
            for p in paths:
                if "request-check" in p:
                    print(f"  FOUND: {p}")
                else:
                    # print(f"  {p}") # Commented out to avoid spam
                    pass
    except Exception as e:
        print(f"OpenAPI Check Failed: {e}")

if __name__ == "__main__":
    debug_server()
