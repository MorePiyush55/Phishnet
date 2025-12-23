import requests
import sys

BASE_URL = "https://phishnet-backend-iuoc.onrender.com"

def test_endpoint():
    print(f"Testing connection to {BASE_URL}...")
    
    # 1. Test Health Check
    try:
        resp = requests.get(f"{BASE_URL}/health")
        print(f"\n[Health Check] Status: {resp.status_code}")
        print(f"[Health Check] Response: {resp.text}")
    except Exception as e:
        print(f"\n[Health Check] Failed: {e}")

    # 2. Test Root
    try:
        resp = requests.get(f"{BASE_URL}/")
        print(f"\n[Root] Status: {resp.status_code}")
        print(f"[Root] Response: {resp.text}")
    except Exception as e:
        print(f"\n[Root] Failed: {e}")

    # 3. Test API Endpoint (Method Not Allowed is expected if it exists but we use GET)
    # We use GET here just to see if the route exists (405) vs not found (404)
    try:
        resp = requests.get(f"{BASE_URL}/api/v2/request-check")
        print(f"\n[API Check] Status: {resp.status_code}")
        if resp.status_code == 405:
            print("[API Check] SUCCESS: Endpoint exists (405 Method Not Allowed is expected for GET)")
        elif resp.status_code == 404:
            print("[API Check] FAILURE: Endpoint NOT FOUND (404)")
        else:
            print(f"[API Check] Response: {resp.text}")
    except Exception as e:
        print(f"\n[API Check] Failed: {e}")

if __name__ == "__main__":
    test_endpoint()
