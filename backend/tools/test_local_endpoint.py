import requests
import json
import sys

def test_on_demand_check():
    url = "http://localhost:8002/api/v2/request-check"
    
    # Test case 1: Request without token (should return need_oauth=True)
    payload_no_token = {
        "message_id": "12345",
        "user_id": "test_user_local",
        "store_consent": False
    }
    
    print(f"Testing {url} with no token...")
    try:
        response = requests.post(url, json=payload_no_token)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        data = response.json()
        if data.get("need_oauth") is True:
            print("SUCCESS: Correctly identified need for OAuth.")
        else:
            print("WARNING: Did not return need_oauth=True as expected (unless mocked).")

    except Exception as e:
        print(f"FAILED: {e}")
        if 'response' in locals():
            print(f"Response Text: {response.text}")

if __name__ == "__main__":
    test_on_demand_check()
