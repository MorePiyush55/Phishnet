
import sys
import os

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI
from app.main import app

def check_route(path_prefix):
    found = False
    for route in app.routes:
        if getattr(route, "path", "").startswith(path_prefix):
            found = True
            print(f"[OK] Found route: {route.path}")
            break
    
    if not found:
        print(f"[FAIL] Route {path_prefix} not found!")
        return False
    return True

print("Checking router verification...")
ok1 = check_route("/api/v1/analytics")
ok2 = check_route("/api/v1/feedback")

if ok1 and ok2:
    print("\nSUCCESS: Both routers wired successfully!")
    sys.exit(0)
else:
    print("\nFAILURE: One or more routers missing.")
    sys.exit(1)
