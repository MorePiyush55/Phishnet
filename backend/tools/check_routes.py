import sys
import os
sys.path.append(os.getcwd())

from app.main import app, router_errors

with open("router_errors_only.txt", "w") as f:
    f.write(str(router_errors))

print(f"Router Errors written to router_errors_only.txt")

print("Registered Routes:")
for route in app.routes:
    try:
        path = getattr(route, "path", "No Path")
        methods = getattr(route, "methods", "No Methods")
        name = getattr(route, "name", "No Name")
        print(f"Route: {path} [{methods}] ({name})")
    except Exception as e:
        print(f"Error printing route: {e}")
