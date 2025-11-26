import sys
import os
import traceback

sys.path.append(os.getcwd())

try:
    print("Importing app.api.v2.on_demand...")
    import app.api.v2.on_demand
    print("SUCCESS")
except Exception:
    print("FAILED")
    traceback.print_exc()
