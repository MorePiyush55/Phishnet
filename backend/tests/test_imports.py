import sys
import os

# Add the current directory to sys.path to simulate running from root
sys.path.append(os.getcwd())

print("Attempting to import app.api.v2.on_demand...")
try:
    from app.api.v2.on_demand import router
    print("SUCCESS: app.api.v2.on_demand imported.")
except Exception as e:
    print(f"FAILURE: {e}")
    import traceback
    traceback.print_exc()

print("\nAttempting to import app.services.gmail_ondemand...")
try:
    from app.services.gmail_ondemand import gmail_ondemand_service
    print("SUCCESS: app.services.gmail_ondemand imported.")
except Exception as e:
    print(f"FAILURE: {e}")
    import traceback
    traceback.print_exc()
