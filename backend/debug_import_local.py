import sys
import os
import traceback

# Add project root to path
sys.path.insert(0, os.getcwd())

try:
    print("Attempting to import app.api.gmail_oauth...")
    import app.api.gmail_oauth
    print("SUCCESS: app.api.gmail_oauth imported successfully")
except Exception as e:
    print(f"FAILURE: {e}")
    traceback.print_exc()

try:
    print("\nAttempting to import app.services.gmail_oauth...")
    import app.services.gmail_oauth
    print("SUCCESS: app.services.gmail_oauth imported successfully")
except Exception as e:
    print(f"FAILURE: {e}")
    traceback.print_exc()
