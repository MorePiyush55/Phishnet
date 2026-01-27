import sys
import os
import traceback

sys.path.insert(0, os.getcwd())

print("--- DIAGNOSTIC START ---")

try:
    print("1. Importing app.api.gmail_oauth...")
    import app.api.gmail_oauth
    print("   SUCCESS: Module imported.")
except ImportError:
    print("   FAILURE: ImportError")
    traceback.print_exc()
except Exception:
    print("   FAILURE: Exception during import")
    traceback.print_exc()

try:
    print("2. Checking for router object...")
    if hasattr(app.api.gmail_oauth, 'router'):
        print("   SUCCESS: router object found.")
    else:
        print("   FAILURE: router object NOT found.")
except Exception:
    print("   FAILURE: generic error accessing router")
    traceback.print_exc()

print("--- DIAGNOSTIC END ---")
