import sys
import os

sys.path.append(os.getcwd())

print("Checking imports...")

modules = [
    "app.api.v2.on_demand",
    "app.api.v1.imap_emails"
]

try:
    import app.core.security
    print("Security module loaded.")
    if 'get_current_user' in dir(app.core.security):
        print("SUCCESS: get_current_user found in security module.")
    else:
        print("FAILED: get_current_user NOT found in security module.")
        print(f"Available: {dir(app.core.security)}")
except Exception as e:
    print(f"Failed to load security module: {e}")

for module in modules:
    try:
        if module.startswith("app."):
            # For app modules, we need to import them specifically to trigger their internal imports
            __import__(module, fromlist=['router'])
        else:
            __import__(module)
        print(f"SUCCESS: {module} imported.")
    except ImportError as e:
        print(f"FAILED: {module}: {e}")
    except Exception as e:
        print(f"ERROR: {module}: {e}")
