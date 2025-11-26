import sys
import os
import traceback
sys.path.append(os.getcwd())

try:
    print("Attempting to import app.api.v1.imap_emails...")
    import app.api.v1.imap_emails
    print("SUCCESS: app.api.v1.imap_emails imported.")
except Exception:
    print("FAILED to import app.api.v1.imap_emails.")
    traceback.print_exc()
