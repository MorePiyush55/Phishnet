# Ensure the repository root is on sys.path so tests can import the `app` package
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    # Insert at front so local packages shadow any installed packages
    sys.path.insert(0, str(ROOT))

# Remove potential duplicate package paths (e.g., backend/app) that can cause
# SQLAlchemy table re-definition when tests import both `app` and `backend.app`.
for p in list(sys.path):
    try:
        if str(Path(p).resolve()).endswith(str(Path('backend').resolve())):
            sys.path.remove(p)
    except Exception:
        continue
