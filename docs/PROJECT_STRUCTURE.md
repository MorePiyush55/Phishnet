# PhishNet Project Structure

## Overview
This document describes the organized project structure after reorganization on October 13, 2025.

## Root Directory Structure

```
Phishnet/
├── .github/                    # GitHub workflows and configuration
├── .venv/                      # Python virtual environment (local dev only)
├── backend/                    # Backend API and services
├── docs/                       # Project documentation
├── frontend/                   # React frontend application
├── .gitignore                  # Git ignore rules
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # Project license
├── PROJECT_STRUCTURE.md        # This file
└── README.md                   # Main project readme
```

## Backend Structure

```
backend/
├── app/                                    # Main application code
│   ├── api/                               # API endpoints and routes
│   ├── core/                              # Core functionality and config
│   ├── integrations/                      # External integrations
│   │   └── playbooks/                     # Phantom playbook integration
│   │       ├── source_playbooks/          # Original Phantom playbook files (*.py, *.json)
│   │       ├── rules/                     # Parsed playbook rules (JSON)
│   │       ├── playbook_adapter.py        # AST parser for playbooks
│   │       ├── playbook_engine.py         # Playbook execution engine
│   │       ├── batch_processor.py         # Batch API call processor
│   │       ├── cache_extensions.py        # Enhanced caching layer
│   │       ├── performance_metrics.py     # Performance monitoring
│   │       ├── demo_integration.py        # Demo script
│   │       └── README.md                  # Integration documentation
│   ├── models/                            # Database models
│   ├── schemas/                           # Pydantic schemas
│   ├── services/                          # Business logic services
│   └── utils/                             # Utility functions
│
├── deployment/                            # Deployment configurations
│   ├── docker/                            # Docker configurations
│   ├── helm/                              # Kubernetes Helm charts
│   ├── k8s/                               # Kubernetes manifests
│   ├── monitoring/                        # Monitoring configs (Prometheus, Grafana)
│   ├── docker-compose.yml                 # Local development compose
│   ├── docker-compose.prod.yml            # Production compose
│   ├── Dockerfile                         # Main Dockerfile
│   └── README.md                          # Deployment guide
│
├── scripts/                               # Utility scripts
│   └── analyze_playbooks.py               # Standalone playbook analyzer
│
├── tests/                                 # Test files
│   ├── integration/                       # Integration tests
│   ├── unit/                              # Unit tests
│   └── conftest.py                        # Pytest configuration
│
├── testsprite_tests/                      # TestSprite automated tests
│   └── tmp/                               # Temporary test files
│
├── tools/                                 # Development tools
│   ├── scripts/                           # Helper scripts
│   ├── Makefile                           # Build automation
│   └── verify_structure.py                # Structure validation
│
├── alembic/                               # Database migrations
├── src/                                   # Additional source code
├── main.py                                # FastAPI application entry point
├── requirements.txt                       # Python dependencies
├── requirements-production.txt            # Production dependencies
├── pyproject.toml                         # Python project configuration
├── pytest.ini                             # Pytest configuration
└── README.md                              # Backend documentation
```

## Frontend Structure

```
frontend/
├── public/                     # Static assets
├── src/                        # Source code
│   ├── components/            # React components
│   ├── pages/                 # Page components
│   ├── services/              # API services
│   ├── hooks/                 # Custom React hooks
│   ├── store/                 # State management (Zustand)
│   ├── utils/                 # Utility functions
│   ├── types/                 # TypeScript types
│   ├── App.tsx                # Main App component
│   └── main.tsx               # Entry point
│
├── package.json               # Node.js dependencies
├── tsconfig.json              # TypeScript configuration
├── vite.config.ts             # Vite build configuration
├── tailwind.config.js         # Tailwind CSS configuration
└── README.md                  # Frontend documentation
```

## Documentation Structure

```
docs/
├── ANALYTICS_DASHBOARD.md              # Analytics dashboard guide
├── APP_BRANDING_GUIDE.md               # Branding guidelines
├── BACKEND_OAUTH_SPECIFICATION.md      # OAuth backend spec
├── DEPLOYMENT_GUIDE.md                 # Deployment instructions
├── GMAIL_OAUTH_IMPLEMENTATION_COMPLETE.md  # Gmail OAuth guide
├── IMPLEMENTATION_SUMMARY.md           # Project implementation summary
├── MONGODB_INTEGRATION_SUMMARY.md      # MongoDB integration
├── OAUTH_QUICK_START.md                # OAuth quick start
├── PLAYBOOK_INTEGRATION_IMPROVEMENTS.md # Playbook integration details
├── PRIORITY_3_OAUTH_SECURITY_COMPLETE.md # OAuth security
└── [additional documentation files...]
```

## Key Changes Made

### 1. **Moved to Backend**
- `testsprite_tests/` → `backend/testsprite_tests/`
- `tools/` → `backend/tools/`
- `deployment/` → `backend/deployment/`
- `analyze_playbooks.py` → `backend/scripts/analyze_playbooks.py`

### 2. **Moved to Docs**
- `IMPLEMENTATION_SUMMARY.md` → `docs/IMPLEMENTATION_SUMMARY.md`

### 3. **Integrated into Backend**
- `Phishing Playbook/` → `backend/app/integrations/playbooks/source_playbooks/`
- `Phishing Playbook and app/` → Merged Python/JSON files to `source_playbooks/`, deleted archives

### 4. **Deleted/Removed**
- Archive files (*.tgz) from "Phishing Playbook and app" folder
- Original "Phishing Playbook" and "Phishing Playbook and app" directories

### 5. **Updated File References**
Updated these files to reference new paths:
- `backend/scripts/analyze_playbooks.py`
- `backend/app/integrations/playbooks/playbook_adapter.py`
- `backend/app/integrations/playbooks/demo_integration.py`

## Clean Root Directory

The root directory now contains only:
- `.github/` - GitHub configuration
- `.pytest_cache/` - Pytest cache (git-ignored)
- `.venv/` - Virtual environment (git-ignored)
- `backend/` - Backend application
- `docs/` - Documentation
- `frontend/` - Frontend application
- Configuration files (.gitignore, LICENSE, README.md, CONTRIBUTING.md)

## Running the Project

### Backend
```bash
cd backend
pip install -r requirements.txt
python main.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Analyze Playbooks
```bash
cd backend
python scripts/analyze_playbooks.py
```

### Run Tests
```bash
cd backend
pytest
```

## Benefits of This Structure

1. **Clear Separation**: Frontend, Backend, and Docs are cleanly separated
2. **Backend Organization**: All backend-related tools, tests, and deployments are in one place
3. **Easy Navigation**: Developers can quickly find what they need
4. **Standard Structure**: Follows industry best practices for monorepo organization
5. **Scalability**: Easy to add new modules or services
6. **CI/CD Friendly**: Clear paths for automated builds and deployments

## Notes

- The `source_playbooks/` directory contains the original Phantom playbook files for reference and parsing
- Parsed playbook rules are stored in JSON format in the `rules/` directory
- All path references in code have been updated to reflect the new structure
- The project maintains backwards compatibility with existing functionality
