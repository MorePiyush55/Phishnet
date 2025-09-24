# PhishNet Project Structure

This document outlines the reorganized project structure for PhishNet, with clear separation between frontend and backend components.

## 📁 Project Organization

```
Phishnet/
├── backend/                    # 🐍 Python Backend (FastAPI)
│   ├── app/                   # Main application code
│   │   ├── api/              # API routes and endpoints
│   │   ├── auth/             # Authentication & authorization
│   │   ├── analyzers/        # Email analysis modules
│   │   ├── config/           # Configuration management
│   │   ├── core/             # Core utilities and services
│   │   ├── db/               # Database models and connections
│   │   ├── health/           # Health check endpoints
│   │   ├── integrations/     # External service integrations
│   │   ├── middleware/       # FastAPI middleware
│   │   ├── ml/               # Machine learning models
│   │   ├── models/           # SQLAlchemy models
│   │   ├── observability/    # Monitoring and logging
│   │   ├── orchestrator/     # Task orchestration
│   │   ├── repositories/     # Data access layer
│   │   ├── resilience/       # Circuit breakers, retries
│   │   ├── schemas/          # Pydantic schemas
│   │   ├── services/         # Business logic services
│   │   ├── templates/        # Email templates
│   │   ├── workers/          # Background workers
│   │   └── main.py           # FastAPI application entry
│   ├── tests/                # Backend tests
│   ├── alembic/              # Database migrations
│   ├── src/                  # Additional source code (CLI tools)
│   ├── .env                  # Environment variables
│   ├── requirements.txt      # Python dependencies
│   ├── pyproject.toml        # Python project configuration
│   ├── pytest.ini           # Pytest configuration
│   ├── alembic.ini           # Alembic configuration
│   ├── render.yaml           # Render deployment config
│   └── main.py               # Backend server entry point
│
├── frontend/                  # ⚛️ React Frontend (Vite)
│   ├── src/                  # Source code
│   ├── components/           # React components
│   ├── pages/                # Page components
│   ├── hooks/                # Custom React hooks
│   ├── context/              # React context providers
│   ├── utils/                # Utility functions
│   ├── public/               # Static assets
│   ├── static/               # Additional static files
│   ├── package.json          # Node.js dependencies
│   ├── vite.config.ts        # Vite configuration
│   ├── tsconfig.json         # TypeScript configuration
│   ├── tailwind.config.js    # Tailwind CSS configuration
│   └── vercel.json           # Vercel deployment config
│
├── deployment/               # 🚀 Deployment & Infrastructure
│   ├── docker-compose.yml    # Development container setup
│   ├── docker-compose.prod.yml # Production container setup
│   ├── Dockerfile            # Application container build
│   ├── .dockerignore         # Docker ignore rules
│   ├── k8s/                  # Kubernetes manifests
│   ├── helm/                 # Helm charts
│   ├── monitoring/           # Monitoring configurations
│   └── docker/               # Specialized Docker configs
│
├── tools/                    # �️ Development Tools & Utilities
│   ├── scripts/              # Utility scripts
│   ├── Makefile              # Development commands
│   └── verify_structure.py   # Project structure validation
│
├── docs/                     # 📚 Documentation
├── .github/                  # 🤖 GitHub workflows
├── README.md                 # � Project overview
├── PROJECT_STRUCTURE.md      # 📋 This file
├── CONTRIBUTING.md           # 🤝 Contribution guidelines
├── LICENSE                   # ⚖️ License information
└── .gitignore                # � Git ignore rules
```

## 🚀 Getting Started

### Backend Development
```bash
# Navigate to backend directory
cd backend/

# Install dependencies
pip install -r requirements.txt

# Run the backend server
python main.py
```

### Frontend Development
```bash
# Navigate to frontend directory
cd frontend/

# Install dependencies
npm install

# Run the development server
npm run dev
```

### Full Stack Development
```bash
# Run both frontend and backend with Docker
cd deployment/
docker-compose up

# Or use the Makefile from tools
cd tools/
make docker-dev
```

## 🔧 Development Commands

### Backend
- `cd backend && python main.py` - Start backend server
- `cd backend && pytest` - Run backend tests
- `cd backend && alembic upgrade head` - Run database migrations

### Frontend
- `cd frontend && npm run dev` - Start development server
- `cd frontend && npm run build` - Build for production
- `cd frontend && npm run test` - Run frontend tests

### Deployment
- `cd deployment && docker-compose up` - Start all services
- `cd deployment && docker-compose up backend` - Start only backend
- `cd deployment && docker-compose up frontend` - Start only frontend

### Tools & Utilities
- `cd tools && make dev` - Start development server via Makefile
- `cd tools && python verify_structure.py` - Verify project structure
- `cd tools && make test` - Run all tests

## 📋 Key Changes Made

### Latest Cleanup (Optimized Structure):
1. **Removed Development Artifacts**: Cleaned up `__pycache__`, `.pytest_cache`, `.coverage`, and virtual environments
2. **Eliminated Duplicates**: Removed duplicate Vercel configs, environment files, and Node.js configurations
3. **Consolidated Infrastructure**: Removed redundant infrastructure directories and sandbox duplicates
4. **Streamlined Backend**: Removed minimal app version, kept main and enhanced versions
5. **Cleaned Scripts**: Removed duplicate smoke test and development scripts
6. **Enhanced .gitignore**: Added comprehensive rules to prevent future clutter

### Initial Reorganization:
1. **Backend Consolidation**: All Python/FastAPI code moved to `backend/` directory
2. **Frontend Organization**: All React/Vite code remains in `frontend/` directory  
3. **Configuration Updates**: Updated Docker, Makefile, and config files to reference new paths
4. **Clear Separation**: Each part of the stack has its own isolated directory structure

## 🔍 Migration Notes

- Database files moved to `backend/` directory
- Root `app/` directory merged into `backend/app/`
- All Python dependencies consolidated in `backend/requirements.txt`
- Docker configurations updated to use new path structure
- Makefile commands updated to work with new directory layout

This structure provides clear separation of concerns, making the project easier to navigate, develop, and deploy.