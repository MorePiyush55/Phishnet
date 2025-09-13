# PhishNet - Deployment Ready Project Structure

This project is structured for optimal deployment with:
- **Frontend** → Vercel (React/Next.js)
- **Backend** → Render (FastAPI/Python)
- **Database** → Render PostgreSQL or external service

## 📁 Project Structure

```
phishnet-project/
│
├── frontend/                    # 🌐 Vercel Deployment
│   ├── public/                  # Static assets
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── pages/              # Route pages
│   │   ├── services/           # API client services
│   │   ├── hooks/              # Custom React hooks
│   │   ├── utils/              # Helper functions
│   │   └── types/              # TypeScript definitions
│   ├── package.json
│   ├── vite.config.ts          # Build configuration
│   ├── vercel.json             # Vercel deployment config
│   ├── .env.example            # Environment variables template
│   └── .env.local              # Local development vars
│
├── backend/                     # 🚀 Render Deployment
│   ├── app/
│   │   ├── api/                # API route handlers
│   │   ├── core/               # Core configuration
│   │   ├── db/                 # Database connections
│   │   ├── models/             # Database models
│   │   ├── schemas/            # Pydantic schemas
│   │   ├── services/           # Business logic
│   │   ├── workers/            # Background tasks
│   │   ├── ml/                 # ML/AI components
│   │   └── main.py             # FastAPI application
│   ├── alembic/                # Database migrations
│   ├── tests/                  # Backend tests
│   ├── requirements.txt        # Python dependencies
│   ├── Procfile               # Render process definition
│   ├── render.yaml            # Render deployment config
│   ├── .env.example           # Environment template
│   └── pyproject.toml         # Python project config
│
├── shared/                      # 🔄 Shared Resources
│   ├── docs/                   # Project documentation
│   ├── scripts/                # Deployment/utility scripts
│   └── configs/                # Shared configurations
│
├── .github/                     # 🔄 CI/CD Workflows
│   └── workflows/
│       ├── deploy-frontend.yml
│       └── deploy-backend.yml
│
├── README.md                    # Project overview
├── .gitignore                  # Git ignore rules
└── LICENSE                     # Project license
```

## 🔗 Architecture Flow

### Frontend (Vercel)
1. **User Interface** - React components for auth, dashboard, results
2. **API Client** - Services to communicate with backend
3. **Authentication** - OAuth flow management (frontend part)
4. **Real-time Updates** - WebSocket/SSE connections

### Backend (Render)
1. **API Endpoints** - RESTful APIs for frontend
2. **OAuth Handler** - Complete Google OAuth implementation
3. **Email Analysis** - Phishing detection engine
4. **Database** - User data, scan results, audit logs
5. **Background Workers** - Async email processing

### Data Flow
```
Frontend (Vercel) → API Calls → Backend (Render) → Gmail API
                              ↓
                         Database (PostgreSQL)
                              ↓
                         Background Processing
                              ↓
                         WebSocket Updates → Frontend
```

## 🚀 Deployment Process

### Frontend Deployment (Vercel)
1. Connect GitHub repo to Vercel
2. Set root directory to `frontend/`
3. Configure environment variables
4. Automatic deployment on git push

### Backend Deployment (Render)
1. Connect GitHub repo to Render
2. Set root directory to `backend/`
3. Configure environment variables
4. Automatic deployment on git push

## 🔧 Environment Variables

### Frontend (.env.local)
```bash
VITE_API_BASE_URL=https://your-backend.onrender.com
VITE_WS_BASE_URL=wss://your-backend.onrender.com
VITE_GOOGLE_CLIENT_ID=your-google-client-id
```

### Backend (.env)
```bash
DATABASE_URL=postgresql://user:password@host:port/db
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
JWT_SECRET=your-jwt-secret
REDIS_URL=redis://user:password@host:port
```

## 📊 Benefits of This Structure

1. **Clean Separation** - Frontend and backend are completely independent
2. **Scalable** - Each service can scale independently
3. **Secure** - Secrets only in backend, no client-side exposure
4. **Maintainable** - Clear boundaries and responsibilities
5. **CI/CD Ready** - Separate deployment pipelines