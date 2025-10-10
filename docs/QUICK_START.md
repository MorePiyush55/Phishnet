# PhishNet Development Setup

## Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/your-username/phishnet.git
cd phishnet
```

### 2. Backend Setup
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn main:app --reload
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm start
```

### 4. Database Setup
```bash
# Start MongoDB (Docker)
docker run -d -p 27017:27017 mongo:latest

# Or use MongoDB Atlas (cloud)
# Update MONGODB_URL in backend/.env
```

## Environment Configuration

### Backend (.env)
```bash
MONGODB_URL=mongodb://localhost:27017/phishnet
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Frontend (.env)
```bash
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
```

## Available Scripts

### Backend
```bash
# Start development server
python -m uvicorn main:app --reload

# Run tests
pytest

# Check code quality
black .
flake8 .

# Start production server
python production_main.py
```

### Frontend
```bash
# Start development server
npm start

# Build for production
npm run build

# Run tests
npm test
```

## API Documentation

### Local Development
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Key Endpoints
- Health Check: `GET /health`
- Analytics Dashboard: `GET /api/analytics/dashboard`
- WebSocket Monitor: `ws://localhost:8000/ws/monitor`

## Testing

### Run All Tests
```bash
# Backend tests
cd backend && pytest

# Frontend tests
cd frontend && npm test
```

### Test Coverage
```bash
# Backend coverage
cd backend && pytest --cov=app

# Frontend coverage
cd frontend && npm test -- --coverage
```

## Deployment

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up --build

# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### Cloud Deployment (Render/Heroku)
1. Push to GitHub
2. Connect repository to hosting platform
3. Configure environment variables
4. Deploy!

## Troubleshooting

### Common Issues

1. **Module Import Errors**
   ```bash
   # Fix Python path
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

2. **Database Connection Issues**
   ```bash
   # Check MongoDB status
   mongosh --eval "db.adminCommand('ismaster')"
   ```

3. **Port Conflicts**
   ```bash
   # Find process using port
   netstat -ano | findstr :8000
   
   # Kill process (Windows)
   taskkill /PID <process_id> /F
   ```

## Development Guidelines

### Code Style
- Python: Black formatter, flake8 linting
- TypeScript: Prettier, ESLint
- Git: Conventional commits

### Commit Message Format
```
<type>(<scope>): <description>

feat(analytics): add real-time threat monitoring
fix(auth): resolve OAuth token refresh issue
docs(readme): update setup instructions
```

### Branch Strategy
- `main`: Production-ready code
- `develop`: Development integration
- `feature/*`: New features
- `hotfix/*`: Critical fixes

## Architecture Overview

```
PhishNet/
├── backend/           # FastAPI Python backend
│   ├── app/          # Application code
│   ├── tests/        # Test files
│   └── requirements.txt
├── frontend/         # React TypeScript frontend
│   ├── src/         # Source code
│   ├── public/      # Static assets
│   └── package.json
├── deployment/      # Docker and K8s configs
├── docs/           # Documentation
└── scripts/        # Utility scripts
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Update documentation
6. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Support

- Documentation: `/docs` folder
- Issues: GitHub Issues
- Discussions: GitHub Discussions

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.