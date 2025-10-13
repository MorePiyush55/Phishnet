# PhishNet Development Makefile
# Provides common development tasks and shortcuts

.PHONY: help setup test lint format clean run dev docs build install-dev

# Default target
help:
	@echo "PhishNet Development Commands:"
	@echo "  setup          - Setup development environment"
	@echo "  install-dev    - Install development dependencies"
	@echo "  run            - Start the application"
	@echo "  dev            - Start development server with auto-reload"
	@echo "  test           - Run all tests"
	@echo "  test-cov       - Run tests with coverage"
	@echo "  lint           - Run linting (flake8, mypy)"
	@echo "  format         - Format code (black, isort)"
	@echo "  check          - Run all quality checks"
	@echo "  clean          - Clean up temporary files"
	@echo "  migrate        - Run database migrations"
	@echo "  docs           - Generate documentation"
	@echo "  typescript     - Generate TypeScript client"
	@echo "  build          - Build Docker image"

# Setup development environment
setup:
	python -m venv phishnet_env
	@echo "Virtual environment created. Activate with:"
	@echo "  Windows: phishnet_env\\Scripts\\activate"
	@echo "  Linux/Mac: source phishnet_env/bin/activate"

# Install development dependencies
install-dev:
	pip install -r ../backend/requirements.txt
	pip install pytest pytest-cov black isort flake8 mypy

# Run the application
run:
	cd ../backend && python main.py

# Start development server
dev:
	cd ../backend && python main.py --reload

# Run all tests
test:
	cd ../backend && pytest tests/ -v

# Run tests with coverage
test-cov:
	cd ../backend && pytest tests/ --cov=app --cov-report=html --cov-report=term

# Lint code
lint:
	flake8 app/ tests/ --max-line-length=88 --ignore=E203,W503
	mypy app/ --ignore-missing-imports

# Format code
format:
	black app/ tests/ scripts/ --line-length=88
	isort app/ tests/ scripts/ --profile=black

# Run all quality checks
check: format lint test

# Clean up temporary files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/

# Run database migrations
migrate:
	cd ../backend && python -m app.core.migrations migrate

# Create new migration
migration:
	@read -p "Migration name: " name; \
	cd ../backend && python -m app.core.migrations create "$$name"

# Generate documentation
docs:
	@echo "Starting documentation server..."
	@echo "API docs available at: http://localhost:8080/api/docs"

# Generate TypeScript client
typescript:
	cd ../backend && python -m app.core.typescript_generator http://localhost:8080 ../frontend/src/api

# Build Docker image
build:
	cd ../deployment && docker build -t phishnet:latest .

# Run with Docker Compose
docker-dev:
	cd ../deployment && docker-compose up

# Run production with Docker Compose
docker-prod:
	cd ../deployment && docker-compose -f docker-compose.prod.yml up -d

# Initialize database with sample data
init-db:
	python scripts/phase1_backbone.py
	python scripts/phase2_emails_simple.py
	python scripts/phase3_links.py

# Start all services with Docker Compose
up:
	docker-compose up -d

# Stop all services
down:
	docker-compose down

# View logs
logs:
	docker-compose logs -f

# Health check
health:
	curl -f http://localhost:8080/api/v1/health || echo "Service not healthy"

# Performance test
perf:
	@echo "Running performance tests..."
	@echo "This would run locust or other performance testing tools"

# Security scan
security:
	@echo "Running security scans..."
	@echo "This would run bandit, safety, or other security tools"

# Backup database
backup:
	@echo "Creating database backup..."
	cp phishnet_dev.db "phishnet_backup_$(shell date +%Y%m%d_%H%M%S).db"

# Full development setup
dev-setup: setup install-dev init-db
	@echo "Development environment ready!"
	@echo "Run 'make run' to start the application"
