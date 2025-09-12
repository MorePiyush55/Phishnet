# Contributing to PhishNet

Thank you for your interest in contributing to PhishNet! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

1. **Check existing issues** first to avoid duplicates
2. **Use the issue template** when creating new issues
3. **Provide detailed information** including:
   - Steps to reproduce the problem
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Log files or error messages

### Contributing Code

1. **Fork the repository** and create a new branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Follow coding standards**:
   - Use Python 3.11+ features
   - Follow PEP 8 style guidelines
   - Add type hints to all functions
   - Write docstrings for all classes and functions

3. **Write tests** for your changes:
   - Unit tests for individual functions
   - Integration tests for API endpoints
   - Performance tests for scalability features

4. **Update documentation** as needed:
   - Update README.md if adding new features
   - Add docstrings and comments
   - Update API documentation

5. **Commit your changes** with clear messages:
   ```bash
   git commit -m "feat: add horizontal scaling feature"
   ```

6. **Push and create a Pull Request**:
   ```bash
   git push origin feature/your-feature-name
   ```

## 🏗️ Development Setup

### Prerequisites

- Python 3.11+
- PostgreSQL 13+
- Redis 6+
- Docker & Docker Compose

### Setup Steps

1. **Clone and setup environment**:
   ```bash
   git clone https://github.com/MorePiyush55/Phishnet.git
   cd Phishnet
   python -m venv phishnet_env
   source phishnet_env/bin/activate  # Linux/Mac
   # phishnet_env\Scripts\activate  # Windows
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements_enhanced.txt  # For additional features
   ```

3. **Setup environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Initialize database**:
   ```bash
   python scripts/init_db.py
   alembic upgrade head
   ```

5. **Run tests to verify setup**:
   ```bash
   pytest tests/ -v
   ```

## 📝 Coding Standards

### Python Style

- **Follow PEP 8** with 88-character line limit
- **Use type hints** for all function parameters and returns
- **Add docstrings** using Google style format
- **Use async/await** for I/O operations

### Example Function

```python
async def analyze_email(
    email_data: EmailData,
    use_cache: bool = True
) -> ThreatAnalysisResult:
    """
    Analyze an email for phishing threats.
    
    Args:
        email_data: The email data to analyze
        use_cache: Whether to use cached results
        
    Returns:
        Analysis result with threat score and details
        
    Raises:
        ValidationError: If email data is invalid
        AnalysisError: If analysis fails
    """
    # Implementation here
    pass
```

### Code Organization

```
app/
├── api/           # REST API endpoints
├── core/          # Core business logic
├── models/        # Database models
├── schemas/       # Pydantic models
├── services/      # Business services
├── config/        # Configuration
└── utils/         # Utility functions
```

## 🧪 Testing Guidelines

### Test Structure

```python
import pytest
from httpx import AsyncClient
from app.main import app

class TestEmailAnalysis:
    """Test email analysis functionality."""
    
    @pytest.mark.asyncio
    async def test_analyze_phishing_email(self):
        """Test analysis of known phishing email."""
        # Arrange
        email_data = {...}
        
        # Act
        async with AsyncClient(app=app, base_url="http://test") as ac:
            response = await ac.post("/api/v1/emails/analyze", json=email_data)
        
        # Assert
        assert response.status_code == 200
        result = response.json()
        assert result["threat_score"] > 0.8
```

### Test Categories

1. **Unit Tests** (`tests/unit/`):
   - Test individual functions
   - Mock external dependencies
   - Fast execution

2. **Integration Tests** (`tests/integration/`):
   - Test API endpoints
   - Test database interactions
   - Test service integrations

3. **Performance Tests** (`tests/performance/`):
   - Test scalability features
   - Load testing
   - Performance benchmarks

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/performance/

# Run with coverage
pytest --cov=app --cov-report=html

# Run performance tests
pytest tests/performance/ -v --tb=short
```

## 🔄 Pull Request Process

### Before Submitting

1. **Ensure tests pass**:
   ```bash
   pytest tests/ -v
   ```

2. **Check code quality**:
   ```bash
   flake8 app/
   mypy app/
   black app/ --check
   ```

3. **Update documentation**:
   - Add docstrings to new functions
   - Update README if needed
   - Add API documentation

### PR Requirements

- [ ] **Tests added/updated** for new functionality
- [ ] **Documentation updated** (README, docstrings, etc.)
- [ ] **Code follows style guidelines** (PEP 8, type hints)
- [ ] **All CI checks pass** (tests, linting, security)
- [ ] **No breaking changes** (or clearly documented)

### PR Description Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added and passing
```

## 🏷️ Issue Labels

We use the following labels to categorize issues:

- **`bug`**: Something isn't working
- **`enhancement`**: New feature or request
- **`documentation`**: Improvements or additions to documentation
- **`performance`**: Performance improvements
- **`security`**: Security-related issues
- **`scalability`**: Horizontal scaling and performance
- **`good first issue`**: Good for newcomers
- **`help wanted`**: Extra attention needed

## 🎯 Feature Priorities

### High Priority
1. **Performance Optimization**: Improving email processing speed
2. **ML Model Enhancement**: Better detection accuracy
3. **Security Hardening**: Authentication and authorization
4. **Monitoring**: Better observability and alerting

### Medium Priority
1. **UI/UX Improvements**: Dashboard enhancements
2. **API Extensions**: New endpoints and features
3. **Documentation**: Comprehensive guides and examples
4. **Integration**: Third-party service integrations

### Low Priority
1. **Code Refactoring**: Technical debt reduction
2. **Testing**: Additional test coverage
3. **Tooling**: Development experience improvements

## 📞 Getting Help

If you need help contributing:

1. **Check the documentation** in the `docs/` directory
2. **Search existing issues** for similar questions
3. **Join our discussions** in GitHub Discussions
4. **Ask questions** in new issues with the `question` label

## 🙏 Recognition

Contributors will be recognized in:
- **README.md** contributors section
- **Release notes** for significant contributions
- **GitHub contributors** page

Thank you for contributing to PhishNet! 🛡️
