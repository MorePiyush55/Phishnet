# Configuration Validator & Health Check System

## Overview

This document covers the implementation of **Task 9 (Configuration Validator)** and **Task 10 (Health Check System)**, which complete the PhishNet architectural restructuring for single source of truth pipeline architecture.

## Task 9: Configuration Validator ✅

### Implementation

**Location**: `src/common/config_validator.py`

### Features

1. **Comprehensive Validation**
   - Application configuration (name, version, URLs)
   - Security settings (secret keys, tokens, algorithms)  
   - Database configuration (URL format, pool settings)
   - External service URLs (Redis, Celery)
   - API key validation (format and presence)
   - Analysis configuration (limits, timeouts, ML settings)
   - Performance settings (rate limiting, processing limits)
   - Network configuration (CORS, ports)
   - File path validation (models, logs, directories)
   - Environment-specific checks (production vs development)

2. **Error Classification**
   - **Errors** 🔴: Critical issues that prevent startup
   - **Warnings** 🟡: Potential issues or suboptimal configurations
   - **Info** 🔵: Informational messages and recommendations

3. **Smart Validation Logic**
   ```python
   # Example validations
   - Secret key strength and default value detection
   - Token expiration reasonableness checks  
   - Database URL format validation
   - API key format validation (e.g., VirusTotal 64-char requirement)
   - Production vs development environment checks
   - Resource limit reasonableness (memory, timeouts, etc.)
   ```

### CLI Integration

```bash
# Validate configuration
python phishnet-cli.py config

# Example output:
❌ Configuration validation failed!

🔴 Errors (1):
  • SECRET_KEY appears to be a default or weak value - change in production

🟡 Warnings (4):
  • DEBUG mode is enabled - ensure this is not production
  • Missing API keys (set MOCK_EXTERNAL_APIS=true for development): GEMINI_API_KEY
  • PROMETHEUS_PORT and METRICS_PORT are the same
  • Log directory 'logs' does not exist

🔵 Info (1):
  • MODEL_PATH 'models/' does not exist - will be created if needed
```

### Startup Integration

The validator can be integrated into application startup:

```python
from src.common.config_validator import validate_configuration_on_startup

# Call during app initialization
validate_configuration_on_startup()
```

## Task 10: Health Check System ✅

### Architecture

**Location**: `app/health/`

### Components

1. **Base System** (`base.py`)
   - `HealthChecker`: Abstract base class for all health checkers
   - `HealthResult`: Standardized result format with status, message, details
   - `HealthStatus`: Enum (HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN)
   - `CompositeHealthChecker`: Runs multiple checkers in parallel

2. **Individual Checkers**
   - `DatabaseHealthChecker` (`database.py`): Connection, performance, migrations
   - `ExternalAPIHealthChecker` (`external_apis.py`): VirusTotal, AbuseIPDB, Gemini, Gmail OAuth
   - `FilesystemHealthChecker` (`filesystem.py`): Disk space, permissions, directories
   - `DependencyHealthChecker` (`dependencies.py`): Python packages, versions, imports
   - `SystemHealthChecker` (`system.py`): CPU, memory, network, processes

3. **Unified Service** (`service.py`)
   - `HealthCheckService`: Orchestrates all health checks
   - Parallel execution with timeout protection
   - Formatted reporting and status aggregation

### Health Check Features

#### Database Health
- Connection testing with pool metrics
- Performance measurement (query response times)
- Migration status verification
- Connection pool utilization monitoring

#### External API Health  
- Connectivity tests for all configured APIs
- Response time measurement
- API key validation
- Graceful handling when APIs are mocked

#### Filesystem Health
- Disk space monitoring with thresholds
- Required directory existence checks
- File permission validation
- Temporary directory accessibility

#### Dependency Health
- Python version compatibility
- Critical vs optional package availability
- Package version reporting
- Import functionality testing

#### System Health
- CPU utilization monitoring
- Memory usage tracking
- Network connectivity tests
- Process resource usage

### CLI Integration

```bash
# Run comprehensive health checks
python phishnet-cli.py health

# Example output:
🏥 PhishNet Health Check Report
==================================================
Overall Status: ⚠️ DEGRADED
Timestamp: 2025-09-10T18:41:32.600701
Execution Time: 6194.4ms

📊 Component Summary:
  ✅ dependencies: healthy (2674.1ms)
  ✅ system: healthy (2593.4ms)  
  ⚠️ filesystem: degraded (17.1ms)
  ⚠️ external_apis: degraded (6127.8ms)
  ❌ database: unhealthy (5359.3ms)

📈 Statistics:
  Total Checks: 5
  Healthy: 2
  Degraded: 2
  Unhealthy: 1
```

### API Integration

Health checks are exposed via REST API endpoints:

```python
# Available endpoints
GET /health/              # Comprehensive health status
GET /health/ready         # Kubernetes readiness probe
GET /health/live          # Kubernetes liveness probe  
GET /health/components    # Available health check components
GET /health/database      # Database-specific health
GET /health/external-apis # External API health
GET /health/system        # System resource health
```

### Usage Patterns

#### Development
```python
from app.health.service import check_health

# Quick health check
report = await check_health()
print(f"Status: {report['overall_status']}")
```

#### Production Monitoring
- **Liveness Probe**: `/health/live` - Basic application responsiveness
- **Readiness Probe**: `/health/ready` - Ready to serve traffic
- **Detailed Monitoring**: `/health/` - Full system health dashboard

#### CI/CD Integration
```bash
# Health check as part of deployment verification
python phishnet-cli.py health
if [ $? -eq 0 ]; then
    echo "Health checks passed, deployment successful"
else  
    echo "Health checks failed, rolling back deployment"
    exit 1
fi
```

## Benefits Achieved

### Configuration Validator
1. **Early Error Detection**: Catches configuration issues before runtime
2. **Clear Error Messages**: Specific guidance on what needs to be fixed
3. **Environment-Aware**: Different validation rules for dev vs production
4. **Extensible**: Easy to add new validation rules for new settings

### Health Check System  
1. **Comprehensive Coverage**: All critical system components monitored
2. **Kubernetes Ready**: Standard readiness/liveness probes
3. **Performance Monitoring**: Response times and resource utilization
4. **Parallel Execution**: Fast health checks with timeout protection
5. **Detailed Reporting**: Rich information for troubleshooting

## Single Source of Truth Achievement

Both systems contribute to the **single source of truth** architecture:

- **Configuration Validator** ensures consistent, valid configuration across all components
- **Health Check System** provides unified monitoring of all system dependencies
- **Centralized CLI** consolidates all operational commands
- **Standardized Interfaces** ensure consistent behavior across components

The architectural restructuring is now complete with all 10 tasks implemented, providing a robust, maintainable, and production-ready PhishNet system! 🚀
