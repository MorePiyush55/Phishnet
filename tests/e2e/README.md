# End-to-End Testing Suite

Comprehensive end-to-end testing suite for the PhishNet application, providing complete validation of all system components, privacy compliance, security measures, and performance characteristics.

## Overview

The E2E testing suite consists of four main test categories:

1. **Complete Flow Testing** (`test_complete_flow.py`)
   - OAuth authentication flow testing
   - Gmail integration and email synchronization
   - Threat analysis pipeline testing
   - Result processing and storage
   - End-to-end user workflow validation

2. **Privacy Compliance Testing** (`test_privacy_compliance.py`)
   - GDPR compliance verification
   - CCPA compliance verification
   - Consent management testing
   - PII redaction and data protection
   - Data subject rights testing
   - Audit trail validation

3. **Security Testing** (`test_security.py`)
   - Authentication and authorization testing
   - Input validation and sanitization
   - Threat detection accuracy testing
   - Security headers and encryption
   - Rate limiting and monitoring
   - Vulnerability assessments

4. **Performance Testing** (`test_performance.py`)
   - API endpoint performance
   - Database query optimization
   - Concurrent load handling
   - Memory usage and leak detection
   - Scalability testing
   - Resource utilization monitoring

## Quick Start

### Prerequisites

Ensure you have the following dependencies installed:

```bash
pip install pytest pytest-asyncio pytest-html pytest-timeout aiohttp psutil
```

### Basic Usage

1. **Create default configuration:**
```bash
python run_e2e_tests.py --create-config
```

2. **Run all test suites:**
```bash
python run_e2e_tests.py
```

3. **Run specific test suite:**
```bash
python run_e2e_tests.py --suite complete_flow
python run_e2e_tests.py --suite privacy_compliance
python run_e2e_tests.py --suite security
python run_e2e_tests.py --suite performance
```

4. **List available test suites:**
```bash
python run_e2e_tests.py --list-suites
```

### Configuration

The test runner uses a JSON configuration file (`e2e_test_config.json`) that controls:

- **Test Suite Settings**: Enable/disable suites, set timeouts, configure parallelization
- **Reporting Options**: HTML reports, JSON reports, JUnit XML output
- **Environment Settings**: Database connections, API endpoints, test parameters
- **Performance Thresholds**: Response time limits, memory usage caps, CPU utilization

#### Sample Configuration

```json
{
  "test_suites": {
    "complete_flow": {
      "enabled": true,
      "timeout": 300,
      "parallel": false,
      "test_files": ["test_complete_flow.py"]
    },
    "privacy_compliance": {
      "enabled": true,
      "timeout": 180,
      "parallel": true,
      "test_files": ["test_privacy_compliance.py"]
    },
    "security": {
      "enabled": true,
      "timeout": 240,
      "parallel": true,
      "test_files": ["test_security.py"]
    },
    "performance": {
      "enabled": true,
      "timeout": 600,
      "parallel": false,
      "test_files": ["test_performance.py"]
    }
  },
  "reporting": {
    "generate_html_report": true,
    "generate_json_report": true,
    "generate_junit_xml": true,
    "save_logs": true
  },
  "environment": {
    "test_database": "test.db",
    "api_base_url": "http://localhost:8000",
    "test_timeout": 30,
    "max_retries": 3
  },
  "performance_thresholds": {
    "api_response_time_ms": 2000,
    "database_query_time_ms": 100,
    "memory_usage_mb": 500,
    "cpu_usage_percent": 80
  }
}
```

## Test Scenarios

### Complete Flow Testing

#### OAuth Authentication Flow
- **Scenario**: Gmail OAuth setup and token exchange
- **Coverage**: Authorization URL generation, callback handling, token refresh
- **Validation**: Authentication success, token security, error handling

#### Email Synchronization
- **Scenario**: High-volume Gmail inbox processing
- **Coverage**: Batch email fetching, incremental sync, error recovery
- **Validation**: Data accuracy, performance under load, duplicate handling

#### Threat Analysis Pipeline
- **Scenario**: End-to-end threat detection workflow
- **Coverage**: ML model inference, URL analysis, attachment scanning
- **Validation**: Accuracy metrics, response times, result storage

#### Privacy Compliance Integration
- **Scenario**: Privacy-aware email processing
- **Coverage**: Consent verification, PII redaction, audit logging
- **Validation**: GDPR/CCPA compliance, data protection measures

### Privacy Compliance Testing

#### Consent Management
```python
# Test consent recording and validation
await consent_manager.record_consent(
    user_id="test_user",
    consent_type=ConsentType.DATA_PROCESSING,
    granted=True,
    legal_basis="consent",
    purpose="email_threat_analysis"
)

has_consent = await consent_manager.has_consent(user_id, ConsentType.DATA_PROCESSING)
assert has_consent, "Consent should be recorded and retrievable"
```

#### PII Redaction
```python
# Test automatic PII redaction
text = "Contact us at support@example.com or call +1-555-123-4567"
redacted = PIIRedactor.redact_pii(text)

assert "support@example.com" not in redacted
assert "+1-555-123-4567" not in redacted
assert "[EMAIL]" in redacted or "[PII]" in redacted
```

#### Data Subject Rights
```python
# Test data access request processing
request_id = await rights_manager.submit_request(
    user_id="test_user",
    request_type=PrivacyRightType.ACCESS,
    description="Request all my personal data"
)

await rights_manager.process_request(request_id, "approve")
request_status = await rights_manager.get_request_status(request_id)
assert request_status.status == "completed"
```

### Security Testing

#### Authentication Security
```python
# Test password strength validation
weak_passwords = ["123456", "password", "abc123"]
for password in weak_passwords:
    is_valid = await auth_service.validate_password_strength(password)
    assert not is_valid, f"Weak password should be rejected: {password}"
```

#### Threat Detection Accuracy
```python
# Test phishing detection
phishing_email = {
    "subject": "URGENT: Verify your account NOW!",
    "body": "Click here: http://phishing-site.com",
    "sender": "security@paypal-fake.com"
}

prediction = await threat_classifier.predict(phishing_email)
assert prediction["is_phishing"], "Should detect phishing email"
assert prediction["confidence"] > 0.8, "Should have high confidence"
```

#### Input Validation
```python
# Test SQL injection prevention
injection_attempts = [
    "'; DROP TABLE users; --",
    "1' OR '1'='1",
    "admin'--"
]

validator = InputValidator()
for attempt in injection_attempts:
    is_safe = validator.check_sql_injection(attempt)
    assert not is_safe, f"Should detect SQL injection: {attempt}"
```

### Performance Testing

#### API Response Time
```python
# Test API endpoint performance
response_times = []
for _ in range(100):
    start_time = time.time()
    response = await client.get("/api/health")
    end_time = time.time()
    response_times.append(end_time - start_time)

avg_response_time = statistics.mean(response_times)
assert avg_response_time < 0.05, f"Health endpoint too slow: {avg_response_time:.3f}s"
```

#### Concurrent Load Testing
```python
# Test concurrent user handling
async def simulate_user_session():
    # Login, scan email, get results
    session_duration = await perform_user_workflow()
    return session_duration

# Run 50 concurrent user sessions
tasks = [simulate_user_session() for _ in range(50)]
session_durations = await asyncio.gather(*tasks)

avg_session_duration = statistics.mean(session_durations)
assert avg_session_duration < 5.0, "Sessions too slow under load"
```

#### Memory Usage Monitoring
```python
# Test memory usage during intensive operations
process = psutil.Process()
initial_memory = process.memory_info().rss

# Process large batch of emails
await email_service.process_email_batch(large_email_batch)

current_memory = process.memory_info().rss
memory_increase = (current_memory - initial_memory) / 1024 / 1024  # MB

assert memory_increase < 100, f"Memory usage too high: {memory_increase:.1f}MB"
```

## Reporting

The test suite generates comprehensive reports in multiple formats:

### HTML Report
Interactive HTML report with:
- Test results summary
- Individual test details
- Failure analysis
- Performance metrics
- Screenshots and logs

### JSON Report
Machine-readable JSON report containing:
- Test execution metadata
- Detailed results for each test
- Performance metrics
- Configuration settings
- Recommendations

### JUnit XML
Standard JUnit XML format for CI/CD integration:
- Test suite results
- Individual test outcomes
- Execution times
- Error messages

### Performance Reports
Specialized performance reports including:
- Response time distributions
- Throughput measurements
- Resource utilization graphs
- Scalability analysis
- Performance recommendations

## CI/CD Integration

### GitHub Actions Integration

```yaml
name: E2E Tests
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:13
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r tests/requirements-test.txt
    
    - name: Setup test environment
      run: |
        python tests/e2e/run_e2e_tests.py --create-config
    
    - name: Run E2E tests
      run: |
        python tests/e2e/run_e2e_tests.py
    
    - name: Upload test reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: e2e-test-reports
        path: tests/e2e/reports/
```

### Docker Integration

```dockerfile
# Dockerfile.e2e-tests
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt tests/requirements-test.txt ./
RUN pip install -r requirements.txt -r requirements-test.txt

COPY . .
WORKDIR /app/tests/e2e

CMD ["python", "run_e2e_tests.py"]
```

## Best Practices

### Test Data Management
- Use fixtures for consistent test data setup
- Implement proper test data cleanup
- Isolate tests to prevent data contamination
- Use factories for generating test data

### Error Handling
- Implement comprehensive error scenarios
- Test failure recovery mechanisms
- Validate error messages and codes
- Ensure graceful degradation

### Performance Considerations
- Set realistic performance thresholds
- Monitor resource usage during tests
- Implement load testing scenarios
- Profile and optimize slow tests

### Privacy and Security
- Validate all privacy compliance measures
- Test security controls thoroughly
- Use secure test credentials
- Implement proper data anonymization

## Troubleshooting

### Common Issues

1. **Test Timeouts**
   - Increase timeout values in configuration
   - Check for slow database queries
   - Verify network connectivity
   - Monitor system resource usage

2. **Authentication Failures**
   - Verify OAuth credentials
   - Check token expiration handling
   - Validate redirect URLs
   - Review permission scopes

3. **Performance Degradation**
   - Monitor database connection pools
   - Check for memory leaks
   - Verify cache configurations
   - Analyze slow queries

4. **Privacy Compliance Failures**
   - Verify consent management setup
   - Check PII redaction patterns
   - Validate audit logging
   - Review data retention policies

### Debugging Tips

1. **Enable Detailed Logging**
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **Use Test-Specific Configuration**
   ```bash
   python run_e2e_tests.py --config debug_config.json
   ```

3. **Run Individual Test Classes**
   ```bash
   pytest test_complete_flow.py::TestGmailIntegration -v
   ```

4. **Generate Debug Reports**
   ```bash
   python run_e2e_tests.py --suite performance --generate-debug-report
   ```

## Contributing

When adding new E2E tests:

1. Follow the established test patterns
2. Include comprehensive docstrings
3. Add appropriate fixtures and cleanup
4. Update configuration as needed
5. Document new test scenarios
6. Ensure tests are deterministic
7. Add performance assertions
8. Include error handling tests

## Support

For issues with the E2E testing suite:

1. Check the troubleshooting guide
2. Review test logs and reports
3. Validate configuration settings
4. Run individual test suites for isolation
5. Monitor system resources during tests
6. Check dependencies and versions