# Real Analyzer Quick Start Guide

## 🚀 **Getting Started with Real Analyzers**

### **Prerequisites**
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up API keys (optional for testing, required for production)
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"  
export GOOGLE_API_KEY="your_google_gemini_api_key"
```

### **Quick Test**
```bash
# Test basic integration (works without API keys)
python test_basic_integration.py

# Expected output: "Test PASSED" with all components verified
```

## 📋 **Available Real Analyzers**

### **1. VirusTotal Client**
```python
from app.services.virustotal import VirusTotalClient

vt = VirusTotalClient()

# Analyze URL
result = await vt.scan("https://suspicious-site.com")
print(f"Threat Score: {result['threat_score']}")

# Analyze IP  
result = await vt.scan("192.168.1.1")

# Analyze file hash
result = await vt.scan("d41d8cd98f00b204e9800998ecf8427e")
```

### **2. AbuseIPDB Client**
```python
from app.services.abuseipdb import AbuseIPDBClient

abuse = AbuseIPDBClient()

# Check IP reputation
result = await abuse.scan("8.8.8.8")
print(f"Abuse Confidence: {result['abuse_confidence']}")
print(f"Country: {result['country_code']}")
```

### **3. Gemini AI Client**
```python
from app.services.gemini import GeminiClient

gemini = GeminiClient()

# Analyze text for phishing
result = await gemini.scan("Urgent! Verify your account now!")
print(f"Phishing Score: {result['threat_score']}")
print(f"Indicators: {result['indicators']}")
```

### **4. Link Redirect Analyzer**
```python
from app.services.link_redirect_analyzer import LinkRedirectAnalyzer

redirect = LinkRedirectAnalyzer()

# Trace redirect chain
result = await redirect.scan("https://bit.ly/suspicious-link")
print(f"Final URL: {result['final_url']}")
print(f"Redirect Chain: {result['redirect_chain']}")
print(f"Cloaking Detected: {result['cloaking_detected']}")
```

## 🔧 **Unified Analysis**

### **Using Analyzer Factory**
```python
from app.services.analyzer_factory import get_analyzer_factory

# Get all real analyzers
factory = get_analyzer_factory()
await factory.initialize()

analyzers = factory.get_real_analyzers()
print(f"Available: {list(analyzers.keys())}")

# Use specific analyzer
vt = analyzers['virustotal']
result = await vt.scan("https://example.com")
```

### **Using Threat Orchestrator**
```python
from app.orchestrator.real_threat_orchestrator import create_real_threat_orchestrator

# Complete email analysis
orchestrator = create_real_threat_orchestrator()
await orchestrator.initialize()

email_data = {
    "headers": {
        "from": "suspicious@phisher.com",
        "subject": "Urgent Account Verification",
        "to": "victim@example.com"
    },
    "text_content": "Click here to verify: https://bit.ly/fake-bank",
    "links": ["https://bit.ly/fake-bank"],
    "attachments": []
}

result = await orchestrator.analyze_email_comprehensive(email_data)
print(f"Overall Threat Score: {result['threat_score']}")
print(f"Verdict: {result['verdict']}")
print(f"Key Indicators: {result['indicators']}")
```

## 🔒 **Privacy-Preserving Analysis**

### **Using Privacy Adapter**
```python
from app.services.privacy_adapter import get_privacy_adapter

privacy = get_privacy_adapter()

# Make protected external request
response = await privacy.make_protected_request(
    url="https://api.virustotal.com/api/v3/urls",
    service="virustotal",
    data={"url": "https://target-site.com"}
)

# Sanitize email data
sanitized = privacy.sanitize_email_data(email_data)
```

## 📊 **Threat Aggregation**

### **Combining Multiple Results**
```python
from app.services.threat_aggregator import ThreatAggregator

aggregator = ThreatAggregator()

# Analysis results from multiple services
results = {
    "virustotal": {
        "threat_score": 0.8,
        "verdict": "malicious",
        "confidence": 0.9,
        "indicators": ["malware_detected"]
    },
    "abuseipdb": {
        "threat_score": 0.6,
        "verdict": "suspicious", 
        "confidence": 0.8,
        "indicators": ["high_abuse_confidence"]
    },
    "gemini": {
        "threat_score": 0.9,
        "verdict": "phishing",
        "confidence": 0.95,
        "indicators": ["urgency_language", "credential_harvesting"]
    }
}

# Get unified assessment
final_result = await aggregator.aggregate_threat_analysis(
    target="suspicious-email@phisher.com",
    analysis_results=results
)

print(f"Final Score: {final_result.threat_score}")
print(f"Consensus: {final_result.verdict}")
print(f"Confidence: {final_result.confidence}")
```

## 🧪 **Testing & Validation**

### **Running Test Vectors**
```python
from app.services.threat_scoring_validator import create_threat_scoring_validator

validator = create_threat_scoring_validator()

# Get test summary
summary = validator.get_test_vector_summary()
print(f"Total test vectors: {summary['total_vectors']}")

# Run validation (requires API keys)
results = await validator.run_validation_suite()
print(f"Pass rate: {results['validation_summary']['pass_rate']:.1%}")
```

### **Custom Test Vectors**
```python
from app.services.threat_scoring_validator import TestVector, ExpectedOutcome

# Create custom test
test_vector = TestVector(
    test_id="custom_001",
    test_name="Custom Phishing Test",
    test_type="phishing_email",
    input_data={
        "text": "Win $1000! Click now: https://fake-lottery.scam"
    },
    expected_outcome=ExpectedOutcome(
        threat_score_min=0.7,
        threat_score_max=1.0,
        expected_verdict="phishing",
        confidence_threshold=0.8,
        expected_indicators=["lottery_scam", "urgency"]
    ),
    priority=1
)

# Validate custom test
result = await validator.validate_test_vector(test_vector)
print(f"Test passed: {result['passed']}")
```

## ⚡ **Performance Tips**

### **Caching**
- Results are automatically cached for 2 hours
- Repeat analysis of same content uses cache
- Redis connection pooling for efficiency

### **Parallel Processing**
```python
import asyncio

# Analyze multiple items in parallel
tasks = []
for email in email_batch:
    task = orchestrator.analyze_email_comprehensive(email)
    tasks.append(task)

results = await asyncio.gather(*tasks)
```

### **Rate Limiting**
- VirusTotal: 4 requests/minute (free tier)
- AbuseIPDB: 1000 requests/day (free tier)  
- Gemini: Rate limited by Google API quotas
- Built-in delays prevent API limit violations

## 🔍 **Troubleshooting**

### **Common Issues**

1. **"No module named 'app.db.base'"**
   - This is expected for basic testing
   - Full orchestrator requires database setup
   - Use individual analyzers for simple testing

2. **API Rate Limits**
   - Check rate limit status in service health
   - Enable caching to reduce API calls
   - Use appropriate delays between requests

3. **Redis Connection Errors**
   - System falls back to mock Redis client
   - Functionality preserved without Redis
   - Install Redis for production caching

### **Debug Mode**
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Detailed logging for troubleshooting
result = await analyzer.scan("test-input")
```

## 📚 **API Documentation**

### **Standard Response Format**
All analyzers return results in this format:
```python
{
    "threat_score": float,      # 0.0-1.0 threat level
    "verdict": str,             # "clean", "suspicious", "malicious"
    "confidence": float,        # 0.0-1.0 confidence level
    "indicators": List[str],    # Threat indicators found
    "metadata": Dict[str, Any], # Service-specific details
    "execution_time": float,    # Analysis duration
    "service": str              # Service identifier
}
```

### **Error Handling**
```python
try:
    result = await analyzer.scan("input")
except Exception as e:
    print(f"Analysis failed: {e}")
    # System provides graceful degradation
```

## 🎯 **Production Deployment**

### **Environment Variables**
```bash
# Required for production
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
GOOGLE_API_KEY=your_key

# Optional configuration
REDIS_URL=redis://localhost:6379
PRIVACY_SANDBOX_IPS=10.0.1.1,10.0.1.2
LOG_LEVEL=INFO
```

### **Health Monitoring**
```python
# Check system health
health = await orchestrator.health_check()
print(f"System status: {health['status']}")
print(f"Available services: {health['available_services']}")

for service, status in health['service_health'].items():
    print(f"{service}: {status}")
```

---

**🚀 You're now ready to use PhishNet's real analyzer capabilities!**

For detailed implementation examples, see:
- `demo_real_analyzers.py` - Full demonstration
- `test_basic_integration.py` - Basic functionality test
- `REAL_ANALYZER_IMPLEMENTATION_COMPLETE.md` - Complete documentation
