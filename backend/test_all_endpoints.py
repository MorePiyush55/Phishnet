"""
Comprehensive endpoint testing script for PhishNet
Tests all 80+ endpoints to verify they are working correctly
"""

import httpx
import asyncio
import json
from typing import Dict, List, Tuple
from collections import defaultdict
import sys

# Production and local URLs
BASE_URLS = {
    "production": "https://phishnet-backend-iuoc.onrender.com",
    "local": "http://localhost:8000"
}

# Test results storage
results = {
    "passed": [],
    "failed": [],
    "skipped": [],
    "not_implemented": []
}

# Endpoints organized by category
ENDPOINTS = {
    "Chrome Extension": [
        {"method": "POST", "path": "/api/v2/request-check", "auth": False, "body": {"message_id": "test", "user_id": "test"}},
        {"method": "GET", "path": "/api/v2/auth/callback", "auth": False, "params": {"code": "test"}},
    ],
    
    "Authentication": [
        {"method": "POST", "path": "/api/v1/auth/login", "auth": False, "form": {"username": "test", "password": "test"}},
        {"method": "POST", "path": "/api/v1/auth/logout", "auth": True},
        {"method": "POST", "path": "/api/v1/auth/refresh", "auth": False, "body": {"refresh_token": "test"}},
        {"method": "GET", "path": "/api/v1/auth/me", "auth": True},
        {"method": "GET", "path": "/api/v1/auth/google", "auth": False},
        {"method": "GET", "path": "/api/v1/auth/google/callback", "auth": False, "params": {"code": "test"}},
        {"method": "POST", "path": "/api/v1/auth/verify", "auth": True},
    ],
    
    "Gmail Integration V1": [
        {"method": "GET", "path": "/api/v1/gmail/status", "auth": True},
        {"method": "GET", "path": "/api/v1/gmail/connect", "auth": True},
        {"method": "POST", "path": "/api/v1/gmail/sync/start", "auth": True},
        {"method": "POST", "path": "/api/v1/gmail/sync/pause", "auth": True},
        {"method": "POST", "path": "/api/v1/gmail/sync/resume", "auth": True},
        {"method": "GET", "path": "/api/v1/gmail/sync/progress", "auth": True},
        {"method": "POST", "path": "/api/v1/gmail/backfill/start", "auth": True, "body": {"days_back": 7}},
        {"method": "GET", "path": "/api/v1/gmail/backfill/jobs", "auth": True},
        {"method": "POST", "path": "/api/v1/gmail/backfill/pause/test-job-id", "auth": True},
    ],
    
    "Gmail Integration Alternate": [
        {"method": "GET", "path": "/api/gmail/statistics", "auth": True},
        {"method": "GET", "path": "/api/gmail/auth-url", "auth": True},
        {"method": "GET", "path": "/api/gmail/quota-status", "auth": True},
        {"method": "POST", "path": "/api/gmail/setup-watches", "auth": True},
        {"method": "GET", "path": "/api/gmail/sync-progress", "auth": True},
        {"method": "POST", "path": "/api/gmail/start-initial-sync", "auth": True},
        {"method": "POST", "path": "/api/gmail/pause-sync", "auth": True},
        {"method": "POST", "path": "/api/gmail/resume-sync", "auth": True},
        {"method": "GET", "path": "/api/gmail/backfill/jobs", "auth": True},
    ],
    
    "Gmail Simple API": [
        {"method": "POST", "path": "/api/gmail-simple/analyze", "auth": False, "body": {"email_data": "test"}},
        {"method": "GET", "path": "/api/gmail-simple/check-tokens/test@example.com", "auth": False},
        {"method": "GET", "path": "/api/gmail-simple/health", "auth": False},
    ],
    
    "Email Management": [
        {"method": "GET", "path": "/api/v1/emails", "auth": True, "params": {"page": 1, "size": 20}},
        {"method": "GET", "path": "/api/v1/emails/1", "auth": True},
        {"method": "GET", "path": "/api/v1/emails/1/body", "auth": True},
        {"method": "PATCH", "path": "/api/v1/emails/1/status", "auth": True, "body": {"status": "safe"}},
        {"method": "DELETE", "path": "/api/v1/emails/1", "auth": True},
        {"method": "POST", "path": "/api/v1/emails/bulk-action", "auth": True, "body": {"email_ids": [1], "action": "quarantine"}},
        {"method": "GET", "path": "/api/v1/emails/1/attachments/1/download", "auth": True},
        {"method": "GET", "path": "/api/v1/emails/stats/summary", "auth": True},
    ],
    
    "IMAP Email": [
        {"method": "GET", "path": "/api/v1/imap-emails/pending", "auth": True},
        {"method": "POST", "path": "/api/v1/imap-emails/analyze/test-uid", "auth": True},
    ],
    
    "Email Analysis": [
        {"method": "POST", "path": "/api/v1/emails/analyze", "auth": True, "body": {"subject": "test", "sender": "test@example.com", "content": "test"}},
        {"method": "POST", "path": "/api/analyze/email", "auth": False, "body": {"subject": "test", "sender": "test@example.com", "content": "test"}},
        {"method": "POST", "path": "/api/v1/ml/analyze", "auth": True, "body": {"email_content": "test"}},
        {"method": "POST", "path": "/api/v1/ml/feedback", "auth": True, "body": {"analysis_id": "test", "correct": True}},
        {"method": "POST", "path": "/api/analysis/reprocess/1", "auth": True},
        {"method": "GET", "path": "/api/analysis/threat-intel", "auth": True, "params": {"query": "test.com"}},
    ],
    
    "Threat Analysis": [
        {"method": "POST", "path": "/api/v1/threat/analyze", "auth": True, "body": {"content": "test"}},
        {"method": "GET", "path": "/api/v1/threat/history", "auth": True},
        {"method": "GET", "path": "/api/v1/threat/verify-deterministic/testhash", "auth": True},
    ],
    
    "Link Analysis": [
        {"method": "GET", "path": "/api/v1/emails/1/links", "auth": True},
        {"method": "POST", "path": "/api/links/1/analyze", "auth": True},
        {"method": "POST", "path": "/api/links/1/screenshot", "auth": True},
        {"method": "POST", "path": "/api/v1/redirect-analysis/analyze", "auth": True, "body": {"url": "https://example.com"}},
        {"method": "POST", "path": "/api/v1/redirect-analysis/quick-scan", "auth": True, "body": {"url": "https://example.com"}},
    ],
    
    "Threat Intelligence": [
        {"method": "GET", "path": "/api/threat-intelligence/health", "auth": False},
        {"method": "GET", "path": "/api/threat-intelligence/cache-stats", "auth": False},
    ],
    
    "Sandbox": [
        {"method": "GET", "path": "/api/sandbox/jobs", "auth": True},
        {"method": "POST", "path": "/api/sandbox/jobs/test-job/cancel", "auth": True},
        {"method": "POST", "path": "/api/sandbox/jobs/test-job/retry", "auth": True},
        {"method": "GET", "path": "/api/sandbox/jobs/test-job/evidence/download", "auth": True},
    ],
    
    "Consent & Privacy": [
        {"method": "GET", "path": "/api/v1/consent/status", "auth": True},
        {"method": "PATCH", "path": "/api/v1/consent/preferences", "auth": True, "body": {"analytics": True}},
        {"method": "GET", "path": "/api/v1/consent/export", "auth": True},
        {"method": "POST", "path": "/api/v1/consent/revoke", "auth": True, "body": {"reason": "test"}},
        {"method": "GET", "path": "/api/v1/privacy/dashboard", "auth": True},
        {"method": "GET", "path": "/api/v1/privacy/audit-trail", "auth": True},
        {"method": "GET", "path": "/api/v1/privacy/retention-policies", "auth": True},
    ],
    
    "Audit Logs": [
        {"method": "GET", "path": "/api/v1/audit/logs", "auth": True, "params": {"page": 1}},
        {"method": "GET", "path": "/api/v1/audit/stats", "auth": True},
        {"method": "GET", "path": "/api/v1/audit/export", "auth": True},
        {"method": "GET", "path": "/api/audits/logs", "auth": True},
    ],
    
    "Analytics & Dashboard": [
        {"method": "GET", "path": "/api/dashboard/kpis", "auth": True},
        {"method": "GET", "path": "/api/analytics/dashboard", "auth": True},
        {"method": "GET", "path": "/api/orchestrator/stats", "auth": True},
        {"method": "GET", "path": "/api/jobs/test-job/status", "auth": True},
    ],
    
    "System & Health": [
        {"method": "GET", "path": "/api/system/stats", "auth": True},
        {"method": "GET", "path": "/api/system/health", "auth": False},
        {"method": "GET", "path": "/health", "auth": False},
    ],
    
    "OAuth Testing": [
        {"method": "POST", "path": "/api/test/oauth/start", "auth": False},
        {"method": "GET", "path": "/api/test/oauth", "auth": False},
        {"method": "GET", "path": "/api/test/oauth/callback", "auth": False, "params": {"code": "test"}},
    ],
    
    "User Management": [
        {"method": "GET", "path": "/api/user/status", "auth": True},
        {"method": "POST", "path": "/api/scan/trigger", "auth": True},
        {"method": "GET", "path": "/api/scan/history", "auth": True},
        {"method": "GET", "path": "/api/user/export", "auth": True},
        {"method": "DELETE", "path": "/api/user/delete", "auth": True},
    ],
    
    "Client Logging": [
        {"method": "POST", "path": "/api/logs/client-errors", "auth": False, "body": {"error": "test"}},
        {"method": "POST", "path": "/api/metrics/client", "auth": False, "body": {"metric": "test"}},
    ],
}


async def test_endpoint(client: httpx.AsyncClient, category: str, endpoint: Dict, base_url: str) -> Tuple[str, str, int, str]:
    """Test a single endpoint"""
    method = endpoint["method"]
    path = endpoint["path"]
    full_url = f"{base_url}{path}"
    
    headers = {}
    if endpoint.get("auth", False):
        headers["Authorization"] = "Bearer test_token"
    
    try:
        kwargs = {
            "headers": headers,
            "timeout": 10.0,
            "follow_redirects": False
        }
        
        # Add body if present
        if "body" in endpoint:
            kwargs["json"] = endpoint["body"]
        
        # Add form data if present
        if "form" in endpoint:
            kwargs["data"] = endpoint["form"]
        
        # Add query params if present
        if "params" in endpoint:
            kwargs["params"] = endpoint["params"]
        
        # Make request
        if method == "GET":
            response = await client.get(full_url, **kwargs)
        elif method == "POST":
            response = await client.post(full_url, **kwargs)
        elif method == "PATCH":
            response = await client.patch(full_url, **kwargs)
        elif method == "DELETE":
            response = await client.delete(full_url, **kwargs)
        elif method == "PUT":
            response = await client.put(full_url, **kwargs)
        else:
            return (category, f"{method} {path}", 0, "Unsupported method")
        
        status = response.status_code
        
        # Determine result
        if status == 404:
            result = "NOT_FOUND"
        elif status == 405:
            result = "METHOD_NOT_ALLOWED"
        elif status == 501:
            result = "NOT_IMPLEMENTED"
        elif status in [200, 201, 202, 204]:
            result = "SUCCESS"
        elif status in [401, 403]:
            result = "AUTH_REQUIRED" if not endpoint.get("auth") else "AUTH_FAILED"
        elif status == 422:
            result = "VALIDATION_ERROR"
        elif status >= 500:
            result = "SERVER_ERROR"
        else:
            result = f"STATUS_{status}"
        
        return (category, f"{method} {path}", status, result)
        
    except httpx.ConnectError:
        return (category, f"{method} {path}", 0, "CONNECTION_FAILED")
    except httpx.TimeoutException:
        return (category, f"{method} {path}", 0, "TIMEOUT")
    except Exception as e:
        return (category, f"{method} {path}", 0, f"ERROR: {str(e)}")


async def test_all_endpoints(base_url: str):
    """Test all endpoints"""
    print(f"\n{'='*80}")
    print(f"Testing endpoints at: {base_url}")
    print(f"{'='*80}\n")
    
    results_by_category = defaultdict(list)
    total_count = 0
    
    async with httpx.AsyncClient() as client:
        # Test each category
        for category, endpoints in ENDPOINTS.items():
            print(f"\n📂 Testing {category} ({len(endpoints)} endpoints)")
            print("-" * 80)
            
            for endpoint in endpoints:
                total_count += 1
                result = await test_endpoint(client, category, endpoint, base_url)
                results_by_category[category].append(result)
                
                # Color coding for results
                category_name, endpoint_name, status, result_type = result
                
                if result_type == "SUCCESS":
                    symbol = "✅"
                elif result_type in ["AUTH_REQUIRED", "AUTH_FAILED"]:
                    symbol = "🔐"
                elif result_type in ["NOT_FOUND", "METHOD_NOT_ALLOWED"]:
                    symbol = "❌"
                elif result_type == "NOT_IMPLEMENTED":
                    symbol = "⚠️"
                elif result_type == "CONNECTION_FAILED":
                    symbol = "🔌"
                elif result_type == "VALIDATION_ERROR":
                    symbol = "📝"
                elif "ERROR" in result_type:
                    symbol = "💥"
                else:
                    symbol = "❓"
                
                print(f"{symbol} [{status:3d}] {endpoint_name:60s} {result_type}")
            
            await asyncio.sleep(0.1)  # Small delay between categories
    
    return results_by_category, total_count


def print_summary(results_by_category: Dict, total_count: int):
    """Print test summary"""
    print(f"\n{'='*80}")
    print(f"TEST SUMMARY")
    print(f"{'='*80}\n")
    
    # Count by result type
    result_counts = defaultdict(int)
    for category_results in results_by_category.values():
        for _, _, _, result_type in category_results:
            result_counts[result_type] += 1
    
    print(f"Total Endpoints Tested: {total_count}\n")
    
    print("Results by Status:")
    print("-" * 80)
    for result_type, count in sorted(result_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / total_count) * 100
        print(f"  {result_type:30s}: {count:3d} ({percentage:5.1f}%)")
    
    print("\n" + "=" * 80)
    print("\nResults by Category:")
    print("-" * 80)
    
    for category, results in results_by_category.items():
        success_count = sum(1 for r in results if r[3] == "SUCCESS")
        total = len(results)
        print(f"\n{category}: {success_count}/{total} successful")
        
        # Show problematic endpoints
        problems = [r for r in results if r[3] not in ["SUCCESS", "AUTH_REQUIRED", "AUTH_FAILED"]]
        if problems:
            for _, endpoint, status, result in problems:
                print(f"  ❌ [{status:3d}] {endpoint} - {result}")
    
    print("\n" + "=" * 80)
    
    # Key findings
    print("\n🔍 KEY FINDINGS:")
    print("-" * 80)
    
    not_found = [r for results in results_by_category.values() for r in results if r[3] == "NOT_FOUND"]
    not_implemented = [r for results in results_by_category.values() for r in results if r[3] == "NOT_IMPLEMENTED"]
    errors = [r for results in results_by_category.values() for r in results if "ERROR" in r[3] or "SERVER_ERROR" in r[3]]
    
    if not_found:
        print(f"\n❌ {len(not_found)} endpoints return 404 (Not Found):")
        for _, endpoint, _, _ in not_found[:10]:  # Show first 10
            print(f"   - {endpoint}")
        if len(not_found) > 10:
            print(f"   ... and {len(not_found) - 10} more")
    
    if not_implemented:
        print(f"\n⚠️  {len(not_implemented)} endpoints return 501 (Not Implemented):")
        for _, endpoint, _, _ in not_implemented[:10]:
            print(f"   - {endpoint}")
    
    if errors:
        print(f"\n💥 {len(errors)} endpoints have errors:")
        for _, endpoint, status, result in errors[:10]:
            print(f"   - [{status}] {endpoint}: {result}")
    
    # Calculate health score
    working = result_counts.get("SUCCESS", 0) + result_counts.get("AUTH_REQUIRED", 0) + result_counts.get("AUTH_FAILED", 0)
    health_score = (working / total_count) * 100
    
    print(f"\n{'='*80}")
    print(f"API HEALTH SCORE: {health_score:.1f}% ({working}/{total_count} endpoints functioning)")
    print(f"{'='*80}\n")


async def main():
    """Main test runner"""
    print("\n" + "="*80)
    print("PHISHNET API ENDPOINT TESTING")
    print("="*80)
    
    # Determine which URL to test
    if len(sys.argv) > 1:
        env = sys.argv[1].lower()
        if env in BASE_URLS:
            base_url = BASE_URLS[env]
        else:
            print(f"Unknown environment: {env}")
            print(f"Available: {', '.join(BASE_URLS.keys())}")
            return
    else:
        # Default to local
        base_url = BASE_URLS["local"]
    
    try:
        results, total_count = await test_all_endpoints(base_url)
        print_summary(results, total_count)
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
    except Exception as e:
        print(f"\n\n💥 Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("\nUsage: python test_all_endpoints.py [local|production]")
    print("Default: local\n")
    asyncio.run(main())
