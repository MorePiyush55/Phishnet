#!/usr/bin/env python3
"""
Demonstration script for the complete threat intelligence system.

This script shows how all components work together: API adapters, caching,
resilience patterns, and privacy protection.
"""

import asyncio
import os
import sys
import time
from datetime import datetime
from typing import List, Dict, Any

# Add backend to path
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from app.integrations.unified_service import (
    UnifiedThreatIntelligenceService,
    ThreatIntelligenceConfig
)


class ThreatIntelligenceDemo:
    """Demo class to showcase the threat intelligence system."""
    
    def __init__(self):
        self.service = None
        self.demo_results = []
    
    async def initialize(self):
        """Initialize the threat intelligence service."""
        print("🚀 Initializing PhishNet Threat Intelligence System")
        print("=" * 60)
        
        # Configuration (use environment variables or demo keys)
        config = ThreatIntelligenceConfig(
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", "demo_key_virustotal"),
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", "demo_key_abuseipdb"),
            gemini_api_key=os.getenv("GEMINI_API_KEY", "demo_key_gemini"),
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
            cache_enabled=True,
            pii_sanitization_enabled=True,
            audit_logging_enabled=True,
            enable_virustotal=True,
            enable_abuseipdb=True,
            enable_gemini=True,
            fallback_enabled=True
        )
        
        print(f"✅ Configuration loaded:")
        print(f"   - Cache enabled: {config.cache_enabled}")
        print(f"   - PII sanitization: {config.pii_sanitization_enabled}")
        print(f"   - Services: VirusTotal, AbuseIPDB, Gemini")
        print()
        
        # Initialize service
        self.service = UnifiedThreatIntelligenceService(config)
        
        try:
            await self.service.initialize()
            print("✅ Threat Intelligence Service initialized successfully!")
        except Exception as e:
            print(f"⚠️  Service initialization failed (demo mode): {e}")
            print("   This is expected if API keys are not configured")
        
        print()
    
    async def demo_service_health(self):
        """Demonstrate service health monitoring."""
        print("🏥 Service Health Monitoring")
        print("-" * 30)
        
        try:
            health_status = await self.service.get_service_health()
            
            for service_name, health in health_status.items():
                status_emoji = "✅" if health.is_healthy else "❌"
                print(f"{status_emoji} {service_name.capitalize()}:")
                print(f"   State: {health.circuit_breaker_state}")
                
                if health.quota_remaining is not None:
                    print(f"   Quota: {health.quota_remaining} remaining")
                
                if health.error_message:
                    print(f"   Error: {health.error_message}")
                
                print()
                
        except Exception as e:
            print(f"⚠️  Health check failed (demo mode): {e}")
        
        print()
    
    async def demo_cache_stats(self):
        """Demonstrate cache statistics."""
        print("📊 Cache Performance Statistics")
        print("-" * 35)
        
        try:
            cache_stats = await self.service.get_cache_stats()
            
            if cache_stats.get("cache_disabled"):
                print("⚠️  Cache is disabled")
            else:
                print(f"✅ Cache Status: {cache_stats.get('status', 'unknown')}")
                print(f"   Hit Rate: {cache_stats.get('hit_rate', 0) * 100:.1f}%")
                print(f"   Total Keys: {cache_stats.get('total_keys', 0)}")
                print(f"   Memory Usage: {cache_stats.get('memory_usage', 'Unknown')}")
                print(f"   Cache Hits: {cache_stats.get('hits', 0)}")
                print(f"   Cache Misses: {cache_stats.get('misses', 0)}")
                
        except Exception as e:
            print(f"⚠️  Cache stats failed (demo mode): {e}")
        
        print()
    
    async def demo_url_analysis(self):
        """Demonstrate URL threat analysis."""
        print("🔍 URL Threat Analysis Demo")
        print("-" * 30)
        
        demo_urls = [
            "https://google.com",
            "https://phishing-example.com",
            "https://malware-test.com",
            "https://suspicious-site.example"
        ]
        
        for url in demo_urls:
            print(f"🌐 Analyzing: {url}")
            start_time = time.time()
            
            try:
                result = await self.service.analyze_url(url)
                processing_time = time.time() - start_time
                
                # Display results
                cache_indicator = "💾 CACHED" if result.cache_hit else "🌐 LIVE"
                privacy_indicator = "🔒 PROTECTED" if result.privacy_protected else "🔓 DIRECT"
                
                print(f"   {cache_indicator} | {privacy_indicator}")
                print(f"   Threat Level: {result.primary_result.threat_level.value if result.primary_result else 'UNKNOWN'}")
                print(f"   Confidence: {result.confidence * 100:.1f}%")
                print(f"   Score: {result.aggregated_score:.3f}")
                print(f"   Sources: {', '.join(result.sources_used)}")
                print(f"   Processing: {processing_time:.3f}s")
                
                if result.errors:
                    print(f"   Errors: {len(result.errors)} issues")
                
                self.demo_results.append({
                    "resource": url,
                    "type": "url",
                    "cache_hit": result.cache_hit,
                    "processing_time": processing_time,
                    "score": result.aggregated_score
                })
                
            except Exception as e:
                print(f"   ❌ Analysis failed: {e}")
            
            print()
    
    async def demo_ip_analysis(self):
        """Demonstrate IP address analysis."""
        print("🌍 IP Address Analysis Demo")
        print("-" * 32)
        
        demo_ips = [
            "8.8.8.8",          # Google DNS (safe)
            "185.220.101.182",  # Tor exit node (suspicious)
            "192.168.1.1",     # Private IP
            "127.0.0.1"         # Localhost
        ]
        
        for ip in demo_ips:
            print(f"🌐 Analyzing IP: {ip}")
            start_time = time.time()
            
            try:
                result = await self.service.analyze_ip(ip)
                processing_time = time.time() - start_time
                
                # Display results
                cache_indicator = "💾 CACHED" if result.cache_hit else "🌐 LIVE"
                privacy_indicator = "🔒 PROTECTED" if result.privacy_protected else "🔓 DIRECT"
                
                print(f"   {cache_indicator} | {privacy_indicator}")
                print(f"   Threat Level: {result.primary_result.threat_level.value if result.primary_result else 'UNKNOWN'}")
                print(f"   Confidence: {result.confidence * 100:.1f}%")
                print(f"   Score: {result.aggregated_score:.3f}")
                print(f"   Sources: {', '.join(result.sources_used)}")
                print(f"   Processing: {processing_time:.3f}s")
                
                self.demo_results.append({
                    "resource": ip,
                    "type": "ip",
                    "cache_hit": result.cache_hit,
                    "processing_time": processing_time,
                    "score": result.aggregated_score
                })
                
            except Exception as e:
                print(f"   ❌ Analysis failed: {e}")
            
            print()
    
    async def demo_content_analysis(self):
        """Demonstrate content analysis with PII protection."""
        print("📝 Content Analysis with PII Protection")
        print("-" * 45)
        
        demo_contents = [
            "This is a normal email message.",
            "Urgent! Your account will be suspended. Click here to verify: https://phishing-site.com",
            "Dear john.doe@example.com, your SSN 123-45-6789 has been compromised. Call (555) 123-4567.",
            "CONGRATULATIONS! You've won $1,000,000! Send your bank details to claim your prize!"
        ]
        
        for i, content in enumerate(demo_contents, 1):
            print(f"📄 Content Sample {i}:")
            print(f"   Text: {content[:60]}{'...' if len(content) > 60 else ''}")
            
            start_time = time.time()
            
            try:
                result = await self.service.analyze_content(content)
                processing_time = time.time() - start_time
                
                # Display results
                privacy_indicator = "🔒 PII PROTECTED" if result.privacy_protected else "🔓 DIRECT"
                
                print(f"   {privacy_indicator}")
                print(f"   Threat Level: {result.primary_result.threat_level.value if result.primary_result else 'UNKNOWN'}")
                print(f"   Confidence: {result.confidence * 100:.1f}%")
                print(f"   Score: {result.aggregated_score:.3f}")
                print(f"   Sources: {', '.join(result.sources_used)}")
                print(f"   Processing: {processing_time:.3f}s")
                
                if result.audit_logs:
                    print(f"   Privacy Logs: {len(result.audit_logs)} entries")
                
                self.demo_results.append({
                    "resource": f"content_{i}",
                    "type": "content", 
                    "cache_hit": result.cache_hit,
                    "processing_time": processing_time,
                    "score": result.aggregated_score,
                    "privacy_protected": result.privacy_protected
                })
                
            except Exception as e:
                print(f"   ❌ Analysis failed: {e}")
            
            print()
    
    async def demo_cache_behavior(self):
        """Demonstrate cache hit/miss behavior."""
        print("⚡ Cache Behavior Demonstration")
        print("-" * 35)
        
        test_url = "https://demo-cache-test.com"
        
        print(f"🌐 Testing cache behavior with: {test_url}")
        print()
        
        # First analysis - should be cache miss
        print("1️⃣  First analysis (expected cache miss):")
        try:
            result1 = await self.service.analyze_url(test_url)
            cache_status1 = "💾 CACHE HIT" if result1.cache_hit else "🌐 CACHE MISS"
            print(f"   {cache_status1} - Processing time: {result1.processing_time:.3f}s")
        except Exception as e:
            print(f"   ❌ Failed: {e}")
        
        print()
        
        # Second analysis - should be cache hit
        print("2️⃣  Second analysis (expected cache hit):")
        try:
            result2 = await self.service.analyze_url(test_url)
            cache_status2 = "💾 CACHE HIT" if result2.cache_hit else "🌐 CACHE MISS"
            print(f"   {cache_status2} - Processing time: {result2.processing_time:.3f}s")
            
            if result2.cache_hit:
                speedup = result1.processing_time / result2.processing_time if result2.processing_time > 0 else 0
                print(f"   ⚡ Cache speedup: {speedup:.1f}x faster")
        except Exception as e:
            print(f"   ❌ Failed: {e}")
        
        print()
    
    async def demo_privacy_summary(self):
        """Show privacy protection summary."""
        print("🔒 Privacy Protection Summary")
        print("-" * 32)
        
        try:
            privacy_summary = await self.service.get_privacy_summary()
            
            if privacy_summary.get("privacy_protection_disabled"):
                print("⚠️  Privacy protection is disabled")
            else:
                print("✅ Privacy protection is enabled")
                
                for service_name, service_summary in privacy_summary.items():
                    if isinstance(service_summary, dict):
                        print(f"   📊 {service_name.capitalize()}:")
                        print(f"      Requests processed: {service_summary.get('total_requests', 0)}")
                        print(f"      PII detections: {service_summary.get('pii_detections', 0)}")
                        print(f"      Fields sanitized: {service_summary.get('fields_sanitized', 0)}")
                
        except Exception as e:
            print(f"⚠️  Privacy summary failed (demo mode): {e}")
        
        print()
    
    def demo_summary(self):
        """Show summary of all demo results."""
        print("📈 Demo Summary")
        print("-" * 15)
        
        if not self.demo_results:
            print("No results to summarize")
            return
        
        total_requests = len(self.demo_results)
        cache_hits = sum(1 for r in self.demo_results if r.get("cache_hit", False))
        cache_hit_rate = (cache_hits / total_requests) * 100 if total_requests > 0 else 0
        
        avg_processing_time = sum(r.get("processing_time", 0) for r in self.demo_results) / total_requests
        avg_score = sum(r.get("score", 0) for r in self.demo_results) / total_requests
        
        privacy_protected = sum(1 for r in self.demo_results if r.get("privacy_protected", False))
        
        print(f"📊 Total Analyses: {total_requests}")
        print(f"💾 Cache Hit Rate: {cache_hit_rate:.1f}%")
        print(f"⏱️  Average Processing Time: {avg_processing_time:.3f}s")
        print(f"🎯 Average Threat Score: {avg_score:.3f}")
        print(f"🔒 Privacy Protected: {privacy_protected}/{total_requests}")
        
        # Breakdown by type
        type_counts = {}
        for result in self.demo_results:
            result_type = result.get("type", "unknown")
            type_counts[result_type] = type_counts.get(result_type, 0) + 1
        
        print(f"📋 Analysis Types:")
        for analysis_type, count in type_counts.items():
            print(f"   {analysis_type.capitalize()}: {count}")
        
        print()
    
    async def run_complete_demo(self):
        """Run the complete demonstration."""
        print("🌟 PhishNet Threat Intelligence System Demo")
        print("=" * 50)
        print(f"🕐 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        try:
            # Initialize
            await self.initialize()
            
            # Health check
            await self.demo_service_health()
            
            # Cache stats
            await self.demo_cache_stats()
            
            # URL analysis
            await self.demo_url_analysis()
            
            # IP analysis
            await self.demo_ip_analysis()
            
            # Content analysis
            await self.demo_content_analysis()
            
            # Cache behavior
            await self.demo_cache_behavior()
            
            # Privacy summary
            await self.demo_privacy_summary()
            
            # Final summary
            self.demo_summary()
            
        except Exception as e:
            print(f"❌ Demo failed: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            # Cleanup
            if self.service:
                await self.service.close()
            
            print("🏁 Demo completed!")
            print(f"🕐 Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


async def main():
    """Main demo function."""
    demo = ThreatIntelligenceDemo()
    await demo.run_complete_demo()


if __name__ == "__main__":
    # Run the demo
    print("Starting PhishNet Threat Intelligence Demo...")
    print("Note: This demo will work in mock mode if API keys are not configured")
    print()
    
    asyncio.run(main())