"""
Quick start script for testing playbook integration.

This script demonstrates the complete workflow:
1. Parse playbooks from source directory
2. Initialize the enhanced orchestrator with playbook support
3. Run a sample analysis
4. Display performance metrics
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from app.integrations.playbooks.playbook_adapter import PlaybookAdapter
from app.integrations.playbooks.performance_metrics import get_performance_monitor


async def main():
    """Main demo function."""
    print("=" * 70)
    print("PhishNet Playbook Integration - Quick Start Demo")
    print("=" * 70)
    print()
    
    # Step 1: Parse playbooks
    print("Step 1: Parsing Phantom playbooks...")
    print("-" * 70)
    
    playbook_dir = Path(__file__).parent / "source_playbooks"
    output_dir = Path(__file__).parent / "rules"
    
    if not playbook_dir.exists():
        print(f"❌ Playbook directory not found: {playbook_dir}")
        print("   Please ensure 'source_playbooks' folder exists in playbooks module")
        return
    
    adapter = PlaybookAdapter(playbook_dir)
    exported_files = adapter.export_rules_to_json(output_dir)
    
    print(f"✓ Parsed and exported {len(exported_files)} playbook rules")
    for f in exported_files:
        print(f"  - {f.name}")
    print()
    
    # Step 2: Display sample playbook structure
    print("Step 2: Sample Playbook Structure")
    print("-" * 70)
    
    if exported_files:
        import json
        sample_rule = json.loads(exported_files[0].read_text())
        print(f"Playbook: {sample_rule['playbook_name']}")
        print(f"Description: {sample_rule['description'][:100]}...")
        print(f"Entry Point: {sample_rule['entry_point']}")
        print(f"Total Blocks: {len(sample_rule['blocks'])}")
        print(f"Block Types: {', '.join(set(b['block_type'] for b in sample_rule['blocks'].values()))}")
        print()
    
    # Step 3: Initialize orchestrator with playbooks
    print("Step 3: Initializing Enhanced Orchestrator")
    print("-" * 70)
    
    try:
        from app.orchestrator.enhanced_threat_orchestrator import EnhancedThreatOrchestrator
        
        orchestrator = EnhancedThreatOrchestrator()
        await orchestrator.initialize()
        
        if orchestrator.playbook_engine:
            stats = orchestrator.playbook_engine.get_execution_stats()
            print(f"✓ Playbook engine initialized")
            print(f"  Loaded playbooks: {stats['loaded_playbooks']}")
        else:
            print("⚠ Playbook engine not initialized (optional)")
        
        if orchestrator.batch_processor:
            print(f"✓ Batch processor initialized")
            print(f"  Max concurrent requests: {orchestrator.batch_processor.max_concurrent_requests}")
            print(f"  Batch size: {orchestrator.batch_processor.batch_size}")
        
        print()
    except Exception as e:
        print(f"⚠ Could not initialize orchestrator: {e}")
        print("  (This is okay for testing playbook parsing only)")
        print()
    
    # Step 4: Performance metrics demo
    print("Step 4: Performance Metrics Demo")
    print("-" * 70)
    
    monitor = get_performance_monitor()
    
    # Simulate some operations
    print("Simulating playbook executions...")
    for i in range(5):
        monitor.record_playbook_execution(
            playbook_name="PhishTank_URL_Reputation_Analysis",
            execution_time_ms=250.0 + (i * 10),
            success=True,
            findings_count=3,
            actions_count=2
        )
    
    print("Simulating cache operations...")
    for i in range(10):
        monitor.record_cache_access(
            hit=(i % 3 != 0),  # 67% hit rate
            access_time_ms=8.5 if (i % 3 != 0) else 320.0
        )
    
    print("Simulating email analyses...")
    for i in range(8):
        monitor.record_email_analysis(analysis_time_ms=1800.0 + (i * 100))
    
    print()
    
    # Display metrics
    print("Performance Metrics Report:")
    print("-" * 70)
    report = monitor.get_full_report()
    
    print(f"\n📊 Playbook Performance:")
    playbook_perf = report['playbook_performance']
    print(f"  Total Executions: {playbook_perf['total_executions']}")
    print(f"  Success Rate: {playbook_perf['overall_success_rate'] * 100:.1f}%")
    print(f"  Avg Execution Time: {playbook_perf['avg_execution_time_ms']:.1f}ms")
    
    print(f"\n💾 Cache Performance:")
    cache_perf = report['cache_performance']
    print(f"  Total Requests: {cache_perf['total_requests']}")
    print(f"  Hit Rate: {cache_perf['hit_rate']:.1f}%")
    print(f"  Time Saved: {cache_perf['time_saved_seconds']:.2f}s")
    
    print(f"\n⚡ Throughput:")
    throughput = report['throughput']
    print(f"  Emails Analyzed: {throughput['emails_analyzed']}")
    print(f"  Avg Analysis Time: {throughput['avg_analysis_time_ms']:.1f}ms")
    print(f"  Emails/Second: {throughput['emails_per_second']:.2f}")
    print(f"  P95 Latency: {throughput['latency_percentiles']['p95_ms']:.1f}ms")
    
    print()
    print("=" * 70)
    print("✅ Demo Complete!")
    print()
    print("Next Steps:")
    print("1. Review generated rules in:", output_dir)
    print("2. Configure Redis connection for caching")
    print("3. Set API keys for external services (VirusTotal, etc.)")
    print("4. Run full integration tests")
    print("5. Monitor metrics at /api/metrics/playbook-performance")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
