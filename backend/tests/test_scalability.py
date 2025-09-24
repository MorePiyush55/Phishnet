"""
Scalability Tests for PhishNet Background Worker System
Tests queue performance, worker scaling, and system limits.
"""

import asyncio
import time
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any
import concurrent.futures
from statistics import mean, median, stdev
import requests
import logging

from backend.app.workers.celery_config import celery_app
from backend.app.workers.worker_manager import WorkerManager
from backend.app.workers.task_prioritizer import TaskPrioritizer
from backend.app.core.redis_client import get_redis_client
from backend.app.tasks.scan_tasks import quick_email_scan, full_email_scan
from backend.app.tasks.analysis_tasks import basic_threat_analysis, ml_threat_detection

logger = logging.getLogger(__name__)

class ScalabilityTestSuite:
    """Comprehensive scalability testing suite."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.worker_manager = WorkerManager()
        self.task_prioritizer = TaskPrioritizer()
        self.redis_client = get_redis_client()
        self.test_results = {}
        
    def generate_test_email(self, index: int = 0) -> Dict[str, Any]:
        """Generate a test email for analysis."""
        return {
            "subject": f"Test Email #{index} - Urgent Security Alert",
            "sender": f"test{index}@example.com",
            "content": f"""
            Dear User,
            
            This is test email #{index} for scalability testing.
            
            Your account has been compromised and requires immediate attention.
            Please click the link below to verify your account:
            
            http://suspicious-phishing-site{index}.com/verify?token=abc123
            
            If you do not verify within 24 hours, your account will be suspended.
            
            Thank you,
            Security Team
            """,
            "recipients": [f"user{index}@company.com"],
            "analysis_type": "standard"
        }
    
    async def test_bulk_job_submission(self, num_jobs: int = 1000) -> Dict[str, Any]:
        """Test submitting a large number of jobs simultaneously."""
        print(f"\n🚀 Testing bulk job submission ({num_jobs} jobs)...")
        
        start_time = time.time()
        job_ids = []
        failed_submissions = 0
        
        # Generate test emails
        test_emails = [self.generate_test_email(i) for i in range(num_jobs)]
        
        # Submit jobs in batches to avoid overwhelming the system
        batch_size = 50
        batches = [test_emails[i:i + batch_size] for i in range(0, len(test_emails), batch_size)]
        
        for batch_idx, batch in enumerate(batches):
            print(f"  Submitting batch {batch_idx + 1}/{len(batches)}...")
            
            # Submit batch via API
            try:
                response = requests.post(
                    f"{self.base_url}/api/v1/analysis/submit-bulk",
                    json={
                        "emails": batch,
                        "analysis_type": "quick",
                        "priority": "normal"
                    },
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    job_ids.extend(result.get("job_ids", []))
                else:
                    failed_submissions += len(batch)
                    print(f"    Batch failed with status {response.status_code}")
                    
            except Exception as e:
                failed_submissions += len(batch)
                print(f"    Batch failed with error: {str(e)}")
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        submission_time = time.time() - start_time
        
        return {
            "test_name": "bulk_job_submission",
            "num_jobs_requested": num_jobs,
            "jobs_submitted": len(job_ids),
            "failed_submissions": failed_submissions,
            "submission_time": submission_time,
            "jobs_per_second": len(job_ids) / submission_time if submission_time > 0 else 0,
            "job_ids": job_ids
        }
    
    async def test_queue_performance(self, job_ids: List[str], timeout: int = 600) -> Dict[str, Any]:
        """Test queue processing performance and worker scaling."""
        print(f"\n⚡ Testing queue performance...")
        
        start_time = time.time()
        completed_jobs = 0
        failed_jobs = 0
        processing_times = []
        
        # Monitor job completion
        while time.time() - start_time < timeout and completed_jobs + failed_jobs < len(job_ids):
            # Check job statuses
            for job_id in job_ids[:50]:  # Sample first 50 jobs
                try:
                    response = requests.get(f"{self.base_url}/api/v1/analysis/status/{job_id}")
                    if response.status_code == 200:
                        job_status = response.json()
                        
                        if job_status["status"] == "completed":
                            completed_jobs += 1
                            if job_status.get("processing_time"):
                                processing_times.append(job_status["processing_time"])
                        elif job_status["status"] == "failed":
                            failed_jobs += 1
                            
                except Exception as e:
                    logger.error(f"Failed to check status for job {job_id}: {str(e)}")
            
            # Get queue metrics
            queue_metrics = self.worker_manager.get_queue_metrics()
            worker_status = self.worker_manager.get_worker_status()
            
            # Print progress
            total_processed = completed_jobs + failed_jobs
            if total_processed > 0:
                print(f"  Progress: {total_processed}/{len(job_ids)} jobs processed ({(total_processed/len(job_ids)*100):.1f}%)")
                print(f"  Active workers: {len([w for w in worker_status if w.get('status') == 'online'])}")
                print(f"  Queue depths: {', '.join([f'{k}: {v.get('length', 0)}' for k, v in queue_metrics.items()])}")
            
            await asyncio.sleep(10)  # Check every 10 seconds
        
        total_time = time.time() - start_time
        
        return {
            "test_name": "queue_performance",
            "total_jobs": len(job_ids),
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "total_time": total_time,
            "throughput": completed_jobs / total_time if total_time > 0 else 0,
            "average_processing_time": mean(processing_times) if processing_times else 0,
            "median_processing_time": median(processing_times) if processing_times else 0,
            "processing_time_stddev": stdev(processing_times) if len(processing_times) > 1 else 0,
            "success_rate": completed_jobs / (completed_jobs + failed_jobs) if completed_jobs + failed_jobs > 0 else 0
        }
    
    async def test_worker_auto_scaling(self) -> Dict[str, Any]:
        """Test worker auto-scaling capabilities."""
        print(f"\n🔄 Testing worker auto-scaling...")
        
        initial_workers = len(self.worker_manager.get_worker_status())
        
        # Create high load scenario
        print("  Creating high load scenario...")
        load_jobs = []
        for i in range(100):
            job = full_email_scan.apply_async(
                args=[str(uuid.uuid4()), {"comprehensive": True}],
                queue="heavy"
            )
            load_jobs.append(job.id)
        
        # Monitor scaling for 5 minutes
        scaling_data = []
        start_time = time.time()
        
        while time.time() - start_time < 300:  # 5 minutes
            worker_status = self.worker_manager.get_worker_status()
            queue_metrics = self.worker_manager.get_queue_metrics()
            
            scaling_data.append({
                "timestamp": time.time(),
                "active_workers": len([w for w in worker_status if w.get('status') == 'online']),
                "queue_depths": {k: v.get('length', 0) for k, v in queue_metrics.items()},
                "total_pending": sum(v.get('length', 0) for v in queue_metrics.values())
            })
            
            print(f"  Workers: {scaling_data[-1]['active_workers']}, Pending: {scaling_data[-1]['total_pending']}")
            
            await asyncio.sleep(30)  # Check every 30 seconds
        
        # Clean up load jobs
        celery_app.control.revoke(load_jobs, terminate=True)
        
        final_workers = len(self.worker_manager.get_worker_status())
        
        return {
            "test_name": "worker_auto_scaling",
            "initial_workers": initial_workers,
            "final_workers": final_workers,
            "max_workers": max(data["active_workers"] for data in scaling_data),
            "scaling_data": scaling_data,
            "scaling_occurred": final_workers > initial_workers
        }
    
    async def test_system_limits(self) -> Dict[str, Any]:
        """Test system limits and resource constraints."""
        print(f"\n🔥 Testing system limits...")
        
        # Test memory usage under load
        memory_data = []
        
        # Test with increasing job counts
        job_counts = [100, 500, 1000, 2000]
        results = {}
        
        for job_count in job_counts:
            print(f"  Testing with {job_count} jobs...")
            
            # Submit jobs
            test_jobs = []
            for i in range(job_count):
                job = quick_email_scan.apply_async(
                    args=[str(uuid.uuid4()), {"quick": True}],
                    queue="realtime"
                )
                test_jobs.append(job.id)
            
            # Wait a bit and measure system state
            await asyncio.sleep(30)
            
            queue_metrics = self.worker_manager.get_queue_metrics()
            worker_status = self.worker_manager.get_worker_status()
            
            # Get Redis memory usage
            try:
                redis_info = self.redis_client.info('memory')
                memory_usage = redis_info.get('used_memory', 0)
            except Exception:
                memory_usage = 0
            
            results[job_count] = {
                "pending_jobs": sum(v.get('length', 0) for v in queue_metrics.values()),
                "active_workers": len([w for w in worker_status if w.get('status') == 'online']),
                "memory_usage_mb": memory_usage / (1024 * 1024),
                "redis_connected_clients": redis_info.get('connected_clients', 0) if 'redis_info' in locals() else 0
            }
            
            # Clean up
            celery_app.control.revoke(test_jobs, terminate=True)
            await asyncio.sleep(10)
        
        return {
            "test_name": "system_limits",
            "results_by_job_count": results
        }
    
    async def test_error_handling_and_dlq(self) -> Dict[str, Any]:
        """Test error handling and Dead Letter Queue functionality."""
        print(f"\n💥 Testing error handling and DLQ...")
        
        # Create jobs that will fail
        failing_jobs = []
        for i in range(20):
            # Submit job with invalid data to force failure
            job = basic_threat_analysis.apply_async(
                args=[None, {"force_error": True}],  # Invalid args
                queue="standard"
            )
            failing_jobs.append(job.id)
        
        # Wait for processing
        await asyncio.sleep(60)
        
        # Check DLQ status
        try:
            response = requests.get(f"{self.base_url}/api/v1/workers/dlq")
            dlq_status = response.json() if response.status_code == 200 else {}
        except Exception:
            dlq_status = {}
        
        # Check how many jobs ended up in DLQ
        dlq_items = dlq_status.get('total_items', 0)
        
        # Test DLQ replay functionality
        replayed_jobs = 0
        if dlq_status.get('items'):
            for item in dlq_status['items'][:5]:  # Replay first 5 items
                try:
                    replay_response = requests.post(
                        f"{self.base_url}/api/v1/workers/dlq/{item['task_id']}/replay"
                    )
                    if replay_response.status_code == 200:
                        replayed_jobs += 1
                except Exception:
                    pass
        
        return {
            "test_name": "error_handling_dlq",
            "failing_jobs_submitted": len(failing_jobs),
            "dlq_items": dlq_items,
            "replayed_jobs": replayed_jobs,
            "dlq_categories": dlq_status.get('category_breakdown', {})
        }
    
    async def test_websocket_performance(self, num_connections: int = 100) -> Dict[str, Any]:
        """Test WebSocket connection performance."""
        print(f"\n🔌 Testing WebSocket performance ({num_connections} connections)...")
        
        # This would test WebSocket performance with multiple concurrent connections
        # For now, return a placeholder result
        return {
            "test_name": "websocket_performance",
            "requested_connections": num_connections,
            "successful_connections": 0,  # Would be implemented
            "message_throughput": 0,
            "connection_time_avg": 0
        }
    
    async def run_comprehensive_test_suite(self) -> Dict[str, Any]:
        """Run the complete scalability test suite."""
        print("🧪 Starting PhishNet Scalability Test Suite")
        print("=" * 60)
        
        start_time = time.time()
        all_results = {}
        
        try:
            # Test 1: Bulk job submission
            bulk_result = await self.test_bulk_job_submission(1000)
            all_results["bulk_submission"] = bulk_result
            
            # Test 2: Queue performance (using jobs from test 1)
            if bulk_result.get("job_ids"):
                queue_result = await self.test_queue_performance(bulk_result["job_ids"])
                all_results["queue_performance"] = queue_result
            
            # Test 3: Worker auto-scaling
            scaling_result = await self.test_worker_auto_scaling()
            all_results["worker_scaling"] = scaling_result
            
            # Test 4: System limits
            limits_result = await self.test_system_limits()
            all_results["system_limits"] = limits_result
            
            # Test 5: Error handling and DLQ
            error_result = await self.test_error_handling_and_dlq()
            all_results["error_handling"] = error_result
            
            # Test 6: WebSocket performance
            websocket_result = await self.test_websocket_performance()
            all_results["websocket_performance"] = websocket_result
            
        except Exception as e:
            logger.error(f"Test suite failed: {str(e)}")
            all_results["error"] = str(e)
        
        total_time = time.time() - start_time
        
        # Compile summary
        summary = {
            "test_suite": "PhishNet Scalability Tests",
            "total_execution_time": total_time,
            "tests_completed": len([r for r in all_results.values() if isinstance(r, dict) and "test_name" in r]),
            "timestamp": datetime.utcnow().isoformat(),
            "results": all_results
        }
        
        return summary
    
    def generate_test_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive test report."""
        report = []
        report.append("PhishNet Scalability Test Report")
        report.append("=" * 50)
        report.append(f"Executed at: {results.get('timestamp')}")
        report.append(f"Total execution time: {results.get('total_execution_time', 0):.2f} seconds")
        report.append(f"Tests completed: {results.get('tests_completed', 0)}")
        report.append("")
        
        # Detailed results
        for test_name, test_result in results.get("results", {}).items():
            if isinstance(test_result, dict) and "test_name" in test_result:
                report.append(f"{test_result['test_name'].replace('_', ' ').title()}")
                report.append("-" * 30)
                
                for key, value in test_result.items():
                    if key != "test_name" and not isinstance(value, (list, dict)):
                        report.append(f"  {key.replace('_', ' ').title()}: {value}")
                
                report.append("")
        
        return "\n".join(report)

# CLI runner
async def main():
    """Run the scalability test suite."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PhishNet Scalability Test Suite")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Base URL for API testing")
    parser.add_argument("--jobs", type=int, default=1000, help="Number of jobs to test with")
    parser.add_argument("--output", help="Output file for test results")
    
    args = parser.parse_args()
    
    # Run tests
    test_suite = ScalabilityTestSuite(args.base_url)
    results = await test_suite.run_comprehensive_test_suite()
    
    # Generate report
    report = test_suite.generate_test_report(results)
    print("\n" + report)
    
    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        with open(f"{args.output}.report.txt", 'w') as f:
            f.write(report)
        
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())