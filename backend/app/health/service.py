"""
Unified Health Check Service

Provides a single interface for running all health checks and generating reports.
"""

import asyncio
from typing import Any, Dict, List, Optional
from datetime import datetime

from .base import CompositeHealthChecker, HealthResult, HealthStatus
from .database import DatabaseHealthChecker
from .external_apis import ExternalAPIHealthChecker
from .filesystem import FilesystemHealthChecker
from .dependencies import DependencyHealthChecker
from .system import SystemHealthChecker
from app.config.settings import get_settings


class HealthCheckService:
    """Unified health check service."""
    
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self.settings = get_settings()
        
        # Initialize all health checkers
        self.checkers = {
            'database': DatabaseHealthChecker(timeout=5.0),
            'external_apis': ExternalAPIHealthChecker(timeout=10.0),
            'filesystem': FilesystemHealthChecker(timeout=5.0),
            'dependencies': DependencyHealthChecker(timeout=5.0),
            'system': SystemHealthChecker(timeout=5.0),
        }
        
        self.composite_checker = CompositeHealthChecker(list(self.checkers.values()))
    
    async def check_all(self, parallel: bool = True, include_details: bool = True) -> Dict[str, Any]:
        """Run all health checks and return comprehensive report."""
        start_time = datetime.utcnow()
        
        try:
            # Run all health checks
            results = await self.composite_checker.check_all(parallel=parallel)
            
            # Create detailed report
            report = self.composite_checker.create_summary(results)
            
            # Add execution metadata
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds() * 1000
            
            report.update({
                'execution_time_ms': execution_time,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'parallel_execution': parallel,
                'timeout': self.timeout
            })
            
            # Add individual results if requested
            if include_details:
                report['detailed_results'] = [result.to_dict() for result in results]
            
            return report
            
        except Exception as e:
            return {
                'overall_status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'error_type': type(e).__name__,
                'timestamp': datetime.utcnow().isoformat(),
                'execution_time_ms': (datetime.utcnow() - start_time).total_seconds() * 1000
            }
    
    async def check_specific(self, components: List[str]) -> Dict[str, Any]:
        """Run health checks for specific components only."""
        if not components:
            return await self.check_all()
        
        # Filter checkers
        selected_checkers = []
        for component in components:
            if component in self.checkers:
                selected_checkers.append(self.checkers[component])
            else:
                raise ValueError(f"Unknown health check component: {component}")
        
        # Run selected checks
        composite = CompositeHealthChecker(selected_checkers)
        results = await composite.check_all(parallel=True)
        
        return composite.create_summary(results)
    
    async def check_readiness(self) -> Dict[str, Any]:
        """Check if the system is ready to serve requests."""
        # Critical checks for readiness
        critical_components = ['database', 'dependencies']
        
        try:
            selected_checkers = [self.checkers[comp] for comp in critical_components]
            composite = CompositeHealthChecker(selected_checkers)
            results = await composite.check_all(parallel=True)
            
            overall_status = composite.get_overall_status(results)
            
            return {
                'ready': overall_status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED],
                'status': overall_status.value,
                'timestamp': datetime.utcnow().isoformat(),
                'checks': [result.to_dict() for result in results]
            }
            
        except Exception as e:
            return {
                'ready': False,
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def check_liveness(self) -> Dict[str, Any]:
        """Basic liveness check - is the application running."""
        try:
            # Simple check that the application is responsive
            return {
                'alive': True,
                'status': HealthStatus.HEALTHY.value,
                'timestamp': datetime.utcnow().isoformat(),
                'uptime_check': 'passed'
            }
            
        except Exception as e:
            return {
                'alive': False,
                'status': HealthStatus.UNHEALTHY.value,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_available_checks(self) -> List[str]:
        """Get list of available health check components."""
        return list(self.checkers.keys())
    
    def print_health_report(self, report: Dict[str, Any], show_details: bool = False):
        """Print a formatted health report."""
        print(f"\n🏥 PhishNet Health Check Report")
        print(f"{'='*50}")
        
        # Overall status
        overall_status = report.get('overall_status', 'unknown')
        status_icon = {
            'healthy': '✅',
            'degraded': '⚠️',
            'unhealthy': '❌',
            'unknown': '❓'
        }.get(overall_status, '❓')
        
        print(f"Overall Status: {status_icon} {overall_status.upper()}")
        print(f"Timestamp: {report.get('timestamp', 'unknown')}")
        
        if 'execution_time_ms' in report:
            print(f"Execution Time: {report['execution_time_ms']:.1f}ms")
        
        # Component summary
        if 'components' in report:
            print(f"\n📊 Component Summary:")
            for component, details in report['components'].items():
                status = details.get('status', 'unknown')
                icon = {
                    'healthy': '✅',
                    'degraded': '⚠️', 
                    'unhealthy': '❌',
                    'unknown': '❓'
                }.get(status, '❓')
                
                duration = details.get('duration_ms', 0)
                print(f"  {icon} {component}: {status} ({duration:.1f}ms)")
                
                if show_details and details.get('message'):
                    print(f"     └─ {details['message']}")
        
        # Statistics
        if all(k in report for k in ['total_checks', 'healthy_count', 'degraded_count', 'unhealthy_count']):
            print(f"\n📈 Statistics:")
            print(f"  Total Checks: {report['total_checks']}")
            print(f"  Healthy: {report['healthy_count']}")
            print(f"  Degraded: {report['degraded_count']}")
            print(f"  Unhealthy: {report['unhealthy_count']}")
        
        if 'error' in report:
            print(f"\n❌ Error: {report['error']}")
        
        print(f"{'='*50}")


# Global health check service instance
_health_service = None


def get_health_service() -> HealthCheckService:
    """Get the global health check service instance."""
    global _health_service
    if _health_service is None:
        _health_service = HealthCheckService()
    return _health_service


# Convenience functions for common health check operations
async def check_health(parallel: bool = True, include_details: bool = True) -> Dict[str, Any]:
    """Run all health checks."""
    service = get_health_service()
    return await service.check_all(parallel=parallel, include_details=include_details)


async def check_readiness() -> Dict[str, Any]:
    """Check system readiness."""
    service = get_health_service()
    return await service.check_readiness()


async def check_liveness() -> Dict[str, Any]:
    """Check system liveness."""
    service = get_health_service()
    return await service.check_liveness()


if __name__ == "__main__":
    # CLI usage
    async def main():
        service = HealthCheckService()
        report = await service.check_all()
        service.print_health_report(report, show_details=True)
    
    asyncio.run(main())
