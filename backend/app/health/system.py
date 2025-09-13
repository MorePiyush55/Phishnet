"""
System Health Checker

Checks system-level metrics like CPU, memory, and network connectivity.
"""

import os
import psutil
import socket
from typing import Any, Dict

from .base import HealthChecker, HealthResult, HealthStatus


class SystemHealthChecker(HealthChecker):
    """Health checker for system resources and connectivity."""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("system", timeout)
    
    async def check_health(self) -> HealthResult:
        """Check system health metrics."""
        checks = [
            ('cpu', self._check_cpu()),
            ('memory', self._check_memory()),
            ('network', self._check_network()),
            ('processes', self._check_processes())
        ]
        
        results = {}
        overall_status = HealthStatus.HEALTHY
        messages = []
        
        for check_name, check_result in checks:
            results[check_name] = check_result
            
            if check_result['status'] == 'unhealthy':
                overall_status = HealthStatus.UNHEALTHY
            elif check_result['status'] == 'degraded' and overall_status != HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.DEGRADED
            
            if check_result.get('message'):
                messages.append(f"{check_name}: {check_result['message']}")
        
        return HealthResult(
            component=self.component_name,
            status=overall_status,
            message="; ".join(messages) if messages else "System metrics are healthy",
            details=results
        )
    
    def _check_cpu(self) -> Dict[str, Any]:
        """Check CPU utilization."""
        try:
            # Get CPU usage over a short interval
            cpu_percent = psutil.cpu_percent(interval=1.0)
            cpu_count = psutil.cpu_count()
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else None
            
            # Determine status
            if cpu_percent > 90:
                status = 'unhealthy'
                message = f'Critical CPU usage: {cpu_percent:.1f}%'
            elif cpu_percent > 70:
                status = 'degraded'
                message = f'High CPU usage: {cpu_percent:.1f}%'
            else:
                status = 'healthy'
                message = f'Normal CPU usage: {cpu_percent:.1f}%'
            
            result = {
                'status': status,
                'message': message,
                'cpu_percent': cpu_percent,
                'cpu_count': cpu_count
            }
            
            if load_avg:
                result['load_avg'] = load_avg
                
            return result
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Failed to check CPU: {str(e)}',
                'error': str(e)
            }
    
    def _check_memory(self) -> Dict[str, Any]:
        """Check memory utilization."""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Convert to GB for readability
            total_gb = memory.total / (1024**3)
            available_gb = memory.available / (1024**3)
            used_gb = memory.used / (1024**3)
            
            # Determine status based on available memory
            if memory.percent > 95:
                status = 'unhealthy'
                message = f'Critical memory usage: {memory.percent:.1f}% ({available_gb:.1f}GB available)'
            elif memory.percent > 85:
                status = 'degraded'
                message = f'High memory usage: {memory.percent:.1f}% ({available_gb:.1f}GB available)'
            else:
                status = 'healthy'
                message = f'Normal memory usage: {memory.percent:.1f}% ({available_gb:.1f}GB available)'
            
            return {
                'status': status,
                'message': message,
                'total_gb': round(total_gb, 2),
                'used_gb': round(used_gb, 2),
                'available_gb': round(available_gb, 2),
                'percent': memory.percent,
                'swap_percent': swap.percent
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Failed to check memory: {str(e)}',
                'error': str(e)
            }
    
    def _check_network(self) -> Dict[str, Any]:
        """Check network connectivity."""
        try:
            # Test connectivity to common services
            test_hosts = [
                ('google.com', 80),
                ('8.8.8.8', 53),  # Google DNS
                ('1.1.1.1', 53),  # Cloudflare DNS
            ]
            
            connectivity_results = []
            successful_connections = 0
            
            for host, port in test_hosts:
                try:
                    with socket.create_connection((host, port), timeout=3):
                        connectivity_results.append({'host': host, 'port': port, 'status': 'connected'})
                        successful_connections += 1
                except Exception as e:
                    connectivity_results.append({
                        'host': host, 
                        'port': port, 
                        'status': 'failed', 
                        'error': str(e)
                    })
            
            # Get network interface statistics
            net_io = psutil.net_io_counters()
            
            # Determine status
            if successful_connections == 0:
                status = 'unhealthy'
                message = 'No network connectivity detected'
            elif successful_connections < len(test_hosts):
                status = 'degraded'
                message = f'Partial network connectivity: {successful_connections}/{len(test_hosts)} hosts reachable'
            else:
                status = 'healthy'
                message = f'Network connectivity is good: {successful_connections}/{len(test_hosts)} hosts reachable'
            
            return {
                'status': status,
                'message': message,
                'connectivity_tests': connectivity_results,
                'successful_connections': successful_connections,
                'total_tests': len(test_hosts),
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Failed to check network: {str(e)}',
                'error': str(e)
            }
    
    def _check_processes(self) -> Dict[str, Any]:
        """Check system processes and resource usage."""
        try:
            # Get current process info
            current_process = psutil.Process()
            
            # Get process counts
            total_processes = len(psutil.pids())
            
            # Get current process resource usage
            process_info = {
                'pid': current_process.pid,
                'cpu_percent': current_process.cpu_percent(),
                'memory_percent': current_process.memory_percent(),
                'memory_mb': current_process.memory_info().rss / (1024**2),
                'num_threads': current_process.num_threads(),
                'create_time': current_process.create_time()
            }
            
            # Check if current process is using too many resources
            if process_info['memory_percent'] > 10:
                status = 'degraded'
                message = f'High memory usage by current process: {process_info["memory_percent"]:.1f}%'
            elif process_info['cpu_percent'] > 50:
                status = 'degraded'
                message = f'High CPU usage by current process: {process_info["cpu_percent"]:.1f}%'
            else:
                status = 'healthy'
                message = f'Process resource usage is normal'
            
            return {
                'status': status,
                'message': message,
                'total_processes': total_processes,
                'current_process': process_info
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Failed to check processes: {str(e)}',
                'error': str(e)
            }
