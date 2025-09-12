"""
Dependency Health Checker

Checks Python packages, system dependencies, and runtime requirements.
"""

import sys
import importlib
import pkg_resources
from typing import Any, Dict, List, Tuple

from .base import HealthChecker, HealthResult, HealthStatus


class DependencyHealthChecker(HealthChecker):
    """Health checker for Python dependencies and system requirements."""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("dependencies", timeout)
        
        # Critical dependencies that must be available
        self.critical_packages = [
            'fastapi',
            'uvicorn', 
            'sqlalchemy',
            'pydantic',
            'redis',
            'aiohttp',
            'psutil'
        ]
        
        # Optional dependencies that provide enhanced functionality
        self.optional_packages = [
            'playwright',
            'celery',
            'prometheus_client',
            'structlog',
            'google-generativeai'
        ]
    
    async def check_health(self) -> HealthResult:
        """Check dependency health."""
        results = {
            'python_version': self._check_python_version(),
            'critical_packages': self._check_critical_packages(),
            'optional_packages': self._check_optional_packages(),
            'package_versions': self._check_package_versions(),
            'import_tests': self._check_imports()
        }
        
        # Determine overall status
        overall_status = HealthStatus.HEALTHY
        messages = []
        
        for check_name, check_result in results.items():
            if check_result['status'] == 'unhealthy':
                overall_status = HealthStatus.UNHEALTHY
            elif check_result['status'] == 'degraded' and overall_status != HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.DEGRADED
            
            if check_result.get('message'):
                messages.append(f"{check_name}: {check_result['message']}")
        
        return HealthResult(
            component=self.component_name,
            status=overall_status,
            message="; ".join(messages) if messages else "All dependencies are available",
            details=results
        )
    
    def _check_python_version(self) -> Dict[str, Any]:
        """Check Python version compatibility."""
        version = sys.version_info
        version_str = f"{version.major}.{version.minor}.{version.micro}"
        
        # PhishNet requires Python 3.8+
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            return {
                'status': 'unhealthy',
                'message': f'Python {version_str} is not supported (requires 3.8+)',
                'version': version_str,
                'supported': False
            }
        elif version.major == 3 and version.minor < 9:
            return {
                'status': 'degraded',
                'message': f'Python {version_str} is supported but 3.9+ recommended',
                'version': version_str,
                'supported': True
            }
        else:
            return {
                'status': 'healthy',
                'message': f'Python {version_str} is fully supported',
                'version': version_str,
                'supported': True
            }
    
    def _check_critical_packages(self) -> Dict[str, Any]:
        """Check critical package availability."""
        missing_packages = []
        available_packages = []
        
        for package in self.critical_packages:
            try:
                importlib.import_module(package.replace('-', '_'))
                available_packages.append(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            return {
                'status': 'unhealthy',
                'message': f'Missing critical packages: {", ".join(missing_packages)}',
                'missing': missing_packages,
                'available': available_packages,
                'total_critical': len(self.critical_packages)
            }
        else:
            return {
                'status': 'healthy',
                'message': f'All {len(self.critical_packages)} critical packages available',
                'missing': [],
                'available': available_packages,
                'total_critical': len(self.critical_packages)
            }
    
    def _check_optional_packages(self) -> Dict[str, Any]:
        """Check optional package availability."""
        missing_packages = []
        available_packages = []
        
        for package in self.optional_packages:
            try:
                importlib.import_module(package.replace('-', '_').replace('_', '.', 1) if '.' not in package else package)
                available_packages.append(package)
            except ImportError:
                missing_packages.append(package)
        
        if len(missing_packages) == len(self.optional_packages):
            return {
                'status': 'degraded',
                'message': 'No optional packages available - some features will be disabled',
                'missing': missing_packages,
                'available': available_packages,
                'total_optional': len(self.optional_packages)
            }
        elif missing_packages:
            return {
                'status': 'healthy',
                'message': f'{len(available_packages)}/{len(self.optional_packages)} optional packages available',
                'missing': missing_packages,
                'available': available_packages,
                'total_optional': len(self.optional_packages)
            }
        else:
            return {
                'status': 'healthy',
                'message': f'All {len(self.optional_packages)} optional packages available',
                'missing': [],
                'available': available_packages,
                'total_optional': len(self.optional_packages)
            }
    
    def _check_package_versions(self) -> Dict[str, Any]:
        """Check installed package versions."""
        try:
            installed_packages = {}
            outdated_packages = []
            
            # Get versions of key packages
            key_packages = self.critical_packages + ['pydantic-settings', 'structlog']
            
            for package in key_packages:
                try:
                    # Handle package name variations
                    pkg_name = package
                    if package == 'google-generativeai':
                        pkg_name = 'google_generativeai'
                    elif package == 'pydantic-settings':
                        pkg_name = 'pydantic_settings'
                    
                    dist = pkg_resources.get_distribution(pkg_name)
                    installed_packages[package] = dist.version
                    
                except pkg_resources.DistributionNotFound:
                    installed_packages[package] = 'Not installed'
                except Exception as e:
                    installed_packages[package] = f'Error: {str(e)}'
            
            return {
                'status': 'healthy',
                'message': f'Package versions retrieved for {len(installed_packages)} packages',
                'versions': installed_packages,
                'outdated': outdated_packages
            }
            
        except Exception as e:
            return {
                'status': 'degraded',
                'message': f'Failed to check package versions: {str(e)}',
                'error': str(e)
            }
    
    def _check_imports(self) -> Dict[str, Any]:
        """Test critical imports."""
        import_tests = [
            ('fastapi', 'from fastapi import FastAPI'),
            ('sqlalchemy', 'from sqlalchemy import create_engine'),
            ('pydantic', 'from pydantic import BaseModel'),
            ('aiohttp', 'import aiohttp'),
            ('asyncio', 'import asyncio'),
        ]
        
        failed_imports = []
        successful_imports = []
        
        for package, import_stmt in import_tests:
            try:
                exec(import_stmt)
                successful_imports.append(package)
            except Exception as e:
                failed_imports.append({'package': package, 'error': str(e)})
        
        if failed_imports:
            return {
                'status': 'unhealthy',
                'message': f'{len(failed_imports)} critical imports failed',
                'failed': failed_imports,
                'successful': successful_imports
            }
        else:
            return {
                'status': 'healthy',
                'message': f'All {len(successful_imports)} critical imports successful',
                'failed': [],
                'successful': successful_imports
            }
