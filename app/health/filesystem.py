"""
Filesystem Health Checker

Checks filesystem availability, permissions, and disk space.
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from .base import HealthChecker, HealthResult, HealthStatus
from app.config.settings import get_settings


class FilesystemHealthChecker(HealthChecker):
    """Health checker for filesystem components."""
    
    def __init__(self, timeout: float = 5.0):
        super().__init__("filesystem", timeout)
        self.settings = get_settings()
    
    async def check_health(self) -> HealthResult:
        """Check filesystem health."""
        checks = [
            self._check_disk_space(),
            self._check_required_directories(),
            self._check_file_permissions(),
            self._check_temp_directory()
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
            message="; ".join(messages) if messages else "Filesystem checks passed",
            details=results
        )
    
    def _check_disk_space(self) -> tuple:
        """Check available disk space."""
        try:
            # Get disk usage for current directory
            usage = shutil.disk_usage('.')
            
            total_gb = usage.total / (1024**3)
            free_gb = usage.free / (1024**3)
            used_gb = (usage.total - usage.free) / (1024**3)
            free_percent = (usage.free / usage.total) * 100
            
            # Determine status based on free space
            if free_percent < 5:  # Less than 5% free
                status = 'unhealthy'
                message = f"Critical disk space: {free_percent:.1f}% free ({free_gb:.1f}GB)"
            elif free_percent < 15:  # Less than 15% free
                status = 'degraded'
                message = f"Low disk space: {free_percent:.1f}% free ({free_gb:.1f}GB)"
            else:
                status = 'healthy'
                message = f"Sufficient disk space: {free_percent:.1f}% free ({free_gb:.1f}GB)"
            
            return ('disk_space', {
                'status': status,
                'message': message,
                'total_gb': round(total_gb, 2),
                'used_gb': round(used_gb, 2),
                'free_gb': round(free_gb, 2),
                'free_percent': round(free_percent, 1)
            })
            
        except Exception as e:
            return ('disk_space', {
                'status': 'unhealthy',
                'message': f"Failed to check disk space: {str(e)}",
                'error': str(e)
            })
    
    def _check_required_directories(self) -> tuple:
        """Check that required directories exist and are accessible."""
        try:
            required_dirs = [
                self.settings.MODEL_PATH,
                'logs' if self.settings.LOG_FILE and 'logs' in self.settings.LOG_FILE else None,
                'data',  # Common data directory
                'uploads',  # File upload directory
            ]
            
            # Filter out None values
            required_dirs = [d for d in required_dirs if d]
            
            results = {}
            missing_dirs = []
            inaccessible_dirs = []
            
            for dir_path in required_dirs:
                path = Path(dir_path)
                
                if not path.exists():
                    missing_dirs.append(str(path))
                    results[str(path)] = {'exists': False, 'accessible': False}
                else:
                    # Test accessibility
                    try:
                        # Try to list directory contents
                        list(path.iterdir()) if path.is_dir() else path.read_text(encoding='utf-8', errors='ignore')[:100]
                        results[str(path)] = {'exists': True, 'accessible': True}
                    except PermissionError:
                        inaccessible_dirs.append(str(path))
                        results[str(path)] = {'exists': True, 'accessible': False}
                    except Exception as e:
                        inaccessible_dirs.append(str(path))
                        results[str(path)] = {'exists': True, 'accessible': False, 'error': str(e)}
            
            # Determine status
            if inaccessible_dirs:
                status = 'unhealthy'
                message = f"Inaccessible directories: {', '.join(inaccessible_dirs)}"
            elif missing_dirs:
                status = 'degraded'
                message = f"Missing directories (will be created): {', '.join(missing_dirs)}"
            else:
                status = 'healthy'
                message = f"All {len(required_dirs)} required directories are accessible"
            
            return ('directories', {
                'status': status,
                'message': message,
                'directories': results,
                'missing': missing_dirs,
                'inaccessible': inaccessible_dirs
            })
            
        except Exception as e:
            return ('directories', {
                'status': 'unhealthy',
                'message': f"Failed to check directories: {str(e)}",
                'error': str(e)
            })
    
    def _check_file_permissions(self) -> tuple:
        """Check file system permissions."""
        try:
            # Test write permissions in current directory
            test_file = Path('health_check_test.tmp')
            
            try:
                # Test write
                test_file.write_text('health check test')
                
                # Test read
                content = test_file.read_text()
                
                # Test delete
                test_file.unlink()
                
                if content == 'health check test':
                    return ('permissions', {
                        'status': 'healthy',
                        'message': 'Read/write permissions are working',
                        'can_read': True,
                        'can_write': True,
                        'can_delete': True
                    })
                else:
                    return ('permissions', {
                        'status': 'degraded',
                        'message': 'File content mismatch during permission test',
                        'can_read': True,
                        'can_write': True,
                        'can_delete': True
                    })
                    
            except PermissionError as e:
                # Clean up if possible
                try:
                    if test_file.exists():
                        test_file.unlink()
                except:
                    pass
                    
                return ('permissions', {
                    'status': 'unhealthy',
                    'message': f'Insufficient file permissions: {str(e)}',
                    'can_read': False,
                    'can_write': False,
                    'can_delete': False,
                    'error': str(e)
                })
                
        except Exception as e:
            return ('permissions', {
                'status': 'unhealthy',
                'message': f'Permission check failed: {str(e)}',
                'error': str(e)
            })
    
    def _check_temp_directory(self) -> tuple:
        """Check temporary directory accessibility."""
        try:
            # Check system temp directory
            temp_dir = Path(tempfile.gettempdir())
            
            if not temp_dir.exists():
                return ('temp_directory', {
                    'status': 'unhealthy',
                    'message': f'System temp directory does not exist: {temp_dir}',
                    'temp_dir': str(temp_dir)
                })
            
            # Test temp file creation
            with tempfile.NamedTemporaryFile(mode='w+', delete=True) as tmp_file:
                tmp_file.write('health check test')
                tmp_file.seek(0)
                content = tmp_file.read()
                
                if content == 'health check test':
                    return ('temp_directory', {
                        'status': 'healthy',
                        'message': f'Temp directory is accessible: {temp_dir}',
                        'temp_dir': str(temp_dir),
                        'can_create_files': True
                    })
                else:
                    return ('temp_directory', {
                        'status': 'degraded',
                        'message': 'Temp file content mismatch',
                        'temp_dir': str(temp_dir),
                        'can_create_files': True
                    })
                    
        except Exception as e:
            return ('temp_directory', {
                'status': 'unhealthy',
                'message': f'Temp directory check failed: {str(e)}',
                'temp_dir': str(tempfile.gettempdir()),
                'can_create_files': False,
                'error': str(e)
            })
