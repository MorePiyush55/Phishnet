#!/usr/bin/env python3
"""
Comprehensive Logging Setup for Sandbox Infrastructure

Configures structured logging, security event tracking, and monitoring
for all sandbox components with proper log rotation and aggregation.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Dict, Any
import json
import socket
from datetime import datetime

import structlog


class SandboxLogFormatter(logging.Formatter):
    """Custom formatter for sandbox logs with security context."""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'hostname': socket.gethostname(),
            'service': 'phishnet-sandbox',
            'process_id': os.getpid(),
            'thread_id': getattr(record, 'thread_id', None),
            'worker_id': getattr(record, 'worker_id', None),
            'job_id': getattr(record, 'job_id', None),
            'security_event': getattr(record, 'security_event', False),
            'event_type': getattr(record, 'event_type', None),
            'source_ip': getattr(record, 'source_ip', None),
            'target_url': getattr(record, 'target_url', None)
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                          'pathname', 'filename', 'module', 'lineno', 'funcName',
                          'created', 'msecs', 'relativeCreated', 'thread',
                          'threadName', 'processName', 'process', 'getMessage',
                          'exc_info', 'exc_text', 'stack_info']:
                log_entry[f'extra_{key}'] = value
        
        return json.dumps(log_entry)


def setup_file_logging(log_dir: Path, log_level: str = 'INFO') -> logging.Logger:
    """Set up file-based logging with rotation."""
    
    # Ensure log directory exists
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger('sandbox')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Main log file with rotation
    main_handler = logging.handlers.RotatingFileHandler(
        log_dir / 'sandbox.log',
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=10
    )
    main_handler.setFormatter(SandboxLogFormatter())
    logger.addHandler(main_handler)
    
    # Security events log
    security_handler = logging.handlers.RotatingFileHandler(
        log_dir / 'security.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=20
    )
    security_handler.setFormatter(SandboxLogFormatter())
    security_handler.addFilter(lambda record: getattr(record, 'security_event', False))
    logger.addHandler(security_handler)
    
    # Error log
    error_handler = logging.handlers.RotatingFileHandler(
        log_dir / 'error.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    error_handler.setFormatter(SandboxLogFormatter())
    error_handler.setLevel(logging.ERROR)
    logger.addHandler(error_handler)
    
    # Console output for development
    if os.getenv('SANDBOX_DEBUG', 'false').lower() == 'true':
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(console_handler)
    
    return logger


def setup_structured_logging(log_level: str = 'INFO') -> None:
    """Configure structured logging with processors."""
    
    # Define log processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="ISO"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]
    
    # Add JSON processor for production
    if os.getenv('SANDBOX_ENV', 'development') == 'production':
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def setup_security_logging(redis_client=None) -> logging.Logger:
    """Set up dedicated security event logging."""
    
    security_logger = logging.getLogger('sandbox.security')
    security_logger.setLevel(logging.INFO)
    
    # Security log formatter
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s - '
        'worker_id=%(worker_id)s job_id=%(job_id)s event_type=%(event_type)s'
    )
    
    # File handler for security events
    security_file_handler = logging.handlers.RotatingFileHandler(
        '/var/log/sandbox/security.log',
        maxBytes=20 * 1024 * 1024,  # 20MB
        backupCount=50
    )
    security_file_handler.setFormatter(security_formatter)
    security_logger.addHandler(security_file_handler)
    
    # Syslog handler for external SIEM integration
    try:
        syslog_handler = logging.handlers.SysLogHandler(
            address=('localhost', 514),
            facility=logging.handlers.SysLogHandler.LOG_LOCAL0
        )
        syslog_formatter = logging.Formatter(
            'phishnet-sandbox: %(levelname)s %(message)s'
        )
        syslog_handler.setFormatter(syslog_formatter)
        security_logger.addHandler(syslog_handler)
    except Exception:
        # Syslog not available, skip
        pass
    
    return security_logger


def setup_health_monitoring_logging() -> logging.Logger:
    """Set up health monitoring specific logging."""
    
    health_logger = logging.getLogger('sandbox.health')
    health_logger.setLevel(logging.INFO)
    
    # Health metrics log
    health_handler = logging.handlers.RotatingFileHandler(
        '/var/log/sandbox/health.log',
        maxBytes=5 * 1024 * 1024,  # 5MB
        backupCount=5
    )
    
    health_formatter = logging.Formatter(
        '%(asctime)s - HEALTH - %(message)s'
    )
    health_handler.setFormatter(health_formatter)
    health_logger.addHandler(health_handler)
    
    return health_logger


def setup_audit_logging() -> logging.Logger:
    """Set up audit trail logging for compliance."""
    
    audit_logger = logging.getLogger('sandbox.audit')
    audit_logger.setLevel(logging.INFO)
    
    # Audit log with extensive retention
    audit_handler = logging.handlers.RotatingFileHandler(
        '/var/log/sandbox/audit.log',
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=100  # Keep more audit logs
    )
    
    audit_formatter = SandboxLogFormatter()
    audit_handler.setFormatter(audit_formatter)
    audit_logger.addHandler(audit_handler)
    
    return audit_logger


class SandboxLogger:
    """Centralized logging manager for sandbox components."""
    
    def __init__(self, component_name: str, worker_id: str = None):
        self.component_name = component_name
        self.worker_id = worker_id or os.getenv('WORKER_ID', 'unknown')
        
        # Set up log directory
        self.log_dir = Path('/var/log/sandbox')
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize loggers
        self.main_logger = self._setup_main_logger()
        self.security_logger = setup_security_logging()
        self.health_logger = setup_health_monitoring_logging()
        self.audit_logger = setup_audit_logging()
        
        # Set up structured logging
        setup_structured_logging()
        self.struct_logger = structlog.get_logger(component_name)
    
    def _setup_main_logger(self) -> logging.Logger:
        """Set up the main component logger."""
        logger = logging.getLogger(f'sandbox.{self.component_name}')
        logger.setLevel(logging.INFO)
        
        # Component-specific log file
        handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f'{self.component_name}.log',
            maxBytes=20 * 1024 * 1024,  # 20MB
            backupCount=10
        )
        handler.setFormatter(SandboxLogFormatter())
        logger.addHandler(handler)
        
        return logger
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        kwargs.update({'worker_id': self.worker_id})
        self.struct_logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        kwargs.update({'worker_id': self.worker_id})
        self.struct_logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        kwargs.update({'worker_id': self.worker_id})
        self.struct_logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        kwargs.update({'worker_id': self.worker_id})
        self.struct_logger.critical(message, **kwargs)
    
    def security_event(self, event_type: str, message: str, severity: str = 'medium', **kwargs):
        """Log security event."""
        kwargs.update({
            'worker_id': self.worker_id,
            'event_type': event_type,
            'severity': severity,
            'security_event': True
        })
        
        # Log to security logger
        self.security_logger.warning(message, extra=kwargs)
        
        # Also log to structured logger
        self.struct_logger.warning(f"SECURITY: {message}", **kwargs)
    
    def audit_event(self, action: str, resource: str, result: str, **kwargs):
        """Log audit event."""
        kwargs.update({
            'worker_id': self.worker_id,
            'action': action,
            'resource': resource,
            'result': result,
            'audit_event': True
        })
        
        message = f"AUDIT: {action} on {resource} - {result}"
        self.audit_logger.info(message, extra=kwargs)
    
    def health_metric(self, metric_name: str, value: float, unit: str = None, **kwargs):
        """Log health metric."""
        kwargs.update({
            'worker_id': self.worker_id,
            'metric_name': metric_name,
            'metric_value': value,
            'metric_unit': unit
        })
        
        message = f"METRIC: {metric_name}={value}"
        if unit:
            message += f" {unit}"
        
        self.health_logger.info(message, extra=kwargs)


def configure_container_logging():
    """Configure logging for container environment."""
    
    # Set up log directory
    log_dir = Path('/var/log/sandbox')
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Set log level from environment
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Configure Python logging
    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.handlers.RotatingFileHandler(
                log_dir / 'container.log',
                maxBytes=10 * 1024 * 1024,
                backupCount=5
            )
        ]
    )
    
    # Set up structured logging
    setup_structured_logging(log_level)
    
    # Create symbolic links for Docker log collection
    try:
        stdout_link = log_dir / 'stdout.log'
        stderr_link = log_dir / 'stderr.log'
        
        if not stdout_link.exists():
            stdout_link.symlink_to('/proc/1/fd/1')
        if not stderr_link.exists():
            stderr_link.symlink_to('/proc/1/fd/2')
    except Exception:
        # Symbolic links may not be supported
        pass


if __name__ == "__main__":
    # Initialize logging for the container
    configure_container_logging()
    
    # Test logging
    logger = SandboxLogger('test')
    logger.info("Sandbox logging system initialized")
    logger.security_event('test_event', 'Test security event', severity='low')
    logger.audit_event('test_action', 'test_resource', 'success')
    logger.health_metric('test_metric', 42.0, 'units')
    
    print("Logging setup complete!")
