"""
Web application attack detectors.
"""

import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import hashlib

from core.system import ThreatDetector, ThreatEvent, AttackType, ThreatLevel


class WebAttackDetector(ThreatDetector):
    """Detects web application attacks (SQL injection, XSS, etc.)."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("web_attack_detector", config)
        
        # SQL injection patterns
        self.sql_patterns = [
            r"(?i)(\bunion\b\s+\bselect\b)",
            r"(?i)(\bdrop\b\s+\btable\b)",
            r"(?i)(\binsert\b\s+into\b)",
            r"(?i)(\bdelete\b\s+from\b)",
            r"(?i)(\bupdate\b\s+\w+\s+set\b)",
            r"(?i)(\bor\b\s+1=1\b)",
            r"(?i)(\band\b\s+1=1\b)",
            r"(?i)(--\s*$)",
            r"(?i)(/\*.*?\*/)",
            r"(?i)(\bexec\b\s*\()",
            r"(?i)(\bexecute\b\s*\()",
            r"(?i)(\bsp_executesql\b)",
            r"(?i)(\bxp_cmdshell\b)",
            r"(?i)(\binformation_schema\b)",
            r"(?i)(\bmysql\.user\b)",
            r"(?i)(\bsys\.user_tables\b)"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(?i)(<script[^>]*>.*?</script>)",
            r"(?i)(javascript:)",
            r"(?i)(on\w+\s*=",
            r"(?i)(<iframe[^>]*>.*?</iframe>)",
            r"(?i)(<object[^>]*>.*?</object>)",
            r"(?i)(<embed[^>]*>.*?</embed>)",
            r"(?i)(<link[^>]*>)",
            r"(?i)(<style[^>]*>.*?</style>)",
            r"(?i)(<meta[^>]*>)",
            r"(?i)(<img[^>]*src\s*=\s*['\"]?javascript:)",
            r"(?i)(document\.cookie)",
            r"(?i)(document\.location)",
            r"(?i)(document\.domain)"
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"....//",
            r"....\\\\"
        ]
        
        # Command injection patterns
        self.command_injection_patterns = [
            r"[;&|`$(){}[\]]",
            r"\b(curl|wget|nc|netcat|telnet|ssh|ftp)\b",
            r"\b(bash|sh|cmd|powershell)\b",
            r"\b(cat|ls|rm|cp|mv|chmod|chown)\b",
            r"\b(nmap|ping|traceroute)\b"
        ]
        
        self.compiled_sql = [re.compile(pattern) for pattern in self.sql_patterns]
        self.compiled_xss = [re.compile(pattern) for pattern in self.xss_patterns]
        self.compiled_traversal = [re.compile(pattern) for pattern in self.path_traversal_patterns]
        self.compiled_command = [re.compile(pattern) for pattern in self.command_injection_patterns]
        
        # Rate limiting
        self.request_history = {}
        
    def get_attack_types(self) -> List[AttackType]:
        return [
            AttackType.SQL_INJECTION,
            AttackType.XSS,
            AttackType.FILE_INCLUSION,
            AttackType.BUFFER_OVERFLOW
        ]
        
    def detect(self, data: Any) -> Optional[ThreatEvent]:
        """Analyze web request data for attack patterns."""
        if not data:
            return None
            
        try:
            # Extract request information
            if isinstance(data, dict):
                request_data = data
            else:
                request_data = {'url': str(data)}
                
            # Get request details
            url = request_data.get('url', '')
            method = request_data.get('method', 'GET')
            headers = request_data.get('headers', {})
            body = request_data.get('body', '')
            source_ip = request_data.get('source_ip', 'unknown')
            
            # Rate limiting check
            if self._is_rate_limited(source_ip):
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{datetime.now()}".encode()).hexdigest(),
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    target_system=request_data.get('target', 'web_server'),
                    attack_type=AttackType.DDOS,
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.9,
                    description="Rate limiting threshold exceeded",
                    raw_data=request_data,
                    tags=['rate_limiting', 'ddos']
                )
            
            # Check for attacks
            threats = []
            
            # SQL injection check
            sql_threat = self._check_sql_injection(url, body, source_ip)
            if sql_threat:
                threats.append(sql_threat)
                
            # XSS check
            xss_threat = self._check_xss(url, body, source_ip)
            if xss_threat:
                threats.append(xss_threat)
                
            # Path traversal check
            traversal_threat = self._check_path_traversal(url, body, source_ip)
            if traversal_threat:
                threats.append(traversal_threat)
                
            # Command injection check
            command_threat = self._check_command_injection(url, body, source_ip)
            if command_threat:
                threats.append(command_threat)
                
            # Return the first threat found (in practice, you might want to return all)
            return threats[0] if threats else None
            
        except Exception as e:
            self.logger.error(f"Error analyzing web request: {e}")
            return None
            
    def _check_sql_injection(self, url: str, body: str, source_ip: str) -> Optional[ThreatEvent]:
        """Check for SQL injection patterns."""
        combined_text = f"{url} {body}".lower()
        
        for pattern in self.compiled_sql:
            if pattern.search(combined_text):
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{datetime.now()}sql".encode()).hexdigest(),
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    target_system='web_application',
                    attack_type=AttackType.SQL_INJECTION,
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description=f"SQL injection attempt detected: {pattern.pattern}",
                    raw_data={'url': url, 'body': body},
                    tags=['sql_injection', 'web_attack']
                )
        return None
        
    def _check_xss(self, url: str, body: str, source_ip: str) -> Optional[ThreatEvent]:
        """Check for XSS patterns."""
        combined_text = f"{url} {body}".lower()
        
        for pattern in self.compiled_xss:
            if pattern.search(combined_text):
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{datetime.now()}xss".encode()).hexdigest(),
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    target_system='web_application',
                    attack_type=AttackType.XSS,
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    description=f"XSS attempt detected: {pattern.pattern}",
                    raw_data={'url': url, 'body': body},
                    tags=['xss', 'web_attack']
                )
        return None
        
    def _check_path_traversal(self, url: str, body: str, source_ip: str) -> Optional[ThreatEvent]:
        """Check for path traversal attempts."""
        combined_text = f"{url} {body}"
        
        for pattern in self.compiled_traversal:
            if pattern.search(combined_text):
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{datetime.now()}traversal".encode()).hexdigest(),
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    target_system='web_application',
                    attack_type=AttackType.FILE_INCLUSION,
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description="Path traversal attempt detected",
                    raw_data={'url': url, 'body': body},
                    tags=['path_traversal', 'file_inclusion', 'web_attack']
                )
        return None
        
    def _check_command_injection(self, url: str, body: str, source_ip: str) -> Optional[ThreatEvent]:
        """Check for command injection attempts."""
        combined_text = f"{url} {body}"
        
        for pattern in self.compiled_command:
            if pattern.search(combined_text):
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{datetime.now()}command".encode()).hexdigest(),
                    timestamp=datetime.now(),
                    source_ip=source_ip,
                    target_system='web_application',
                    attack_type=AttackType.BUFFER_OVERFLOW,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=0.7,
                    description="Command injection attempt detected",
                    raw_data={'url': url, 'body': body},
                    tags=['command_injection', 'buffer_overflow', 'web_attack']
                )
        return None
        
    def _is_rate_limited(self, source_ip: str) -> bool:
        """Check if IP should be rate limited."""
        now = datetime.now()
        minute_window = now.replace(second=0, microsecond=0)
        
        if source_ip not in self.request_history:
            self.request_history[source_ip] = {}
            
        if minute_window not in self.request_history[source_ip]:
            self.request_history[source_ip][minute_window] = 0
            
        self.request_history[source_ip][minute_window] += 1
        
        # Clean old entries
        cutoff = now - timedelta(minutes=10)
        self.request_history[source_ip] = {
            window: count for window, count in self.request_history[source_ip].items()
            if window > cutoff
        }
        
        # Check if threshold exceeded (100 requests per minute)
        current_minute_requests = self.request_history[source_ip].get(minute_window, 0)
        return current_minute_requests > 100


class DDoSDetector(ThreatDetector):
    """Detects Distributed Denial of Service attacks."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("ddos_detector", config)
        self.connection_tracker = {}
        
    def get_attack_types(self) -> List[AttackType]:
        return [AttackType.DDOS]
        
    def detect(self, data: Any) -> Optional[ThreatEvent]:
        """Analyze traffic for DDoS patterns."""
        if not data:
            return None
            
        try:
            request_data = data if isinstance(data, dict) else {'source_ip': str(data)}
            source_ip = request_data.get('source_ip', 'unknown')
            target = request_data.get('target', 'server')
            timestamp = datetime.now()
            
            # Track connection patterns
            if source_ip not in self.connection_tracker:
                self.connection_tracker[source_ip] = []
                
            self.connection_tracker[source_ip].append(timestamp)
            
            # Clean old entries (keep last 5 minutes)
            cutoff = timestamp - timedelta(minutes=5)
            self.connection_tracker[source_ip] = [
                ts for ts in self.connection_tracker[source_ip] if ts > cutoff
            ]
            
            # Check for DDoS patterns
            connection_count = len(self.connection_tracker[source_ip])
            threshold = self.config.get('threshold', 100)
            
            if connection_count > threshold:
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{timestamp}ddos".encode()).hexdigest(),
                    timestamp=timestamp,
                    source_ip=source_ip,
                    target_system=target,
                    attack_type=AttackType.DDOS,
                    threat_level=ThreatLevel.CRITICAL,
                    confidence=0.9,
                    description=f"DDoS attack detected: {connection_count} connections in 5 minutes",
                    raw_data=request_data,
                    tags=['ddos', 'high_volume']
                )
                
        except Exception as e:
            self.logger.error(f"Error in DDoS detection: {e}")
            
        return None


class BruteForceDetector(ThreatDetector):
    """Detects brute force attacks."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("brute_force_detector", config)
        self.failed_attempts = {}
        
    def get_attack_types(self) -> List[AttackType]:
        return [AttackType.BRUTE_FORCE]
        
    def detect(self, data: Any) -> Optional[ThreatEvent]:
        """Analyze login attempts for brute force patterns."""
        if not data:
            return None
            
        try:
            request_data = data if isinstance(data, dict) else {'event': str(data)}
            
            # Only process failed login attempts
            if not request_data.get('failed', False):
                return None
                
            source_ip = request_data.get('source_ip', 'unknown')
            target = request_data.get('target', 'auth_service')
            timestamp = datetime.now()
            
            # Track failed attempts per IP
            if source_ip not in self.failed_attempts:
                self.failed_attempts[source_ip] = []
                
            self.failed_attempts[source_ip].append(timestamp)
            
            # Clean old entries (keep last hour)
            cutoff = timestamp - timedelta(hours=1)
            self.failed_attempts[source_ip] = [
                ts for ts in self.failed_attempts[source_ip] if ts > cutoff
            ]
            
            # Check for brute force patterns
            attempt_count = len(self.failed_attempts[source_ip])
            threshold = self.config.get('threshold', 10)
            
            if attempt_count > threshold:
                return ThreatEvent(
                    id=hashlib.md5(f"{source_ip}{timestamp}brute".encode()).hexdigest(),
                    timestamp=timestamp,
                    source_ip=source_ip,
                    target_system=target,
                    attack_type=AttackType.BRUTE_FORCE,
                    threat_level=ThreatLevel.HIGH,
                    confidence=0.8,
                    description=f"Brute force attack detected: {attempt_count} failed attempts in 1 hour",
                    raw_data=request_data,
                    tags=['brute_force', 'authentication']
                )
                
        except Exception as e:
            self.logger.error(f"Error in brute force detection: {e}")
            
        return None