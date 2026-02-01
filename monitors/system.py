"""
System monitoring components for ACARS.
"""

import asyncio
import logging
import time
import socket
import subprocess
import psutil
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import ssl
import smtplib
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor

from core.system import ThreatEvent, AttackType, ThreatLevel


class NetworkMonitor:
    """Monitors network traffic and connections."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.monitor.network")
        self.monitoring = False
        self.connection_threshold = config.get('connection_threshold', 1000)
        self.port_scan_threshold = config.get('port_scan_threshold', 50)
        
        # Track connection patterns
        self.connection_history = {}
        self.port_scan_detection = {}
        
    async def start_monitoring(self):
        """Start network monitoring."""
        self.monitoring = True
        self.logger.info("Starting network monitoring")
        
        # Start multiple monitoring tasks
        tasks = [
            self._monitor_connections(),
            self._monitor_port_scans(),
            self._monitor_bandwidth()
        ]
        
        await asyncio.gather(*tasks)
        
    async def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring = False
        self.logger.info("Network monitoring stopped")
        
    async def _monitor_connections(self):
        """Monitor network connections."""
        while self.monitoring:
            try:
                # Get current network connections
                connections = psutil.net_connections()
                
                # Group by IP
                ip_connections = {}
                for conn in connections:
                    if conn.raddr and conn.raddr.ip:
                        ip = conn.raddr.ip
                        if ip not in ip_connections:
                            ip_connections[ip] = 0
                        ip_connections[ip] += 1
                        
                # Check for suspicious connection patterns
                for ip, count in ip_connections.items():
                    if count > self.connection_threshold:
                        # Detect potential DDoS
                        threat = ThreatEvent(
                            id=f"ddos_{ip}_{int(time.time())}",
                            timestamp=datetime.now(),
                            source_ip=ip,
                            target_system='network',
                            attack_type=AttackType.DDOS,
                            threat_level=ThreatLevel.HIGH,
                            confidence=0.8,
                            description=f"High connection count detected: {count} connections",
                            raw_data={'connections': count, 'ip': ip},
                            tags=['ddos', 'network']
                        )
                        await self._handle_threat(threat)
                        
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring connections: {e}")
                await asyncio.sleep(10)
                
    async def _monitor_port_scans(self):
        """Monitor for port scanning activity."""
        while self.monitoring:
            try:
                # Get netstat data
                result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                
                # Analyze connection patterns
                ip_port_access = {}
                
                for line in lines:
                    if 'ESTABLISHED' in line or 'SYN_SENT' in line or 'SYN_RECV' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            local_addr = parts[3]
                            remote_addr = parts[4]
                            
                            if ':' in remote_addr:
                                ip = remote_addr.split(':')[0]
                                port = remote_addr.split(':')[-1]
                                
                                if ip not in ip_port_access:
                                    ip_port_access[ip] = set()
                                ip_port_access[ip].add(port)
                                
                # Detect port scanning
                for ip, ports in ip_port_access.items():
                    if len(ports) > self.port_scan_threshold:
                        threat = ThreatEvent(
                            id=f"port_scan_{ip}_{int(time.time())}",
                            timestamp=datetime.now(),
                            source_ip=ip,
                            target_system='network',
                            attack_type=AttackType.PORT_SCAN,
                            threat_level=ThreatLevel.MEDIUM,
                            confidence=0.7,
                            description=f"Port scan detected: {len(ports)} ports accessed",
                            raw_data={'ports': list(ports), 'count': len(ports)},
                            tags=['port_scan', 'reconnaissance']
                        )
                        await self._handle_threat(threat)
                        
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error monitoring port scans: {e}")
                await asyncio.sleep(30)
                
    async def _monitor_bandwidth(self):
        """Monitor network bandwidth usage."""
        try:
            previous_stats = psutil.net_io_counters()
            
            while self.monitoring:
                await asyncio.sleep(60)  # Check every minute
                
                current_stats = psutil.net_io_counters()
                
                # Calculate bandwidth usage
                bytes_sent_rate = (current_stats.bytes_sent - previous_stats.bytes_sent) / 60
                bytes_recv_rate = (current_stats.bytes_recv - previous_stats.bytes_recv) / 60
                
                # Check for unusual bandwidth usage (over 100 MB/s)
                bandwidth_threshold = 100 * 1024 * 1024  # 100 MB/s
                
                if bytes_sent_rate > bandwidth_threshold or bytes_recv_rate > bandwidth_threshold:
                    threat = ThreatEvent(
                        id=f"bandwidth_{int(time.time())}",
                        timestamp=datetime.now(),
                        source_ip='unknown',
                        target_system='network',
                        attack_type=AttackType.DDOS,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.6,
                        description=f"High bandwidth usage detected: {bytes_recv_rate / (1024*1024):.2f} MB/s received",
                        raw_data={
                            'bytes_sent_rate': bytes_sent_rate,
                            'bytes_recv_rate': bytes_recv_rate
                        },
                        tags=['bandwidth', 'ddos']
                    )
                    await self._handle_threat(threat)
                    
                previous_stats = current_stats
                
        except Exception as e:
            self.logger.error(f"Error monitoring bandwidth: {e}")
            
    async def _handle_threat(self, threat: ThreatEvent):
        """Handle detected threat."""
        # This would integrate with the main ACARS system
        self.logger.warning(f"Network threat detected: {threat.description}")
        # In a real implementation, this would put the threat in the processing queue


class WebServerMonitor:
    """Monitors web server logs and traffic."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.monitor.webserver")
        self.monitoring = False
        self.log_files = config.get('log_files', ['/var/log/nginx/access.log', '/var/log/apache2/access.log'])
        self.request_threshold = config.get('request_threshold', 1000)
        self.error_threshold = config.get('error_threshold', 100)
        
        # Track request patterns
        self.request_history = {}
        
    async def start_monitoring(self):
        """Start web server monitoring."""
        self.monitoring = True
        self.logger.info("Starting web server monitoring")
        
        tasks = [
            self._monitor_log_files(),
            self._monitor_request_rates(),
            self._monitor_error_rates()
        ]
        
        await asyncio.gather(*tasks)
        
    async def stop_monitoring(self):
        """Stop web server monitoring."""
        self.monitoring = False
        self.logger.info("Web server monitoring stopped")
        
    async def _monitor_log_files(self):
        """Monitor web server access logs."""
        import tailer
        
        while self.monitoring:
            for log_file in self.log_files:
                try:
                    if os.path.exists(log_file):
                        # Use tailer to follow log file
                        for line in tailer.follow(open(log_file)):
                            await self._analyze_log_line(line)
                except Exception as e:
                    self.logger.error(f"Error monitoring log file {log_file}: {e}")
                    
            await asyncio.sleep(1)
            
    async def _analyze_log_line(self, line: str):
        """Analyze individual log line."""
        try:
            # Simple log parsing (you'd want to use proper parsing for your log format)
            parts = line.split()
            if len(parts) >= 8:
                source_ip = parts[0]
                timestamp = ' '.join(parts[3:5]).strip('[')
                method = parts[5].strip('"')
                url = parts[6]
                status_code = int(parts[8]) if parts[8].isdigit() else 0
                
                # Track requests per IP
                current_minute = datetime.now().replace(second=0, microsecond=0)
                
                if source_ip not in self.request_history:
                    self.request_history[source_ip] = {}
                    
                if current_minute not in self.request_history[source_ip]:
                    self.request_history[source_ip][current_minute] = 0
                    
                self.request_history[source_ip][current_minute] += 1
                
                # Check for high request rates
                request_count = self.request_history[source_ip][current_minute]
                if request_count > self.request_threshold:
                    threat = ThreatEvent(
                        id=f"high_requests_{source_ip}_{current_minute}",
                        timestamp=datetime.now(),
                        source_ip=source_ip,
                        target_system='web_server',
                        attack_type=AttackType.DDOS,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        description=f"High request rate detected: {request_count} requests/minute",
                        raw_data={'request_count': request_count, 'url': url},
                        tags=['high_requests', 'ddos']
                    )
                    await self._handle_threat(threat)
                    
                # Check for suspicious URLs
                suspicious_patterns = ['sql', 'script', 'union', 'select', 'drop', 'exec']
                url_lower = url.lower()
                
                for pattern in suspicious_patterns:
                    if pattern in url_lower:
                        threat = ThreatEvent(
                            id=f"suspicious_url_{source_ip}_{int(time.time())}",
                            timestamp=datetime.now(),
                            source_ip=source_ip,
                            target_system='web_server',
                            attack_type=AttackType.SQL_INJECTION if 'sql' in pattern else AttackType.XSS,
                            threat_level=ThreatLevel.HIGH,
                            confidence=0.7,
                            description=f"Suspicious URL pattern detected: {pattern}",
                            raw_data={'url': url, 'pattern': pattern},
                            tags=['suspicious_url', 'web_attack']
                        )
                        await self._handle_threat(threat)
                        break
                        
                # Check for error codes (potential attacks)
                if status_code in [401, 403, 500, 502, 503]:
                    threat = ThreatEvent(
                        id=f"error_code_{source_ip}_{status_code}_{int(time.time())}",
                        timestamp=datetime.now(),
                        source_ip=source_ip,
                        target_system='web_server',
                        attack_type=AttackType.UNKNOWN,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.6,
                        description=f"Server error detected: HTTP {status_code}",
                        raw_data={'status_code': status_code, 'url': url},
                        tags=['server_error']
                    )
                    await self._handle_threat(threat)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing log line: {e}")
            
    async def _monitor_request_rates(self):
        """Monitor overall request rates."""
        while self.monitoring:
            try:
                # Calculate total requests per minute
                current_minute = datetime.now().replace(second=0, microsecond=0)
                total_requests = 0
                
                for ip_requests in self.request_history.values():
                    total_requests += ip_requests.get(current_minute, 0)
                    
                # Clean old data
                cutoff = current_minute - timedelta(minutes=10)
                for ip in self.request_history:
                    self.request_history[ip] = {
                        minute: count for minute, count in self.request_history[ip].items()
                        if minute > cutoff
                    }
                    
                # Check for global rate limiting
                global_threshold = self.request_threshold * 10  # 10x individual threshold
                if total_requests > global_threshold:
                    threat = ThreatEvent(
                        id=f"global_rate_{current_minute}",
                        timestamp=datetime.now(),
                        source_ip='multiple',
                        target_system='web_server',
                        attack_type=AttackType.DDOS,
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.9,
                        description=f"Global high request rate: {total_requests} requests/minute",
                        raw_data={'total_requests': total_requests},
                        tags=['global_ddos', 'high_load']
                    )
                    await self._handle_threat(threat)
                    
                await asyncio.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Error monitoring request rates: {e}")
                await asyncio.sleep(60)
                
    async def _monitor_error_rates(self):
        """Monitor server error rates."""
        while self.monitoring:
            try:
                # This would typically check error logs
                # For now, we'll simulate error rate monitoring
                
                # Check if web servers are responding
                for server_config in self.config.get('servers', []):
                    url = server_config.get('url')
                    if url:
                        try:
                            response = requests.get(url, timeout=10)
                            
                            if response.status_code >= 500:
                                threat = ThreatEvent(
                                    id=f"server_error_{url}_{int(time.time())}",
                                    timestamp=datetime.now(),
                                    source_ip='server_internal',
                                    target_system='web_server',
                                    attack_type=AttackType.UNKNOWN,
                                    threat_level=ThreatLevel.MEDIUM,
                                    confidence=0.8,
                                    description=f"Server error: HTTP {response.status_code}",
                                    raw_data={'url': url, 'status_code': response.status_code},
                                    tags=['server_error', 'availability']
                                )
                                await self._handle_threat(threat)
                                
                        except Exception as e:
                            threat = ThreatEvent(
                                id=f"server_down_{url}_{int(time.time())}",
                                timestamp=datetime.now(),
                                source_ip='server_internal',
                                target_system='web_server',
                                attack_type=AttackType.UNKNOWN,
                                threat_level=ThreatLevel.HIGH,
                                confidence=0.9,
                                description=f"Server unreachable: {str(e)}",
                                raw_data={'url': url, 'error': str(e)},
                                tags=['server_down', 'availability']
                            )
                            await self._handle_threat(threat)
                            
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring error rates: {e}")
                await asyncio.sleep(300)
                
    async def _handle_threat(self, threat: ThreatEvent):
        """Handle detected threat."""
        self.logger.warning(f"Web server threat detected: {threat.description}")


class DatabaseMonitor:
    """Monitors database activity for attacks."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.monitor.database")
        self.monitoring = False
        self.connection_threshold = config.get('connection_threshold', 100)
        self.query_threshold = config.get('query_threshold', 1000)
        
    async def start_monitoring(self):
        """Start database monitoring."""
        self.monitoring = True
        self.logger.info("Starting database monitoring")
        
        tasks = [
            self._monitor_connections(),
            self._monitor_slow_queries(),
            self._monitor_failed_logins()
        ]
        
        await asyncio.gather(*tasks)
        
    async def stop_monitoring(self):
        """Stop database monitoring."""
        self.monitoring = False
        self.logger.info("Database monitoring stopped")
        
    async def _monitor_connections(self):
        """Monitor database connections."""
        # This would integrate with database-specific monitoring
        # For now, we'll simulate connection monitoring
        
        while self.monitoring:
            try:
                # Simulate checking database connections
                # In reality, you'd query your database for connection stats
                
                threat = ThreatEvent(
                    id=f"db_connection_{int(time.time())}",
                    timestamp=datetime.now(),
                    source_ip='unknown',
                    target_system='database',
                    attack_type=AttackType.BRUTE_FORCE,
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.6,
                    description="Database connection monitoring active",
                    raw_data={'monitoring': 'active'},
                    tags=['database', 'monitoring']
                )
                await self._handle_threat(threat)
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring database connections: {e}")
                await asyncio.sleep(300)
                
    async def _monitor_slow_queries(self):
        """Monitor for slow queries (potential attacks)."""
        while self.monitoring:
            try:
                # Simulate slow query detection
                # In reality, you'd check database query logs
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring slow queries: {e}")
                await asyncio.sleep(60)
                
    async def _monitor_failed_logins(self):
        """Monitor database login failures."""
        while self.monitoring:
            try:
                # Simulate failed login monitoring
                # In reality, you'd check database authentication logs
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring failed logins: {e}")
                await asyncio.sleep(60)
                
    async def _handle_threat(self, threat: ThreatEvent):
        """Handle detected threat."""
        self.logger.warning(f"Database threat detected: {threat.description}")


class SystemMonitor:
    """Monitors system resources and processes."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger("acars.monitor.system")
        self.monitoring = False
        self.cpu_threshold = config.get('cpu_threshold', 90)
        self.memory_threshold = config.get('memory_threshold', 90)
        self.disk_threshold = config.get('disk_threshold', 95)
        
    async def start_monitoring(self):
        """Start system monitoring."""
        self.monitoring = True
        self.logger.info("Starting system monitoring")
        
        tasks = [
            self._monitor_resources(),
            self._monitor_processes(),
            self._monitor_file_changes()
        ]
        
        await asyncio.gather(*tasks)
        
    async def stop_monitoring(self):
        """Stop system monitoring."""
        self.monitoring = False
        self.logger.info("System monitoring stopped")
        
    async def _monitor_resources(self):
        """Monitor system resources."""
        while self.monitoring:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.cpu_threshold:
                    threat = ThreatEvent(
                        id=f"high_cpu_{int(time.time())}",
                        timestamp=datetime.now(),
                        source_ip='system_internal',
                        target_system='server',
                        attack_type=AttackType.UNKNOWN,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.7,
                        description=f"High CPU usage detected: {cpu_percent}%",
                        raw_data={'cpu_percent': cpu_percent},
                        tags=['high_cpu', 'performance']
                    )
                    await self._handle_threat(threat)
                    
                # Memory usage
                memory = psutil.virtual_memory()
                if memory.percent > self.memory_threshold:
                    threat = ThreatEvent(
                        id=f"high_memory_{int(time.time())}",
                        timestamp=datetime.now(),
                        source_ip='system_internal',
                        target_system='server',
                        attack_type=AttackType.UNKNOWN,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.7,
                        description=f"High memory usage detected: {memory.percent}%",
                        raw_data={'memory_percent': memory.percent, 'available_gb': memory.available / (1024**3)},
                        tags=['high_memory', 'performance']
                    )
                    await self._handle_threat(threat)
                    
                # Disk usage
                disk = psutil.disk_usage('/')
                if (disk.percent) > self.disk_threshold:
                    threat = ThreatEvent(
                        id=f"high_disk_{int(time.time())}",
                        timestamp=datetime.now(),
                        source_ip='system_internal',
                        target_system='server',
                        attack_type=AttackType.UNKNOWN,
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        description=f"High disk usage detected: {disk.percent}%",
                        raw_data={'disk_percent': disk.percent, 'free_gb': disk.free / (1024**3)},
                        tags=['high_disk', 'storage']
                    )
                    await self._handle_threat(threat)
                    
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error monitoring resources: {e}")
                await asyncio.sleep(60)
                
    async def _monitor_processes(self):
        """Monitor suspicious processes."""
        while self.monitoring:
            try:
                # Get all running processes
                suspicious_processes = []
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        
                        # Check for suspicious process names
                        suspicious_names = ['nc', 'netcat', 'ncat', 'tcpdump', 'wireshark', 'nmap']
                        if proc_info['name'] in suspicious_names:
                            suspicious_processes.append(proc_info)
                            
                        # Check for high resource usage
                        if proc_info.get('cpu_percent', 0) > 90 or proc_info.get('memory_percent', 0) > 90:
                            suspicious_processes.append(proc_info)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                if suspicious_processes:
                    threat = ThreatEvent(
                        id=f"suspicious_processes_{int(time.time())}",
                        timestamp=datetime.now(),
                        source_ip='system_internal',
                        target_system='server',
                        attack_type=AttackType.UNKNOWN,
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.6,
                        description=f"Suspicious processes detected: {len(suspicious_processes)} processes",
                        raw_data={'processes': suspicious_processes},
                        tags=['suspicious_processes', 'system']
                    )
                    await self._handle_threat(threat)
                    
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring processes: {e}")
                await asyncio.sleep(300)
                
    async def _monitor_file_changes(self):
        """Monitor critical file changes."""
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/ssh/sshd_config',
            '/etc/sudoers',
            '/etc/hosts'
        ]
        
        file_hashes = {}
        
        while self.monitoring:
            try:
                for file_path in critical_files:
                    if os.path.exists(file_path):
                        # Calculate file hash
                        with open(file_path, 'rb') as f:
                            current_hash = hashlib.md5(f.read()).hexdigest()
                            
                        if file_path in file_hashes:
                            if file_hashes[file_path] != current_hash:
                                threat = ThreatEvent(
                                    id=f"file_modified_{file_path}_{int(time.time())}",
                                    timestamp=datetime.now(),
                                    source_ip='system_internal',
                                    target_system='server',
                                    attack_type=AttackType.UNKNOWN,
                                    threat_level=ThreatLevel.HIGH,
                                    confidence=0.9,
                                    description=f"Critical file modified: {file_path}",
                                    raw_data={'file_path': file_path, 'old_hash': file_hashes[file_path], 'new_hash': current_hash},
                                    tags=['file_modification', 'integrity']
                                )
                                await self._handle_threat(threat)
                        else:
                            file_hashes[file_path] = current_hash
                            
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error monitoring file changes: {e}")
                await asyncio.sleep(300)
                
    async def _handle_threat(self, threat: ThreatEvent):
        """Handle detected threat."""
        self.logger.warning(f"System threat detected: {threat.description}")


import os
import hashlib
import tailer