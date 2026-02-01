"""
Response action handlers for ACARS.
"""

import logging
import asyncio
import subprocess
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import socket
import shutil
import os
import tempfile
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

from core.system import ResponseActionHandler, ResponseResult, ThreatEvent, ResponseAction


class LogHandler(ResponseActionHandler):
    """Logs threat events to various outputs."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("log_handler", config)
        self.log_format = config.get('format', 'json')
        self.log_file = config.get('file', '/var/log/acars/threats.log')
        self.syslog_enabled = config.get('syslog_enabled', False)
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
    async def execute(self, threat: ThreatEvent) -> ResponseResult:
        """Log threat event."""
        try:
            if self.log_format == 'json':
                log_entry = json.dumps(threat.to_dict(), indent=2)
            else:
                log_entry = f"[{threat.timestamp}] {threat.threat_level.value.upper()}: {threat.description}"
                
            # Write to file
            with open(self.log_file, 'a') as f:
                f.write(log_entry + '\n')
                
            # Log to system logger if enabled
            if self.syslog_enabled:
                self.logger.warning(f"THREAT: {threat.attack_type.value} from {threat.source_ip}")
                
            return ResponseResult(
                success=True,
                action=ResponseAction.LOG_ONLY,
                timestamp=datetime.now(),
                message="Threat logged successfully",
                details={'log_file': self.log_entry}
            )
            
        except Exception as e:
            return ResponseResult(
                success=False,
                action=ResponseAction.LOG_ONLY,
                timestamp=datetime.now(),
                message=f"Failed to log threat: {str(e)}",
                details={'error': str(e)}
            )


class AlertHandler(ResponseActionHandler):
    """Sends alerts for threat events."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("alert_handler", config)
        self.alert_channels = config.get('channels', ['console'])
        self.escalation_delay = config.get('escalation_delay', 300)  # 5 minutes
        
    async def execute(self, threat: ThreatEvent) -> ResponseResult:
        """Send alert notifications."""
        try:
            alert_data = {
                'threat_id': threat.id,
                'timestamp': threat.timestamp.isoformat(),
                'source_ip': threat.source_ip,
                'attack_type': threat.attack_type.value,
                'threat_level': threat.threat_level.value,
                'description': threat.description,
                'confidence': threat.confidence
            }
            
            # Send to configured channels
            for channel in self.alert_channels:
                await self._send_alert_channel(channel, alert_data)
                
            return ResponseResult(
                success=True,
                action=ResponseAction.ALERT,
                timestamp=datetime.now(),
                message="Alert sent successfully",
                details={'channels': self.alert_channels}
            )
            
        except Exception as e:
            return ResponseResult(
                success=False,
                action=ResponseAction.ALERT,
                timestamp=datetime.now(),
                message=f"Failed to send alert: {str(e)}",
                details={'error': str(e)}
            )
            
    async def _send_alert_channel(self, channel: str, data: Dict[str, Any]):
        """Send alert to specific channel."""
        if channel == 'console':
            self.logger.warning(f"SECURITY ALERT: {data['attack_type']} detected from {data['source_ip']}")
        elif channel == 'email':
            await self._send_email_alert(data)
        elif channel == 'slack':
            await self._send_slack_alert(data)
        elif channel == 'webhook':
            await self._send_webhook_alert(data)
            
    async def _send_email_alert(self, data: Dict[str, Any]):
        """Send email alert."""
        email_config = self.config.get('email', {})
        if not email_config.get('enabled', False):
            return
            
        try:
            msg = MimeMultipart()
            msg['From'] = email_config['username']
            msg['To'] = ', '.join(email_config['recipients'])
            msg['Subject'] = f"Security Alert: {data['attack_type']} from {data['source_ip']}"
            
            body = f"""
Security Threat Detected:

Threat ID: {data['threat_id']}
Timestamp: {data['timestamp']}
Source IP: {data['source_ip']}
Attack Type: {data['attack_type']}
Threat Level: {data['threat_level']}
Confidence: {data['confidence']}

Description: {data['description']}

This is an automated alert from ACARS.
            """
            
            msg.attach(MimeText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            text = msg.as_string()
            server.sendmail(email_config['username'], email_config['recipients'], text)
            server.quit()
            
            self.logger.info("Email alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            
    async def _send_slack_alert(self, data: Dict[str, Any]):
        """Send Slack alert."""
        slack_config = self.config.get('slack', {})
        if not slack_config.get('enabled', False):
            return
            
        try:
            import requests
            
            webhook_url = slack_config['webhook_url']
            payload = {
                'channel': slack_config.get('channel', '#security'),
                'username': 'ACARS Alert',
                'text': f":warning: Security Alert: {data['attack_type']} from {data['source_ip']}",
                'attachments': [
                    {
                        'color': 'danger',
                        'fields': [
                            {'title': 'Threat Level', 'value': data['threat_level'], 'short': True},
                            {'title': 'Confidence', 'value': str(data['confidence']), 'short': True},
                            {'title': 'Description', 'value': data['description'], 'short': False}
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload)
            response.raise_for_status()
            self.logger.info("Slack alert sent successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            
    async def _send_webhook_alert(self, data: Dict[str, Any]):
        """Send webhook alert."""
        webhook_config = self.config.get('webhook', {})
        if not webhook_config.get('enabled', False):
            return
            
        try:
            import requests
            
            urls = webhook_config.get('urls', [])
            timeout = webhook_config.get('timeout', 30)
            
            for url in urls:
                response = requests.post(url, json=data, timeout=timeout)
                response.raise_for_status()
                
            self.logger.info(f"Webhook alerts sent to {len(urls)} endpoints")
            
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")


class BlockIPHandler(ResponseActionHandler):
    """Blocks malicious IP addresses."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("block_ip_handler", config)
        self.firewall_types = config.get('firewall_types', ['iptables'])
        self.block_duration = config.get('duration', 3600)  # 1 hour
        self.blocked_ips = set()
        
    async def execute(self, threat: ThreatEvent) -> ResponseResult:
        """Block the source IP address."""
        try:
            source_ip = threat.source_ip
            
            # Check if already blocked
            if source_ip in self.blocked_ips:
                return ResponseResult(
                    success=True,
                    action=ResponseAction.BLOCK_IP,
                    timestamp=datetime.now(),
                    message=f"IP {source_ip} already blocked",
                    details={'ip': source_ip}
                )
                
            # Block using configured firewalls
            blocked = False
            for firewall_type in self.firewall_types:
                if await self._block_with_firewall(source_ip, firewall_type):
                    blocked = True
                    
            if blocked:
                self.blocked_ips.add(source_ip)
                
                # Schedule unblock after duration
                asyncio.create_task(self._schedule_unblock(source_ip))
                
                return ResponseResult(
                    success=True,
                    action=ResponseAction.BLOCK_IP,
                    timestamp=datetime.now(),
                    message=f"IP {source_ip} blocked successfully",
                    details={'ip': source_ip, 'firewalls': self.firewall_types}
                )
            else:
                return ResponseResult(
                    success=False,
                    action=ResponseAction.BLOCK_IP,
                    timestamp=datetime.now(),
                    message=f"Failed to block IP {source_ip}",
                    details={'ip': source_ip}
                )
                
        except Exception as e:
            return ResponseResult(
                success=False,
                action=ResponseAction.BLOCK_IP,
                timestamp=datetime.now(),
                message=f"Error blocking IP: {str(e)}",
                details={'error': str(e)}
            )
            
    async def _block_with_firewall(self, ip: str, firewall_type: str) -> bool:
        """Block IP using specific firewall."""
        try:
            if firewall_type == 'iptables':
                return await self._block_with_iptables(ip)
            elif firewall_type == 'ufw':
                return await self._block_with_ufw(ip)
            elif firewall_type == 'pf':
                return await self._block_with_pf(ip)
            else:
                self.logger.warning(f"Unknown firewall type: {firewall_type}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error blocking with {firewall_type}: {e}")
            return False
            
    async def _block_with_iptables(self, ip: str) -> bool:
        """Block IP using iptables."""
        try:
            # Check if running as root
            if os.geteuid() != 0:
                self.logger.error("iptables blocking requires root privileges")
                return False
                
            # Add iptables rule
            cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"Blocked IP {ip} with iptables")
                return True
            else:
                self.logger.error(f"iptables command failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error with iptables: {e}")
            return False
            
    async def _block_with_ufw(self, ip: str) -> bool:
        """Block IP using UFW."""
        try:
            if os.geteuid() != 0:
                self.logger.error("UFW blocking requires root privileges")
                return False
                
            cmd = ['ufw', 'insert', '1', 'deny', 'from', ip]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error with UFW: {e}")
            return False
            
    async def _block_with_pf(self, ip: str) -> bool:
        """Block IP using PF (Packet Filter)."""
        try:
            if os.geteuid() != 0:
                self.logger.error("PF blocking requires root privileges")
                return False
                
            # PF rule syntax
            pf_rule = f"block in from {ip} to any"
            cmd = ['pfctl', '-t', 'blocked_ips', '-T', 'add', ip]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return result.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Error with PF: {e}")
            return False
            
    async def _schedule_unblock(self, ip: str):
        """Schedule unblocking of IP after duration."""
        await asyncio.sleep(self.block_duration)
        
        for firewall_type in self.firewall_types:
            await self._unblock_with_firewall(ip, firewall_type)
            
        self.blocked_ips.discard(ip)
        self.logger.info(f"Unblocked IP {ip} after {self.block_duration} seconds")
        
    async def _unblock_with_firewall(self, ip: str, firewall_type: str):
        """Unblock IP using specific firewall."""
        try:
            if firewall_type == 'iptables':
                cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            elif firewall_type == 'ufw':
                cmd = ['ufw', 'delete', 'deny', 'from', ip]
            elif firewall_type == 'pf':
                cmd = ['pfctl', '-t', 'blocked_ips', '-T', 'delete', ip]
            else:
                return
                
            subprocess.run(cmd, capture_output=True)
            
        except Exception as e:
            self.logger.error(f"Error unblocking with {firewall_type}: {e}")


class QuarantineSystemHandler(ResponseActionHandler):
    """Quarantines compromised systems."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("quarantine_system_handler", config)
        self.isolation_timeout = config.get('isolation_timeout', 1800)  # 30 minutes
        
    async def execute(self, threat: ThreatEvent) -> ResponseResult:
        """Quarantine the target system."""
        try:
            target_system = threat.target_system
            
            # Create quarantine directory
            quarantine_dir = f"/tmp/acars_quarantine_{target_system}_{int(time.time())}"
            os.makedirs(quarantine_dir, exist_ok=True)
            
            # Actions to perform
            actions_taken = []
            
            # 1. Create backup of system state
            backup_file = await self._create_system_backup(target_system, quarantine_dir)
            if backup_file:
                actions_taken.append(f"backup_created:{backup_file}")
                
            # 2. Network isolation
            if self.config.get('network_isolation', True):
                isolated = await self._isolate_network(target_system)
                if isolated:
                    actions_taken.append("network_isolated")
                    
            # 3. Service isolation
            if self.config.get('service_isolation', True):
                services_stopped = await self._isolate_services(target_system)
                if services_stopped:
                    actions_taken.append(f"services_isolated:{services_stopped}")
                    
            # 4. File system scan
            if self.config.get('file_system_scan', True):
                scan_result = await self._scan_file_system(target_system, quarantine_dir)
                if scan_result:
                    actions_taken.append(f"scan_completed:{scan_result}")
                    
            # Schedule automatic dequarantine
            asyncio.create_task(self._schedule_dequarantine(target_system, quarantine_dir))
            
            return ResponseResult(
                success=True,
                action=ResponseAction.QUARANTINE_SYSTEM,
                timestamp=datetime.now(),
                message=f"System {target_system} quarantined successfully",
                details={
                    'target_system': target_system,
                    'quarantine_dir': quarantine_dir,
                    'actions_taken': actions_taken
                }
            )
            
        except Exception as e:
            return ResponseResult(
                success=False,
                action=ResponseAction.QUARANTINE_SYSTEM,
                timestamp=datetime.now(),
                message=f"Error quarantining system: {str(e)}",
                details={'error': str(e)}
            )
            
    async def _create_system_backup(self, system: str, quarantine_dir: str) -> Optional[str]:
        """Create backup of system state."""
        try:
            backup_file = os.path.join(quarantine_dir, f"{system}_backup_{int(time.time())}.tar.gz")
            
            # Create backup of critical system files
            backup_dirs = ['/etc', '/var/log', '/var/www', '/home']
            cmd = ['tar', '-czf', backup_file] + backup_dirs
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return backup_file
            else:
                self.logger.error(f"Backup failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return None
            
    async def _isolate_network(self, system: str) -> bool:
        """Isolate system from network."""
        try:
            if os.geteuid() != 0:
                self.logger.error("Network isolation requires root privileges")
                return False
                
            # Block all outgoing and incoming traffic except SSH
            cmd = ['iptables', '-A', 'INPUT', '-j', 'DROP']
            subprocess.run(cmd, capture_output=True)
            
            cmd = ['iptables', '-A', 'OUTPUT', '-j', 'DROP']
            subprocess.run(cmd, capture_output=True)
            
            # Allow SSH for remote management
            cmd = ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT']
            subprocess.run(cmd, capture_output=True)
            
            cmd = ['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--sport', '22', '-j', 'ACCEPT']
            subprocess.run(cmd, capture_output=True)
            
            self.logger.info(f"Network isolated for system {system}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error isolating network: {e}")
            return False
            
    async def _isolate_services(self, system: str) -> List[str]:
        """Isolate system services."""
        try:
            # Services to potentially isolate
            services = ['apache2', 'nginx', 'mysql', 'postgresql', 'redis', 'mongodb']
            stopped_services = []
            
            for service in services:
                try:
                    cmd = ['systemctl', 'stop', service]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        stopped_services.append(service)
                        self.logger.info(f"Stopped service {service}")
                        
                except Exception as e:
                    self.logger.error(f"Error stopping service {service}: {e}")
                    
            return stopped_services
            
        except Exception as e:
            self.logger.error(f"Error isolating services: {e}")
            return []
            
    async def _scan_file_system(self, system: str, quarantine_dir: str) -> Optional[str]:
        """Perform file system scan for malware."""
        try:
            # Create a simple file scan report
            scan_report = os.path.join(quarantine_dir, f"scan_report_{int(time.time())}.txt")
            
            with open(scan_report, 'w') as f:
                f.write(f"File system scan report for {system}\n")
                f.write(f"Timestamp: {datetime.now()}\n\n")
                
                # Basic file integrity check
                f.write("Critical files check:\n")
                critical_files = ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/ssh/sshd_config']
                
                for file_path in critical_files:
                    if os.path.exists(file_path):
                        stat = os.stat(file_path)
                        f.write(f"{file_path}: exists, modified {stat.st_mtime}\n")
                    else:
                        f.write(f"{file_path}: MISSING\n")
                        
            return scan_report
            
        except Exception as e:
            self.logger.error(f"Error scanning file system: {e}")
            return None
            
    async def _schedule_dequarantine(self, system: str, quarantine_dir: str):
        """Schedule automatic dequarantine after timeout."""
        await asyncio.sleep(self.isolation_timeout)
        
        # Restore network access
        try:
            if os.geteuid() == 0:
                # Clear iptables rules
                subprocess.run(['iptables', '-F'], capture_output=True)
                subprocess.run(['iptables', '-X'], capture_output=True)
                
            # Restart services
            services = ['apache2', 'nginx', 'mysql', 'postgresql', 'redis', 'mongodb']
            for service in services:
                try:
                    subprocess.run(['systemctl', 'start', service], capture_output=True)
                except:
                    pass
                    
            # Clean up quarantine directory
            if os.path.exists(quarantine_dir):
                shutil.rmtree(quarantine_dir)
                
            self.logger.info(f"System {system} automatically dequarantined")
            
        except Exception as e:
            self.logger.error(f"Error during automatic dequarantine: {e}")


class EmergencyShutdownHandler(ResponseActionHandler):
    """Emergency system shutdown handler."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("emergency_handler", config)
        self.shutdown_timeout = config.get('shutdown_timeout', 60)
        
    async def execute(self, threat: ThreatEvent) -> ResponseResult:
        """Perform emergency shutdown of affected systems."""
        try:
            # Log emergency shutdown attempt
            self.logger.critical(f"EMERGENCY SHUTDOWN INITIATED for {threat.target_system}")
            
            # Perform graceful shutdown
            await self._emergency_shutdown(threat.target_system)
            
            return ResponseResult(
                success=True,
                action=ResponseAction.EMERGENCY_SHUTDOWN,
                timestamp=datetime.now(),
                message=f"Emergency shutdown completed for {threat.target_system}",
                details={'target_system': threat.target_system}
            )
            
        except Exception as e:
            return ResponseResult(
                success=False,
                action=ResponseAction.EMERGENCY_SHUTDOWN,
                timestamp=datetime.now(),
                message=f"Error during emergency shutdown: {str(e)}",
                details={'error': str(e)}
            )
            
    async def _emergency_shutdown(self, system: str):
        """Perform the actual emergency shutdown."""
        try:
            if os.geteuid() != 0:
                self.logger.error("Emergency shutdown requires root privileges")
                return
                
            # Wait for cleanup
            await asyncio.sleep(5)
            
            # Force immediate shutdown
            cmd = ['shutdown', '-h', 'now']
            subprocess.run(cmd)
            
        except Exception as e:
            self.logger.error(f"Error during emergency shutdown: {e}")
            # Fallback: try immediate poweroff
            try:
                subprocess.run(['poweroff', '-f'], capture_output=True)
            except:
                pass