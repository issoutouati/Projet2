"""
Core system classes for ACARS.
"""

import logging
import asyncio
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import threading
import queue
import uuid


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Types of cyber attacks."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    PORT_SCAN = "port_scan"
    BUFFER_OVERFLOW = "buffer_overflow"
    CSRF = "csrf"
    FILE_INCLUSION = "file_inclusion"
    UNKNOWN = "unknown"


class ResponseAction(Enum):
    """Available response actions."""
    LOG_ONLY = "log"
    ALERT = "alert"
    BLOCK_IP = "block_ip"
    QUARANTINE_SYSTEM = "quarantine_system"
    DISABLE_ACCOUNT = "disable_account"
    RESTART_SERVICE = "restart_service"
    ISOLATE_NETWORK = "isolate_network"
    BACKUP_DATA = "backup_data"
    NOTIFY_ADMIN = "notify_admin"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"


@dataclass
class ThreatEvent:
    """Represents a detected threat event."""
    id: str
    timestamp: datetime
    source_ip: str
    target_system: str
    attack_type: AttackType
    threat_level: ThreatLevel
    confidence: float
    description: str
    raw_data: Dict[str, Any]
    tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['attack_type'] = self.attack_type.value
        data['threat_level'] = self.threat_level.value
        return data


@dataclass
class ResponseResult:
    """Result of a response action."""
    success: bool
    action: ResponseAction
    timestamp: datetime
    message: str
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['action'] = self.action.value
        return data


class ThreatDetector:
    """Base class for threat detection modules."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"acars.detector.{name}")
        self.enabled = config.get('enabled', True)
        
    def detect(self, data: Any) -> Optional[ThreatEvent]:
        """Analyze data and return threat event if detected."""
        raise NotImplementedError
        
    def get_attack_types(self) -> List[AttackType]:
        """Return list of attack types this detector can identify."""
        raise NotImplementedError


class ResponseActionHandler:
    """Base class for response action handlers."""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.logger = logging.getLogger(f"acars.response.{name}")
        self.enabled = config.get('enabled', True)
        
    async def execute(self, threat: ThreatEvent) -> ResponseResult:
        """Execute response action for a threat."""
        raise NotImplementedError


class EventBus:
    """Internal event bus for component communication."""
    
    def __init__(self):
        self._subscribers = {}
        self._lock = threading.Lock()
        
    def subscribe(self, event_type: str, callback):
        """Subscribe to an event type."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)
            
    def publish(self, event_type: str, data: Any):
        """Publish an event to subscribers."""
        with self._lock:
            callbacks = self._subscribers.get(event_type, [])
            
        for callback in callbacks:
            try:
                callback(data)
            except Exception as e:
                logging.error(f"Error in event callback: {e}")


class ACARSCore:
    """Main ACARS system class."""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.event_bus = EventBus()
        self.detectors: Dict[str, ThreatDetector] = {}
        self.response_handlers: Dict[str, ResponseActionHandler] = {}
        self.threat_queue = queue.Queue()
        self.running = False
        self.logger = logging.getLogger("acars.core")
        
        # Statistics
        self.stats = {
            'threats_detected': 0,
            'responses_executed': 0,
            'uptime_start': None,
            'last_activity': None
        }
        
    def register_detector(self, detector: ThreatDetector):
        """Register a threat detector."""
        self.detectors[detector.name] = detector
        self.logger.info(f"Registered detector: {detector.name}")
        
    def register_response_handler(self, handler: ResponseActionHandler):
        """Register a response action handler."""
        self.response_handlers[handler.name] = handler
        self.logger.info(f"Registered response handler: {handler.name}")
        
    async def process_threat(self, threat: ThreatEvent) -> List[ResponseResult]:
        """Process a detected threat and execute appropriate responses."""
        self.stats['threats_detected'] += 1
        self.stats['last_activity'] = datetime.now()
        
        self.logger.warning(f"Threat detected: {threat.attack_type.value} from {threat.source_ip}")
        
        # Determine response actions based on threat level
        threat_config = self.config_manager.get(f'detection.threat_levels.{threat.threat_level.value}')
        if not threat_config:
            self.logger.error(f"No response configuration for threat level: {threat.threat_level.value}")
            return []
            
        response_type = threat_config.get('response')
        
        # Map response types to handlers
        response_map = {
            'log': ['log_handler'],
            'alert': ['log_handler', 'alert_handler'],
            'block': ['log_handler', 'alert_handler', 'block_ip_handler'],
            'emergency': ['log_handler', 'alert_handler', 'block_ip_handler', 'emergency_handler']
        }
        
        handler_names = response_map.get(response_type, ['log_handler'])
        results = []
        
        for handler_name in handler_names:
            if handler_name in self.response_handlers:
                try:
                    result = await self.response_handlers[handler_name].execute(threat)
                    results.append(result)
                    if result.success:
                        self.stats['responses_executed'] += 1
                except Exception as e:
                    self.logger.error(f"Error executing response handler {handler_name}: {e}")
                    
        return results
        
    async def start(self):
        """Start the ACARS system."""
        self.running = True
        self.stats['uptime_start'] = datetime.now()
        
        self.logger.info("Starting ACARS system...")
        
        # Start threat processing worker
        asyncio.create_task(self._threat_processor())
        
        # Start detectors
        for detector in self.detectors.values():
            if detector.enabled:
                asyncio.create_task(self._run_detector(detector))
                
        self.logger.info("ACARS system started successfully")
        
    async def stop(self):
        """Stop the ACARS system."""
        self.running = False
        self.logger.info("Stopping ACARS system...")
        
    async def _threat_processor(self):
        """Process threats from the queue."""
        while self.running:
            try:
                threat = self.threat_queue.get(timeout=1.0)
                await self.process_threat(threat)
                self.threat_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing threat: {e}")
                
    async def _run_detector(self, detector: ThreatDetector):
        """Run a threat detector."""
        check_interval = self.config_manager.get('monitoring.check_interval', 10)
        
        while self.running:
            try:
                # Simulate data collection (this would be replaced with actual monitoring)
                threat = detector.detect(None)
                if threat:
                    self.threat_queue.put(threat)
                    
                await asyncio.sleep(check_interval)
            except Exception as e:
                self.logger.error(f"Error in detector {detector.name}: {e}")
                await asyncio.sleep(check_interval)
                
    def get_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        stats = self.stats.copy()
        if stats['uptime_start']:
            uptime = datetime.now() - stats['uptime_start']
            stats['uptime_seconds'] = uptime.total_seconds()
        return stats