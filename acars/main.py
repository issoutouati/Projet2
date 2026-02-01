#!/usr/bin/env python3
"""
Main entry point for ACARS (Automated Cyber Attack Response System).
"""

import asyncio
import logging
import signal
import sys
import os
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.system import ACARSCore, AttackType, ThreatLevel
from config.config_manager import ConfigManager
from detectors.web_attacks import WebAttackDetector, DDoSDetector, BruteForceDetector
from responders.actions import (
    LogHandler, AlertHandler, BlockIPHandler, 
    QuarantineSystemHandler, EmergencyShutdownHandler
)
from monitors.system import NetworkMonitor, WebServerMonitor, DatabaseMonitor, SystemMonitor
from ml.engine import MLThreatDetectionEngine
from integrations.cloud import IntegrationManager


class ACARSApplication:
    """Main application class for ACARS."""
    
    def __init__(self):
        self.config_manager = ConfigManager()
        self.core = None
        self.running = False
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger("acars.main")
        
        self.logger.info("ACARS starting up...")
        
    def _setup_logging(self):
        """Setup logging configuration."""
        log_level = self.config_manager.get('system.log_level', 'INFO')
        
        # Create logs directory
        log_dir = Path('/var/log/acars')
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_dir / 'acars.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
    async def initialize(self):
        """Initialize all ACARS components."""
        try:
            self.logger.info("Initializing ACARS components...")
            
            # Load configuration
            config = self.config_manager.load_config()
            self.config_manager.validate()
            
            # Initialize core system
            self.core = ACARSCore(self.config_manager)
            
            # Initialize and register detectors
            await self._initialize_detectors()
            
            # Initialize and register response handlers
            await self._initialize_response_handlers()
            
            # Initialize monitoring components
            await self._initialize_monitors()
            
            # Initialize ML engine
            await self._initialize_ml_engine()
            
            # Initialize integrations
            await self._initialize_integrations()
            
            self.logger.info("ACARS initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ACARS: {e}")
            raise
            
    async def _initialize_detectors(self):
        """Initialize threat detection modules."""
        detection_config = self.config_manager.get('detection', {})
        
        # Web attack detector
        web_config = detection_config.get('attack_patterns', {})
        web_detector = WebAttackDetector(web_config)
        self.core.register_detector(web_detector)
        
        # DDoS detector
        ddos_config = detection_config.get('attack_patterns', {}).get('ddos', {})
        ddos_detector = DDoSDetector(ddos_config)
        self.core.register_detector(ddos_detector)
        
        # Brute force detector
        brute_config = detection_config.get('attack_patterns', {}).get('brute_force', {})
        brute_detector = BruteForceDetector(brute_config)
        self.core.register_detector(brute_detector)
        
        self.logger.info(f"Initialized {len(self.core.detectors)} detectors")
        
    async def _initialize_response_handlers(self):
        """Initialize response action handlers."""
        response_config = self.config_manager.get('response', {})
        actions_config = response_config.get('actions', {})
        
        # Log handler (always enabled)
        log_config = {'enabled': True}
        log_handler = LogHandler(log_config)
        self.core.register_response_handler(log_handler)
        
        # Alert handler
        alert_config = actions_config.get('alert_handler', {})
        alert_handler = AlertHandler(alert_config)
        self.core.register_response_handler(alert_handler)
        
        # Block IP handler
        block_config = actions_config.get('block_ip', {})
        if block_config.get('enabled', False):
            block_handler = BlockIPHandler(block_config)
            self.core.register_response_handler(block_handler)
            
        # Quarantine system handler
        quarantine_config = actions_config.get('quarantine_system', {})
        if quarantine_config.get('enabled', False):
            quarantine_handler = QuarantineSystemHandler(quarantine_config)
            self.core.register_response_handler(quarantine_handler)
            
        # Emergency shutdown handler (high risk, disabled by default)
        emergency_config = actions_config.get('emergency_handler', {})
        if emergency_config.get('enabled', False):
            emergency_handler = EmergencyShutdownHandler(emergency_config)
            self.core.register_response_handler(emergency_handler)
            
        self.logger.info(f"Initialized {len(self.core.response_handlers)} response handlers")
        
    async def _initialize_monitors(self):
        """Initialize monitoring components."""
        monitoring_config = self.config_manager.get('monitoring', {})
        
        # Network monitor
        network_monitor = NetworkMonitor(monitoring_config)
        
        # Web server monitor
        web_monitor = WebServerMonitor(monitoring_config)
        
        # Database monitor
        db_monitor = DatabaseMonitor(monitoring_config)
        
        # System monitor
        system_monitor = SystemMonitor(monitoring_config)
        
        # Store monitors for later use
        self.monitors = {
            'network': network_monitor,
            'web': web_monitor,
            'database': db_monitor,
            'system': system_monitor
        }
        
        self.logger.info("Initialized monitoring components")
        
    async def _initialize_ml_engine(self):
        """Initialize machine learning components."""
        ml_config = self.config_manager.get('ml', {})
        
        if ml_config.get('enabled', True):
            self.ml_engine = MLThreatDetectionEngine(ml_config)
            self.logger.info("ML threat detection engine initialized")
        else:
            self.ml_engine = None
            self.logger.info("ML engine disabled")
            
    async def _initialize_integrations(self):
        """Initialize third-party integrations."""
        integrations_config = self.config_manager.get('integrations', {})
        
        if integrations_config:
            self.integration_manager = IntegrationManager(integrations_config)
            self.logger.info("Integration manager initialized")
        else:
            self.integration_manager = None
            self.logger.info("Integrations disabled")
            
    async def start(self):
        """Start the ACARS system."""
        try:
            self.running = True
            self.logger.info("Starting ACARS system...")
            
            # Start core system
            await self.core.start()
            
            # Start monitoring components
            if hasattr(self, 'monitors'):
                monitor_tasks = []
                for monitor_name, monitor in self.monitors.items():
                    if monitor:
                        task = asyncio.create_task(monitor.start_monitoring())
                        monitor_tasks.append(task)
                        
                if monitor_tasks:
                    await asyncio.gather(*monitor_tasks)
                    
            self.logger.info("ACARS system started successfully")
            
            # Main monitoring loop
            await self._monitoring_loop()
            
        except Exception as e:
            self.logger.error(f"Error in ACARS start: {e}")
            raise
            
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        self.logger.info("Entering monitoring loop...")
        
        # Simulation of threat detection for demonstration
        while self.running:
            try:
                # Simulate threat detection (in real implementation, this would come from monitors)
                await self._simulate_threat_detection()
                
                # Sleep for monitoring interval
                check_interval = self.config_manager.get('monitoring.check_interval', 10)
                await asyncio.sleep(check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(10)
                
    async def _simulate_threat_detection(self):
        """Simulate threat detection for demonstration purposes."""
        import random
        
        # Simulate various threats
        threats = [
            {
                'url': '/api/users?id=1 UNION SELECT * FROM users',
                'method': 'GET',
                'source_ip': '192.168.1.100',
                'target': 'web_server'
            },
            {
                'url': '/search?q=<script>alert("xss")</script>',
                'method': 'GET',
                'source_ip': '10.0.0.50',
                'target': 'web_server'
            },
            {
                'source_ip': '203.0.113.1',
                'target': 'network',
                'connection_count': 500
            },
            {
                'source_ip': '198.51.100.25',
                'target': 'auth_service',
                'failed_login': True
            }
        ]
        
        # Randomly simulate threats
        if random.random() < 0.1:  # 10% chance of threat
            threat_data = random.choice(threats)
            
            # Create threat event
            from core.system import ThreatEvent
            threat = ThreatEvent(
                id=f"sim_{int(datetime.now().timestamp())}",
                timestamp=datetime.now(),
                source_ip=threat_data.get('source_ip', 'unknown'),
                target_system=threat_data.get('target', 'system'),
                attack_type=random.choice([AttackType.SQL_INJECTION, AttackType.XSS, AttackType.DDOS, AttackType.BRUTE_FORCE]),
                threat_level=random.choice([ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]),
                confidence=random.uniform(0.6, 0.9),
                description="Simulated threat for testing",
                raw_data=threat_data,
                tags=['simulation', 'test']
            )
            
            # Process threat through ML engine if available
            if self.ml_engine:
                ml_results = await self.ml_engine.analyze_threat(threat.to_dict())
                threat.description += f" | ML Analysis: {ml_results.get('classification', {}).get('predicted_type', 'unknown')}"
                
            # Add to threat queue for processing
            self.core.threat_queue.put(threat)
            
    async def stop(self):
        """Stop the ACARS system."""
        self.running = False
        self.logger.info("Stopping ACARS system...")
        
        try:
            # Stop core system
            if self.core:
                await self.core.stop()
                
            # Stop monitoring components
            if hasattr(self, 'monitors'):
                for monitor_name, monitor in self.monitors.items():
                    if monitor and hasattr(monitor, 'stop_monitoring'):
                        await monitor.stop_monitoring()
                        
            self.logger.info("ACARS stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping ACARS: {e}")
            
    async def get_status(self) -> Dict[str, Any]:
        """Get system status information."""
        status = {
            'running': self.running,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'uptime': None,
            'detectors': {},
            'response_handlers': {},
            'monitors': {},
            'statistics': {}
        }
        
        if self.core:
            # Core statistics
            stats = self.core.get_stats()
            status['statistics'] = stats
            
            # Detectors status
            for name, detector in self.core.detectors.items():
                status['detectors'][name] = {
                    'enabled': detector.enabled,
                    'attack_types': [at.value for at in detector.get_attack_types()]
                }
                
            # Response handlers status
            for name, handler in self.core.response_handlers.items():
                status['response_handlers'][name] = {
                    'enabled': handler.enabled
                }
                
        # Monitors status
        if hasattr(self, 'monitors'):
            for name, monitor in self.monitors.items():
                if monitor:
                    status['monitors'][name] = {
                        'monitoring': getattr(monitor, 'monitoring', False)
                    }
                    
        # ML engine status
        if self.ml_engine:
            status['ml_engine'] = self.ml_engine.get_model_performance()
            
        return status


async def main():
    """Main entry point."""
    app = ACARSApplication()
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger = logging.getLogger("acars.main")
        logger.info(f"Received signal {signum}, shutting down...")
        app.running = False
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize and start the application
        await app.initialize()
        await app.start()
        
    except KeyboardInterrupt:
        logger = logging.getLogger("acars.main")
        logger.info("Received keyboard interrupt")
        
    except Exception as e:
        logger = logging.getLogger("acars.main")
        logger.error(f"Application error: {e}")
        
    finally:
        await app.stop()


if __name__ == "__main__":
    # Check if running as root for certain operations
    if os.geteuid() == 0:
        print("ACARS running with root privileges - full functionality available")
    else:
        print("ACARS running without root privileges - some features limited")
        
    # Run the application
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nACARS shutdown completed")
    except Exception as e:
        print(f"ACARS failed to start: {e}")
        sys.exit(1)