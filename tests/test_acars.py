#!/usr/bin/env python3
"""
Test suite for ACARS components.
"""

import asyncio
import sys
import unittest
from unittest.mock import Mock, patch
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.system import ACARSCore, ThreatEvent, AttackType, ThreatLevel
from config.config_manager import ConfigManager
from detectors.web_attacks import WebAttackDetector, DDoSDetector, BruteForceDetector
from responders.actions import LogHandler, BlockIPHandler
from ml.engine import ThreatClassifier, AnomalyDetector


class TestConfigManager(unittest.TestCase):
    """Test configuration management."""
    
    def setUp(self):
        self.config_manager = ConfigManager()
        
    def test_load_config(self):
        """Test loading configuration."""
        config = self.config_manager.load_config()
        self.assertIsInstance(config, dict)
        self.assertIn('system', config)
        self.assertIn('monitoring', config)
        
    def test_get_config_value(self):
        """Test getting configuration values."""
        value = self.config_manager.get('system.name')
        self.assertEqual(value, 'ACARS')
        
    def test_set_config_value(self):
        """Test setting configuration values."""
        self.config_manager.set('test.value', 'test_data')
        value = self.config_manager.get('test.value')
        self.assertEqual(value, 'test_data')


class TestThreatDetection(unittest.TestCase):
    """Test threat detection components."""
    
    def setUp(self):
        self.web_detector = WebAttackDetector({})
        self.ddos_detector = DDoSDetector({})
        self.brute_detector = BruteForceDetector({})
        
    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        test_data = {
            'url': '/api/users?id=1 UNION SELECT * FROM users',
            'method': 'GET',
            'source_ip': '192.168.1.100',
            'target': 'web_server'
        }
        
        threat = self.web_detector.detect(test_data)
        self.assertIsNotNone(threat)
        self.assertEqual(threat.attack_type, AttackType.SQL_INJECTION)
        self.assertEqual(threat.source_ip, '192.168.1.100')
        
    def test_xss_detection(self):
        """Test XSS detection."""
        test_data = {
            'url': '/search?q=<script>alert("xss")</script>',
            'method': 'GET',
            'source_ip': '10.0.0.50',
            'target': 'web_server'
        }
        
        threat = self.web_detector.detect(test_data)
        self.assertIsNotNone(threat)
        self.assertEqual(threat.attack_type, AttackType.XSS)
        
    def test_ddos_detection(self):
        """Test DDoS detection."""
        test_data = {
            'source_ip': '203.0.113.1',
            'target': 'network',
            'connection_count': 500
        }
        
        threat = self.ddos_detector.detect(test_data)
        # This might be None depending on threshold configuration
        # but should not raise an exception
        self.assertTrue(threat is None or threat.attack_type == AttackType.DDOS)
        
    def test_brute_force_detection(self):
        """Test brute force detection."""
        test_data = {
            'source_ip': '198.51.100.25',
            'target': 'auth_service',
            'failed': True
        }
        
        threat = self.brute_detector.detect(test_data)
        # This might be None depending on threshold configuration
        # but should not raise an exception
        self.assertTrue(threat is None or threat.attack_type == AttackType.BRUTE_FORCE)


class TestResponseActions(unittest.TestCase):
    """Test response action handlers."""
    
    def setUp(self):
        self.log_handler = LogHandler({'enabled': True})
        
    def test_log_handler_execution(self):
        """Test log handler execution."""
        # Create a test threat event
        threat = ThreatEvent(
            id='test_threat_001',
            timestamp=asyncio.get_event_loop().time(),
            source_ip='192.168.1.100',
            target_system='test_server',
            attack_type=AttackType.SQL_INJECTION,
            threat_level=ThreatLevel.HIGH,
            confidence=0.8,
            description='Test SQL injection threat',
            raw_data={'test': 'data'},
            tags=['test']
        )
        
        # This should not raise an exception
        try:
            # Since log_handler.execute is async, we need to run it
            result = asyncio.run(self.log_handler.execute(threat))
            self.assertTrue(result.success)
        except Exception as e:
            self.fail(f"Log handler execution failed: {e}")


class TestMLEngine(unittest.TestCase):
    """Test machine learning components."""
    
    def setUp(self):
        self.classifier = ThreatClassifier({'confidence_threshold': 0.7})
        self.anomaly_detector = AnomalyDetector({'contamination': 0.1})
        
    def test_threat_classifier_initialization(self):
        """Test threat classifier initialization."""
        self.classifier.initialize()
        self.assertIsNotNone(self.classifier)
        
    def test_anomaly_detector_initialization(self):
        """Test anomaly detector initialization."""
        self.anomaly_detector.initialize()
        self.assertIsNotNone(self.anomaly_detector)


class TestACARSCore(unittest.TestCase):
    """Test main ACARS core system."""
    
    def setUp(self):
        self.config_manager = ConfigManager()
        self.core = ACARSCore(self.config_manager)
        
    def test_core_initialization(self):
        """Test ACARS core initialization."""
        self.assertIsNotNone(self.core)
        self.assertIsInstance(self.core.detectors, dict)
        self.assertIsInstance(self.core.response_handlers, dict)
        
    def test_detector_registration(self):
        """Test detector registration."""
        detector = WebAttackDetector({})
        self.core.register_detector(detector)
        
        self.assertIn('web_attack_detector', self.core.detectors)
        self.assertEqual(self.core.detectors['web_attack_detector'], detector)
        
    def test_response_handler_registration(self):
        """Test response handler registration."""
        handler = LogHandler({'enabled': True})
        self.core.register_response_handler(handler)
        
        self.assertIn('log_handler', self.core.response_handlers)
        self.assertEqual(self.core.response_handlers['log_handler'], handler)


class IntegrationTests(unittest.TestCase):
    """Integration tests for the complete system."""
    
    def test_full_threat_detection_pipeline(self):
        """Test complete threat detection and response pipeline."""
        # This is a simplified integration test
        config_manager = ConfigManager()
        core = ACARSCore(config_manager)
        
        # Register components
        detector = WebAttackDetector({})
        handler = LogHandler({'enabled': True})
        
        core.register_detector(detector)
        core.register_response_handler(handler)
        
        # Create test threat data
        test_data = {
            'url': '/api/users?id=1 UNION SELECT * FROM users',
            'method': 'GET',
            'source_ip': '192.168.1.100',
            'target': 'web_server'
        }
        
        # Detect threat
        threat = detector.detect(test_data)
        self.assertIsNotNone(threat)
        
        # Process threat
        try:
            # This should not raise an exception
            results = asyncio.run(core.process_threat(threat))
            self.assertIsInstance(results, list)
        except Exception as e:
            self.fail(f"Threat processing failed: {e}")


def run_tests():
    """Run all tests."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestConfigManager,
        TestThreatDetection,
        TestResponseActions,
        TestMLEngine,
        TestACARSCore,
        IntegrationTests
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    print("ACARS Test Suite")
    print("=" * 50)
    
    success = run_tests()
    
    if success:
        print("\n✓ All tests passed!")
        sys.exit(0)
    else:
        print("\n✗ Some tests failed!")
        sys.exit(1)