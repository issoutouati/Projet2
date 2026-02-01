"""
Configuration management for ACARS.
Handles loading and validation of system configurations.
"""

import yaml
import os
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigManager:
    """Manages system configuration for ACARS."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "/home/engine/project/config/config.yaml"
        self._config = None
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if not os.path.exists(self.config_path):
            self._create_default_config()
            
        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f)
            
        return self._config
    
    def _create_default_config(self) -> None:
        """Create default configuration file."""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        default_config = {
            'system': {
                'name': 'ACARS',
                'version': '1.0.0',
                'log_level': 'INFO',
                'max_workers': 10,
                'backup_retention_days': 30
            },
            'monitoring': {
                'enabled_protocols': ['http', 'https', 'ssh', 'ftp', 'smtp', 'tcp'],
                'check_interval': 10,  # seconds
                'retention_period': 86400,  # 24 hours in seconds
                'metrics_collection': True
            },
            'detection': {
                'threat_levels': {
                    'low': {'threshold': 1, 'response': 'log'},
                    'medium': {'threshold': 5, 'response': 'alert'},
                    'high': {'threshold': 10, 'response': 'block'},
                    'critical': {'threshold': 20, 'response': 'emergency'}
                },
                'attack_patterns': {
                    'sql_injection': {
                        'patterns': [
                            "union select",
                            "drop table",
                            "insert into",
                            "delete from",
                            "update set"
                        ],
                        'severity': 'high'
                    },
                    'xss': {
                        'patterns': [
                            "<script",
                            "javascript:",
                            "onload=",
                            "onerror="
                        ],
                        'severity': 'medium'
                    },
                    'ddos': {
                        'threshold': 100,  # requests per minute
                        'severity': 'critical'
                    },
                    'brute_force': {
                        'threshold': 10,  # failed attempts per minute
                        'severity': 'high'
                    }
                }
            },
            'response': {
                'actions': {
                    'block_ip': {
                        'enabled': True,
                        'duration': 3600,  # 1 hour
                        'firewall_rule': True
                    },
                    'quarantine_system': {
                        'enabled': True,
                        'network_isolation': True,
                        'file_system_scan': True
                    },
                    'disable_account': {
                        'enabled': True,
                        'admin_notification': True,
                        'session_termination': True
                    },
                    'service_restart': {
                        'enabled': True,
                        'backup_state': True,
                        'rollback_time': 300  # 5 minutes
                    }
                },
                'escalation': {
                    'auto_escalate': True,
                    'escalation_timeout': 1800,  # 30 minutes
                    'escalation_contacts': []
                }
            },
            'integrations': {
                'firewalls': {
                    'iptables': {'enabled': False},
                    'ufw': {'enabled': False},
                    'pf': {'enabled': False}
                },
                'cloud_services': {
                    'aws': {
                        'enabled': False,
                        'region': 'us-east-1',
                        'services': ['waf', 'security_hub', 'guardduty']
                    },
                    'azure': {
                        'enabled': False,
                        'services': ['sentinel', 'defender', 'firewall']
                    },
                    'gcp': {
                        'enabled': False,
                        'services': ['security_command', 'firewall', 'ids']
                    }
                },
                'siem': {
                    'splunk': {'enabled': False, 'url': '', 'token': ''},
                    'elk': {'enabled': False, 'url': '', 'username': ''},
                    'arcsight': {'enabled': False, 'url': ''}
                },
                'notifications': {
                    'email': {
                        'enabled': False,
                        'smtp_server': '',
                        'smtp_port': 587,
                        'username': '',
                        'password': '',
                        'recipients': []
                    },
                    'slack': {
                        'enabled': False,
                        'webhook_url': '',
                        'channel': '#security'
                    },
                    'webhook': {
                        'enabled': False,
                        'urls': [],
                        'timeout': 30
                    }
                }
            },
            'ml': {
                'enabled': True,
                'model_retrain_interval': 86400,  # 24 hours
                'anomaly_detection': {
                    'enabled': True,
                    'sensitivity': 0.8,
                    'min_samples': 100
                },
                'threat_classification': {
                    'enabled': True,
                    'confidence_threshold': 0.7
                }
            }
        }
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        if self._config is None:
            self.load_config()
            
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation."""
        if self._config is None:
            self.load_config()
            
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
        
        # Save to file
        with open(self.config_path, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False)
    
    def validate(self) -> bool:
        """Validate configuration settings."""
        if self._config is None:
            self.load_config()
            
        # Basic validation checks
        required_sections = ['system', 'monitoring', 'detection', 'response']
        
        for section in required_sections:
            if section not in self._config:
                raise ValueError(f"Missing required configuration section: {section}")
                
        # Validate numeric values
        if self._config['monitoring']['check_interval'] <= 0:
            raise ValueError("check_interval must be positive")
            
        return True


# Global configuration instance
config = ConfigManager()