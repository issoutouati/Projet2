#!/usr/bin/env python3
"""
ACARS - Automated Cyber Attack Response System
"""

__version__ = "1.0.0"
__author__ = "ACARS Development Team"
__email__ = "dev@acars.example.com"
__description__ = "Automated Cyber Attack Response System"

from core.system import ACARSCore, ThreatEvent, AttackType, ThreatLevel
from ml.engine import MLThreatDetectionEngine

__all__ = [
    "ACARSCore",
    "ThreatEvent", 
    "AttackType",
    "ThreatLevel",
    "MLThreatDetectionEngine",
    "__version__"
]