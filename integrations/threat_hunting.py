"""
Automated Threat Hunting System

Provides proactive threat hunting capabilities including automated hunts,
behavioral analysis, IOC correlation, and advanced threat detection.
"""

import asyncio
import logging
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib


class HuntType(Enum):
    BEHAVIORAL = "behavioral"
    IOC_CORRELATION = "ioc_correlation"
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE = "compliance"


class HuntStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class HuntingQuery:
    """Hunting query definition."""
    id: str
    name: str
    description: str
    query: str
    platform: str  # splunk, elk, qradar, snowflake, etc.
    hunt_type: HuntType
    severity_threshold: str
    tags: List[str]
    enabled: bool
    schedule: str  # cron-like expression or 'manual', 'daily', 'weekly'
    last_run: Optional[datetime]
    parameters: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


@dataclass
class HuntResult:
    """Result of a threat hunting operation."""
    hunt_id: str
    query_id: str
    timestamp: datetime
    status: HuntStatus
    findings: List[Dict[str, Any]]
    severity: str
    confidence: float
    execution_time: float
    records_analyzed: int
    threat_indicators: List[str]
    description: str
    recommendations: List[str]


@dataclass
class ThreatHypothesis:
    """Threat hunting hypothesis."""
    id: str
    name: str
    description: str
    hypothesis: str
    supporting_queries: List[str]
    kill_chain_phases: List[str]
    mitre_techniques: List[str]
    confidence_threshold: float
    evidence_found: int = 0
    last_updated: datetime = None


class ThreatHuntingEngine:
    """Core threat hunting engine."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize threat hunting engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Hunting data storage
        self.hunt_queries = {}
        self.hunt_results = []
        self.hypotheses = {}
        self.active_hunts = {}
        
        # Integration with other systems
        self.threat_intelligence = None  # Will be set externally
        self.siem_connections = {}  # SIEM platform connections
        
        # Predefined hunting queries
        self._initialize_predefined_queries()
        
        # Threat hypotheses
        self._initialize_threat_hypotheses()
        
    def _initialize_predefined_queries(self):
        """Initialize predefined threat hunting queries."""
        self.hunt_queries = {
            # Behavioral Analysis Queries
            'unusual_admin_activity': HuntingQuery(
                id='hunt_001',
                name='Unusual Administrative Activity',
                description='Detect unusual administrative activities that may indicate compromise',
                query='''
                index=security (EventCode=4624 OR EventCode=4625) 
                | eval hour=strftime(_time, "%H")
                | where UserType in ("2", "3") AND hour<6 OR hour>22
                | stats count by User, Source_IP, hour
                | where count > 5
                | eval risk_score=count*if(hour<6 OR hour>22, 2, 1)
                | where risk_score > 10
                | sort -risk_score
                ''',
                platform='splunk',
                hunt_type=HuntType.BEHAVIORAL,
                severity_threshold='medium',
                tags=['administrative', 'after_hours', 'privilege_abuse'],
                enabled=True,
                schedule='daily',
                last_run=None
            ),
            
            'impossible_travel': HuntingQuery(
                id='hunt_002',
                name='Impossible Travel',
                description='Detect impossible travel patterns indicating account compromise',
                query='''
                index=authentication
                | eval distance=abs(lat1-lat2)+abs(lon1-lon2)
                | where distance > 500 AND time_diff < 2
                | stats count by user, source_location, dest_location
                | where count > 0
                ''',
                platform='elk',
                hunt_type=HuntType.ANOMALY_DETECTION,
                severity_threshold='high',
                tags=['impossible_travel', 'account_compromise', 'geographic_anomaly'],
                enabled=True,
                schedule='hourly',
                last_run=None
            ),
            
            'privileged_account_usage': HuntingQuery(
                id='hunt_003',
                name='Privileged Account Usage Analysis',
                description='Analyze privileged account usage patterns',
                query='''
                index=security 
                | where User in ("admin", "administrator", "root", "sa", "sysadmin")
                | stats count by User, Computer, Process_Name
                | where count > 10
                | sort -count
                ''',
                platform='qradar',
                hunt_type=HuntType.BEHAVIORAL,
                severity_threshold='medium',
                tags=['privileged_accounts', 'account_monitoring'],
                enabled=True,
                schedule='daily',
                last_run=None
            ),
            
            'lateral_movement_detection': HuntingQuery(
                id='hunt_004',
                name='Lateral Movement Detection',
                description='Detect potential lateral movement using various techniques',
                query='''
                index=security 
                | where EventCode=4624 AND LogonType=3 
                | where Source_IP != dest_ip AND Source_Computer != dest_computer
                | stats count by Source_User, Source_Computer, dest_computer
                | where count > 1
                ''',
                platform='splunk',
                hunt_type=HuntType.BEHAVIORAL,
                severity_threshold='high',
                tags=['lateral_movement', 'network_reconnaissance', 'pass_the_hash'],
                enabled=True,
                schedule='hourly',
                last_run=None
            ),
            
            'data_exfiltration_patterns': HuntingQuery(
                id='hunt_005',
                name='Data Exfiltration Patterns',
                description='Detect potential data exfiltration activities',
                query='''
                index=network 
                | eval volume_mb=bytes_sent/1024/1024
                | where volume_mb > 100 OR (bytes_sent > 50000000 AND hour>=18 OR hour<=6)
                | stats sum(volume_mb) as total_mb by src_ip, user, dest_ip
                | where total_mb > 1000
                | sort -total_mb
                ''',
                platform='elk',
                hunt_type=HuntType.BEHAVIORAL,
                severity_threshold='critical',
                tags=['data_exfiltration', 'large_transfer', 'off_hours_activity'],
                enabled=True,
                schedule='hourly',
                last_run=None
            ),
            
            'ransomware_indicators': HuntingQuery(
                id='hunt_006',
                name='Ransomware Activity Indicators',
                description='Detect activities commonly associated with ransomware',
                query='''
                index=filesystem
                | where Command="cmd.exe" AND (Parameters="*vssadmin*" OR Parameters="*wmic*")
                | stats count by Computer, User, Process_Path
                | where count > 1
                | eval risk_score=count*5
                | where risk_score > 10
                ''',
                platform='splunk',
                hunt_type=HuntType.BEHAVIORAL,
                severity_threshold='critical',
                tags=['ransomware', 'file_deletion', 'shadow_copy'],
                enabled=True,
                schedule='every_15_minutes',
                last_run=None
            ),
            
            'apt_behavioral_patterns': HuntingQuery(
                id='hunt_007',
                name='APT Behavioral Patterns',
                description='Detect Advanced Persistent Threat behavioral patterns',
                query='''
                index=security
                | where EventCode in (4624, 4634, 4648)
                | eval user_activity=mvcount(All_Events)
                | where user_activity > 50 AND day_of_week in (0, 6)
                | stats count by user, hour_of_day
                | where count > 30 AND (hour_of_day < 7 OR hour_of_day > 20)
                ''',
                platform='elk',
                hunt_type=HuntType.BEHAVIORAL,
                severity_threshold='high',
                tags=['apt', 'persistence', 'weekend_activity'],
                enabled=True,
                schedule='daily',
                last_run=None
            ),
            
            # IOC Correlation Queries
            'threat_intelligence_matching': HuntingQuery(
                id='hunt_008',
                name='Threat Intelligence IOC Matching',
                description='Match network traffic against known threat indicators',
                query='''
                index=network
                | lookup threat_intel ioc as dest_ip OUTPUT threat_type, confidence, source
                | where isnotnull(threat_type) AND confidence > 0.7
                | stats count by src_ip, dest_ip, threat_type, source
                | sort -count
                ''',
                platform='splunk',
                hunt_type=HuntType.IOC_CORRELATION,
                severity_threshold='medium',
                tags=['threat_intelligence', 'ioc_matching', 'external_threats'],
                enabled=True,
                schedule='every_30_minutes',
                last_run=None
            ),
            
            'malware_c2_communication': HuntingQuery(
                id='hunt_009',
                name='Malware C2 Communication',
                description='Detect potential malware command and control communication',
                query='''
                index=dns
                | lookup malware_domains domain OUTPUT threat_family, confidence
                | where isnotnull(threat_family)
                | stats count by client_ip, domain, threat_family
                | sort -count
                ''',
                platform='elk',
                hunt_type=HuntType.IOC_CORRELATION,
                severity_threshold='high',
                tags=['malware', 'c2_communication', 'dns_tunneling'],
                enabled=True,
                schedule='every_15_minutes',
                last_run=None
            ),
            
            'phishing_campaign_detection': HuntingQuery(
                id='hunt_010',
                name='Phishing Campaign Detection',
                description='Detect potential phishing campaigns',
                query='''
                index=email
                | where sender_domain IN (phishing_domains) OR url_domain IN (phishing_domains)
                | stats count by sender_email, sender_domain, url_domain, campaign_id
                | where count > 5
                ''',
                platform='qradar',
                hunt_type=HuntType.IOC_CORRELATION,
                severity_threshold='high',
                tags=['phishing', 'email_security', 'campaign_tracking'],
                enabled=True,
                schedule='hourly',
                last_run=None
            ),
            
            # Anomaly Detection Queries
            'statistical_anomalies': HuntingQuery(
                id='hunt_011',
                name='Statistical Network Anomalies',
                description='Detect statistical anomalies in network traffic',
                query='''
                index=netflow
                | eval hour=strftime(_time, "%H")
                | stats count by src_ip, hour
                | where count > avg(count)*3 AND count > 100
                | sort -count
                ''',
                platform='elk',
                hunt_type=HuntType.ANOMALY_DETECTION,
                severity_threshold='medium',
                tags=['anomaly_detection', 'statistical_analysis', 'traffic_patterns'],
                enabled=True,
                schedule='every_30_minutes',
                last_run=None
            ),
            
            'process_anomaly_detection': HuntingQuery(
                id='hunt_012',
                name='Process Execution Anomalies',
                description='Detect anomalous process execution patterns',
                query='''
                index=process
                | stats count by process_name, parent_process
                | where count > 100 OR process_name IN (rare_processes)
                | eval anomaly_score=count*if(process_name IN (rare_processes), 3, 1)
                | where anomaly_score > 200
                ''',
                platform='splunk',
                hunt_type=HuntType.ANOMALY_DETECTION,
                severity_threshold='high',
                tags=['process_anomaly', 'execution_tracking', 'behavioral_baseline'],
                enabled=True,
                schedule='every_15_minutes',
                last_run=None
            ),
            
            # Compliance and Policy Queries
            'policy_violations': HuntingQuery(
                id='hunt_013',
                name='Security Policy Violations',
                description='Detect violations of security policies',
                query='''
                index=security
                | where action IN ("policy_violation", "unauthorized_access")
                | stats count by user, violation_type, severity
                | where severity IN ("high", "critical") AND count > 3
                ''',
                platform='qradar',
                hunt_type=HuntType.COMPLIANCE,
                severity_threshold='medium',
                tags=['compliance', 'policy_violation', 'governance'],
                enabled=True,
                schedule='daily',
                last_run=None
            ),
            
            'privileged_action_tracking': HuntingQuery(
                id='hunt_014',
                name='Privileged Action Tracking',
                description='Track and analyze privileged actions for compliance',
                query='''
                index=audit
                | where privilege_level IN ("high", "critical")
                | stats count by user, action_type, target_resource
                | where count > 5
                | eval compliance_risk=count*severity_score
                | sort -compliance_risk
                ''',
                platform='elk',
                hunt_type=HuntType.COMPLIANCE,
                severity_threshold='medium',
                tags=['privileged_access', 'audit_trail', 'compliance_monitoring'],
                enabled=True,
                schedule='hourly',
                last_run=None
            )
        }
    
    def _initialize_threat_hypotheses(self):
        """Initialize threat hunting hypotheses."""
        self.hypotheses = {
            'apt_long_term_persistence': ThreatHypothesis(
                id='hyp_001',
                name='APT Long-term Persistence',
                description='Hypothesis: Advanced Persistent Threat actors have achieved long-term persistence in the environment',
                hypothesis='APT actors maintain persistent access through multiple backdoors, scheduled tasks, and service installations while keeping activity below detection thresholds.',
                supporting_queries=['hunt_003', 'hunt_007', 'hunt_001'],
                kill_chain_phases=['Persistence', 'Defense Evasion', 'Collection'],
                mitre_techniques=['T1053', 'T1543', 'T1055'],
                confidence_threshold=0.7
            ),
            
            'credential_stuffing_campaign': ThreatHypothesis(
                id='hyp_002',
                name='Credential Stuffing Campaign',
                description='Hypothesis: Active credential stuffing attack against web applications',
                hypothesis='Attackers are using compromised credentials to gain unauthorized access to user accounts and systems.',
                supporting_queries=['hunt_001', 'hunt_002', 'hunt_011'],
                kill_chain_phases=['Reconnaissance', 'Weaponization', 'Delivery', 'Installation'],
                mitre_techniques=['T1110', 'T1078', 'T1219'],
                confidence_threshold=0.8
            ),
            
            'data_exfiltration_operation': ThreatHypothesis(
                id='hyp_003',
                name='Data Exfiltration Operation',
                description='Hypothesis: Active data exfiltration operation targeting sensitive information',
                hypothesis='Threat actors are systematically accessing and exfiltrating sensitive data using legitimate channels.',
                supporting_queries=['hunt_005', 'hunt_008', 'hunt_011'],
                kill_chain_phases=['Collection', 'Exfiltration'],
                mitre_techniques=['T1041', 'T1020', 'T1567'],
                confidence_threshold=0.9
            ),
            
            'ransomware_deployment': ThreatHypothesis(
                id='hyp_004',
                name='Ransomware Deployment',
                description='Hypothesis: Ransomware deployment in progress or completed',
                hypothesis='Ransomware has been deployed and is actively encrypting files or has completed encryption.',
                supporting_queries=['hunt_006', 'hunt_012'],
                kill_chain_phases=['Execution', 'Impact'],
                mitre_techniques=['T1486', 'T1490', 'T1491'],
                confidence_threshold=0.95
            )
        }
    
    async def start(self):
        """Start the threat hunting engine."""
        self.logger.info("Starting Threat Hunting Engine...")
        
        # Start scheduled hunts
        asyncio.create_task(self._hunt_scheduler_loop())
        
        # Start hypothesis monitoring
        asyncio.create_task(self._hypothesis_monitor_loop())
        
        # Start result processing
        asyncio.create_task(self._result_processor_loop())
        
        self.logger.info("Threat Hunting Engine started")
    
    async def _hunt_scheduler_loop(self):
        """Schedule and execute hunts based on their schedules."""
        while True:
            try:
                current_time = datetime.now()
                
                # Check which hunts should run
                for hunt_id, hunt_query in self.hunt_queries.items():
                    if not hunt_query.enabled:
                        continue
                    
                    # Determine if hunt should run
                    should_run = False
                    
                    if hunt_query.schedule == 'manual':
                        continue  # Manual hunts are only run on demand
                    elif hunt_query.schedule == 'hourly':
                        should_run = self._should_run_hourly(hunt_query.last_run)
                    elif hunt_query.schedule == 'daily':
                        should_run = self._should_run_daily(hunt_query.last_run)
                    elif hunt_query.schedule == 'every_15_minutes':
                        should_run = self._should_run_interval(hunt_query.last_run, 15)
                    elif hunt_query.schedule == 'every_30_minutes':
                        should_run = self._should_run_interval(hunt_query.last_run, 30)
                    
                    if should_run:
                        await self._execute_hunt(hunt_query)
                
                # Wait before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in hunt scheduler loop: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    async def _hypothesis_monitor_loop(self):
        """Monitor and evaluate threat hunting hypotheses."""
        while True:
            try:
                for hypothesis_id, hypothesis in self.hypotheses.items():
                    await self._evaluate_hypothesis(hypothesis)
                
                await asyncio.sleep(3600)  # Evaluate every hour
                
            except Exception as e:
                self.logger.error(f"Error in hypothesis monitor loop: {e}")
                await asyncio.sleep(1800)  # Wait 30 minutes on error
    
    async def _result_processor_loop(self):
        """Process hunt results and generate alerts."""
        while True:
            try:
                # Process recent results
                recent_results = [
                    result for result in self.hunt_results
                    if result.timestamp > datetime.now() - timedelta(hours=1)
                ]
                
                for result in recent_results:
                    if result.status == HuntStatus.COMPLETED:
                        await self._process_hunt_result(result)
                
                await asyncio.sleep(300)  # Process every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in result processor loop: {e}")
                await asyncio.sleep(600)  # Wait 10 minutes on error
    
    def _should_run_hourly(self, last_run: Optional[datetime]) -> bool:
        """Check if an hourly hunt should run."""
        if not last_run:
            return True
        
        time_diff = datetime.now() - last_run
        return time_diff.total_seconds() >= 3600  # 1 hour
    
    def _should_run_daily(self, last_run: Optional[datetime]) -> bool:
        """Check if a daily hunt should run."""
        if not last_run:
            return True
        
        time_diff = datetime.now() - last_run
        return time_diff.total_seconds() >= 86400  # 24 hours
    
    def _should_run_interval(self, last_run: Optional[datetime], minutes: int) -> bool:
        """Check if an interval-based hunt should run."""
        if not last_run:
            return True
        
        time_diff = datetime.now() - last_run
        return time_diff.total_seconds() >= (minutes * 60)
    
    async def _execute_hunt(self, hunt_query: HuntingQuery):
        """Execute a specific hunting query."""
        try:
            self.logger.info(f"Executing hunt: {hunt_query.name}")
            
            # Mark hunt as active
            self.active_hunts[hunt_query.id] = {
                'query': hunt_query,
                'start_time': datetime.now(),
                'status': HuntStatus.RUNNING
            }
            
            start_time = datetime.now()
            
            # Execute query based on platform
            if hunt_query.platform == 'splunk':
                findings = await self._execute_splunk_query(hunt_query)
            elif hunt_query.platform == 'elk':
                findings = await self._execute_elk_query(hunt_query)
            elif hunt_query.platform == 'qradar':
                findings = await self._execute_qradar_query(hunt_query)
            else:
                findings = []  # Unsupported platform
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Process findings
            processed_findings = await self._process_hunt_findings(hunt_query, findings)
            
            # Create hunt result
            result = HuntResult(
                hunt_id=hunt_query.id,
                query_id=hunt_query.id,
                timestamp=datetime.now(),
                status=HuntStatus.COMPLETED,
                findings=processed_findings,
                severity=hunt_query.severity_threshold,
                confidence=0.8 if processed_findings else 0.1,
                execution_time=execution_time,
                records_analyzed=len(findings),
                threat_indicators=self._extract_threat_indicators(processed_findings),
                description=f"Hunt '{hunt_query.name}' completed with {len(processed_findings)} findings",
                recommendations=self._generate_recommendations(hunt_query, processed_findings)
            )
            
            # Store result
            self.hunt_results.append(result)
            
            # Update last run time
            hunt_query.last_run = datetime.now()
            
            # Remove from active hunts
            if hunt_query.id in self.active_hunts:
                del self.active_hunts[hunt_query.id]
            
            self.logger.info(f"Hunt '{hunt_query.name}' completed: {len(processed_findings)} findings")
            
        except Exception as e:
            self.logger.error(f"Error executing hunt {hunt_query.id}: {e}")
            
            # Mark hunt as failed
            if hunt_query.id in self.active_hunts:
                self.active_hunts[hunt_query.id]['status'] = HuntStatus.FAILED
                del self.active_hunts[hunt_query.id]
            
            # Create failed result
            failed_result = HuntResult(
                hunt_id=hunt_query.id,
                query_id=hunt_query.id,
                timestamp=datetime.now(),
                status=HuntStatus.FAILED,
                findings=[],
                severity='low',
                confidence=0.0,
                execution_time=0.0,
                records_analyzed=0,
                threat_indicators=[],
                description=f"Hunt '{hunt_query.name}' failed: {str(e)}",
                recommendations=[]
            )
            
            self.hunt_results.append(failed_result)
    
    async def _execute_splunk_query(self, hunt_query: HuntingQuery) -> List[Dict[str, Any]]:
        """Execute a Splunk hunting query."""
        # Simulate Splunk query execution
        # In a real implementation, this would connect to Splunk API
        
        # Simulate query results
        simulated_results = []
        
        if hunt_query.id == 'hunt_001':
            # Unusual admin activity simulation
            simulated_results = [
                {
                    'User': 'admin_user',
                    'Source_IP': '192.168.1.100',
                    'hour': 2,
                    'count': 15,
                    'risk_score': 30,
                    '_time': '2024-02-01T02:30:00Z'
                }
            ]
        elif hunt_query.id == 'hunt_004':
            # Lateral movement simulation
            simulated_results = [
                {
                    'Source_User': 'compromised_user',
                    'Source_Computer': 'WORKSTATION1',
                    'dest_computer': 'SERVER01',
                    'count': 3,
                    '_time': '2024-02-01T14:20:00Z'
                }
            ]
        elif hunt_query.id == 'hunt_006':
            # Ransomware indicators simulation
            simulated_results = [
                {
                    'Computer': 'INFECTED-PC',
                    'User': 'malware_user',
                    'Process_Path': 'C:\\Windows\\System32\\cmd.exe',
                    'count': 8,
                    'risk_score': 40,
                    '_time': '2024-02-01T15:45:00Z'
                }
            ]
        
        return simulated_results
    
    async def _execute_elk_query(self, hunt_query: HuntingQuery) -> List[Dict[str, Any]]:
        """Execute an ELK Stack hunting query."""
        # Simulate ELK query execution
        # In a real implementation, this would connect to Elasticsearch
        
        simulated_results = []
        
        if hunt_query.id == 'hunt_002':
            # Impossible travel simulation
            simulated_results = [
                {
                    'user': 'john.doe@company.com',
                    'source_location': 'New York, US',
                    'dest_location': 'London, UK',
                    'time_diff': 1.5,
                    'distance': 3500,
                    'timestamp': '2024-02-01T08:00:00Z'
                }
            ]
        elif hunt_query.id == 'hunt_005':
            # Data exfiltration simulation
            simulated_results = [
                {
                    'src_ip': '10.0.1.100',
                    'user': 'data_analyst',
                    'dest_ip': 'external.site.com',
                    'total_mb': 2500,
                    'hour': 23,
                    'timestamp': '2024-02-01T23:15:00Z'
                }
            ]
        
        return simulated_results
    
    async def _execute_qradar_query(self, hunt_query: HuntingQuery) -> List[Dict[str, Any]]:
        """Execute a QRadar hunting query."""
        # Simulate QRadar query execution
        # In a real implementation, this would connect to QRadar API
        
        simulated_results = []
        
        if hunt_query.id == 'hunt_013':
            # Policy violations simulation
            simulated_results = [
                {
                    'user': 'employee123',
                    'violation_type': 'unauthorized_access',
                    'severity': 'high',
                    'count': 8,
                    'timestamp': '2024-02-01T16:30:00Z'
                }
            ]
        
        return simulated_results
    
    async def _process_hunt_findings(self, hunt_query: HuntingQuery, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and enrich hunt findings."""
        processed_findings = []
        
        for finding in findings:
            processed_finding = {
                'timestamp': finding.get('_time', finding.get('timestamp', datetime.now().isoformat())),
                'hunt_id': hunt_query.id,
                'hunt_name': hunt_query.name,
                'data': finding,
                'enrichment': await self._enrich_finding(finding, hunt_query),
                'risk_score': self._calculate_risk_score(finding, hunt_query),
                'tags': hunt_query.tags
            }
            
            processed_findings.append(processed_finding)
        
        return processed_findings
    
    async def _enrich_finding(self, finding: Dict[str, Any], hunt_query: HuntingQuery) -> Dict[str, Any]:
        """Enrich a finding with additional context."""
        enrichment = {}
        
        # Extract indicators from finding
        indicators = self._extract_indicators_from_finding(finding)
        
        # Look up indicators in threat intelligence
        if self.threat_intelligence and indicators:
            threat_info = {}
            for indicator in indicators[:5]:  # Limit to 5 indicators
                try:
                    ti_lookup = await self.threat_intelligence.lookup_indicator(indicator)
                    if ti_lookup and ti_lookup.confidence > 0.5:
                        threat_info[indicator] = {
                            'threat_type': ti_lookup.threat_type,
                            'confidence': ti_lookup.confidence,
                            'source': ti_lookup.source
                        }
                except Exception:
                    continue
            
            enrichment['threat_intelligence'] = threat_info
        
        # Add geographic information if IP present
        ip_addresses = [ind for ind in indicators if self._is_ip_address(ind)]
        if ip_addresses:
            enrichment['geographic_info'] = {
                ip: self._get_geographic_info(ip) for ip in ip_addresses[:3]
            }
        
        # Add behavioral context
        enrichment['behavioral_context'] = self._analyze_behavioral_pattern(finding, hunt_query)
        
        return enrichment
    
    def _extract_indicators_from_finding(self, finding: Dict[str, Any]) -> List[str]:
        """Extract potential IOCs from a finding."""
        indicators = []
        
        # Look for common IOC fields
        ioc_fields = [
            'src_ip', 'dest_ip', 'ip', 'domain', 'url', 'hash', 'filename',
            'user', 'computer', 'process_name', 'command_line'
        ]
        
        for field, value in finding.items():
            if field.lower() in ioc_fields and value:
                if isinstance(value, str) and len(value) > 2:
                    indicators.append(value)
                elif isinstance(value, (list, tuple)):
                    indicators.extend([str(v) for v in value if isinstance(v, str) and len(v) > 2])
        
        return list(set(indicators))  # Remove duplicates
    
    def _is_ip_address(self, indicator: str) -> bool:
        """Check if indicator is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(indicator)
            return True
        except ValueError:
            return False
    
    def _get_geographic_info(self, ip_address: str) -> Dict[str, str]:
        """Get geographic information for an IP address."""
        # Simulate geographic lookup
        # In a real implementation, this would use a geo-IP service
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'organization': 'Unknown',
            'latitude': '0.0',
            'longitude': '0.0'
        }
    
    def _analyze_behavioral_pattern(self, finding: Dict[str, Any], hunt_query: HuntingQuery) -> Dict[str, Any]:
        """Analyze behavioral patterns in the finding."""
        context = {
            'time_pattern': 'normal',
            'frequency_pattern': 'normal',
            'sequence_pattern': 'normal',
            'anomaly_score': 0.0
        }
        
        # Analyze time patterns
        timestamp = finding.get('_time') or finding.get('timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00')) if isinstance(timestamp, str) else timestamp
                hour = dt.hour
                
                if hour < 6 or hour > 22:
                    context['time_pattern'] = 'after_hours'
                    context['anomaly_score'] += 0.3
                
                # Weekend activity
                if dt.weekday() >= 5:
                    context['time_pattern'] = 'weekend'
                    context['anomaly_score'] += 0.2
                    
            except Exception:
                pass
        
        # Analyze frequency patterns
        count = finding.get('count', 0)
        if count > 10:
            context['frequency_pattern'] = 'high_volume'
            context['anomaly_score'] += min(count / 100, 0.5)
        
        return context
    
    def _calculate_risk_score(self, finding: Dict[str, Any], hunt_query: HuntingQuery) -> float:
        """Calculate risk score for a finding."""
        base_score = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.95
        }.get(hunt_query.severity_threshold, 0.5)
        
        # Adjust based on findings
        count = finding.get('count', 1)
        if count > 10:
            base_score += 0.1
        
        # Behavioral adjustments
        timestamp = finding.get('_time') or finding.get('timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00')) if isinstance(timestamp, str) else timestamp
                if dt.hour < 6 or dt.hour > 22 or dt.weekday() >= 5:
                    base_score += 0.15
            except Exception:
                pass
        
        return min(base_score, 1.0)
    
    def _extract_threat_indicators(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Extract threat indicators from hunt findings."""
        indicators = []
        
        for finding in findings:
            if 'enrichment' in finding and 'threat_intelligence' in finding['enrichment']:
                indicators.extend(finding['enrichment']['threat_intelligence'].keys())
        
        return list(set(indicators))
    
    def _generate_recommendations(self, hunt_query: HuntingQuery, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on hunt results."""
        recommendations = []
        
        if not findings:
            return recommendations
        
        # Hunt-specific recommendations
        if hunt_query.id == 'hunt_001':
            recommendations.extend([
                'Investigate user authentication patterns',
                'Review privileged account usage',
                'Implement after-hours monitoring'
            ])
        elif hunt_query.id == 'hunt_004':
            recommendations.extend([
                'Check for lateral movement artifacts',
                'Review network segmentation',
                'Monitor privileged account usage'
            ])
        elif hunt_query.id == 'hunt_005':
            recommendations.extend([
                'Implement data loss prevention (DLP)',
                'Monitor for unusual data transfers',
                'Review access controls for sensitive data'
            ])
        elif hunt_query.id == 'hunt_006':
            recommendations.extend([
                'Immediate: Check for active ransomware',
                'Backup verification required',
                'Network segmentation review needed'
            ])
        
        # General recommendations based on severity
        if hunt_query.severity_threshold == 'critical':
            recommendations.extend([
                'Immediate investigation required',
                'Consider incident response activation',
                'Coordinate with security team'
            ])
        
        return recommendations
    
    async def _evaluate_hypothesis(self, hypothesis: ThreatHypothesis):
        """Evaluate a threat hunting hypothesis."""
        # Find supporting hunt results
        supporting_results = []
        for query_id in hypothesis.supporting_queries:
            query_results = [
                result for result in self.hunt_results
                if result.query_id == query_id and result.status == HuntStatus.COMPLETED
            ]
            supporting_results.extend(query_results)
        
        # Calculate confidence based on evidence
        evidence_count = len(supporting_results)
        total_findings = sum(len(result.findings) for result in supporting_results)
        
        # Update hypothesis with current evidence
        hypothesis.evidence_found = total_findings
        hypothesis.last_updated = datetime.now()
        
        # Determine if hypothesis confidence threshold is met
        confidence = min(evidence_count * 0.2 + total_findings * 0.1, 1.0)
        
        if confidence >= hypothesis.confidence_threshold:
            self.logger.warning(f"Hypothesis '{hypothesis.name}' confidence threshold met: {confidence:.2f}")
            await self._trigger_hypothesis_alert(hypothesis, confidence, supporting_results)
    
    async def _trigger_hypothesis_alert(self, hypothesis: ThreatHypothesis, confidence: float, supporting_results: List[HuntResult]):
        """Trigger alert for hypothesis confidence threshold being met."""
        alert_data = {
            'hypothesis_id': hypothesis.id,
            'hypothesis_name': hypothesis.name,
            'description': hypothesis.description,
            'confidence': confidence,
            'evidence_count': hypothesis.evidence_found,
            'kill_chain_phases': hypothesis.kill_chain_phases,
            'mitre_techniques': hypothesis.mitre_techniques,
            'supporting_queries': hypothesis.supporting_queries,
            'timestamp': datetime.now().isoformat(),
            'recommendations': [
                f"Investigate {hypothesis.name.lower()}",
                "Review evidence from supporting hunts",
                "Consider threat hunting campaign execution"
            ]
        }
        
        self.logger.warning(f"HYPOTHESIS ALERT: {hypothesis.name} - Confidence: {confidence:.2f}")
        
        # In a real implementation, this would send to SIEM, create tickets, etc.
    
    async def _process_hunt_result(self, result: HuntResult):
        """Process a completed hunt result."""
        # Generate alerts for significant findings
        if result.findings and result.confidence > 0.6:
            await self._generate_hunt_alert(result)
        
        # Update threat intelligence if findings contain IOCs
        if result.threat_indicators:
            await self._update_threat_intelligence(result)
    
    async def _generate_hunt_alert(self, result: HuntResult):
        """Generate alert for significant hunt findings."""
        alert = {
            'alert_type': 'threat_hunt_result',
            'hunt_id': result.hunt_id,
            'severity': result.severity,
            'confidence': result.confidence,
            'finding_count': len(result.findings),
            'threat_indicators': result.threat_indicators,
            'description': result.description,
            'recommendations': result.recommendations,
            'timestamp': result.timestamp.isoformat()
        }
        
        self.logger.warning(f"HUNT ALERT: {result.hunt_id} - {len(result.findings)} findings")
        
        # In a real implementation, this would integrate with alerting systems
    
    async def _update_threat_intelligence(self, result: HuntResult):
        """Update threat intelligence with IOCs from hunt results."""
        if not self.threat_intelligence:
            return
        
        for indicator in result.threat_indicators:
            try:
                # Create threat intelligence entry
                from .threat_intelligence import ThreatIntelligence
                
                intelligence = ThreatIntelligence(
                    id=f"hunt_{result.hunt_id}_{hashlib.md5(indicator.encode()).hexdigest()}",
                    indicator_type='ip' if self._is_ip_address(indicator) else 'domain',
                    indicator_value=indicator,
                    threat_type='hunt_result',
                    confidence=result.confidence,
                    severity=result.severity,
                    source=f"Threat Hunt: {result.hunt_id}",
                    first_seen=result.timestamp,
                    last_seen=result.timestamp,
                    tags=['hunt_result'] + result.hunt_id.split('_'),
                    description=result.description,
                    raw_data={'hunt_result': asdict(result)},
                    ttl=24
                )
                
                # Store in threat intelligence
                await self.threat_intelligence._store_intelligence(intelligence)
                
            except Exception as e:
                self.logger.error(f"Error updating threat intelligence: {e}")
    
    def get_hunt_statistics(self) -> Dict[str, Any]:
        """Get threat hunting statistics."""
        recent_results = [
            result for result in self.hunt_results
            if result.timestamp > datetime.now() - timedelta(days=7)
        ]
        
        return {
            'total_hunts': len(self.hunt_queries),
            'enabled_hunts': len([q for q in self.hunt_queries.values() if q.enabled]),
            'active_hunts': len(self.active_hunts),
            'total_findings_7_days': sum(len(result.findings) for result in recent_results),
            'high_severity_findings': sum(
                1 for result in recent_results 
                if result.severity in ['high', 'critical'] and result.findings
            ),
            'hypotheses_active': len([h for h in self.hypotheses.values() if h.evidence_found > 0]),
            'platform_coverage': list(set(q.platform for q in self.hunt_queries.values())),
            'hunt_types': [hunt_type.value for hunt_type in set(q.hunt_type for q in self.hunt_queries.values())]
        }
    
    def add_custom_hunt(self, hunt_query: HuntingQuery):
        """Add a custom hunting query."""
        self.hunt_queries[hunt_query.id] = hunt_query
        self.logger.info(f"Added custom hunt: {hunt_query.name}")
    
    async def run_manual_hunt(self, hunt_id: str) -> Optional[HuntResult]:
        """Run a manual hunt immediately."""
        if hunt_id not in self.hunt_queries:
            return None
        
        hunt_query = self.hunt_queries[hunt_id]
        
        if not hunt_query.enabled:
            hunt_query.enabled = True
        
        await self._execute_hunt(hunt_query)
        
        # Return the most recent result for this hunt
        for result in reversed(self.hunt_results):
            if result.hunt_id == hunt_id:
                return result
        
        return None
    
    def get_hunt_results(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent hunt results."""
        recent_results = sorted(
            self.hunt_results,
            key=lambda x: x.timestamp,
            reverse=True
        )[:limit]
        
        return [asdict(result) for result in recent_results]
    
    def get_hypotheses_status(self) -> List[Dict[str, Any]]:
        """Get status of all threat hunting hypotheses."""
        return [
            {
                'id': hyp.id,
                'name': hyp.name,
                'description': hyp.description,
                'confidence_threshold': hyp.confidence_threshold,
                'evidence_found': hyp.evidence_found,
                'last_updated': hyp.last_updated.isoformat() if hyp.last_updated else None,
                'supporting_queries': hyp.supporting_queries,
                'kill_chain_phases': hyp.kill_chain_phases,
                'mitre_techniques': hyp.mitre_techniques
            }
            for hyp in self.hypotheses.values()
        ]