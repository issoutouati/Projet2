"""
Advanced Threat Intelligence System

Provides comprehensive threat intelligence from multiple sources including
commercial feeds, OSINT, government alerts, and industry-specific sources.
"""

import asyncio
import aiohttp
import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import ssl
import certifi


@dataclass
class ThreatIntelligence:
    """Structured threat intelligence data."""
    id: str
    indicator_type: str  # ip, domain, url, hash, filename
    indicator_value: str
    threat_type: str  # malware, apt, botnet, etc.
    confidence: float  # 0.0 to 1.0
    severity: str  # low, medium, high, critical
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    description: str
    raw_data: Dict[str, Any]
    ttl: int  # time to live in hours


@dataclass
class ThreatHuntQuery:
    """Threat hunting query definition."""
    id: str
    name: str
    description: str
    query: str
    platform: str  # splunk, elk, qradar, etc.
    severity_threshold: str
    tags: List[str]
    enabled: bool
    last_run: Optional[datetime]


class ThreatIntelligenceManager:
    """Manages threat intelligence from multiple sources."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize threat intelligence manager."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Threat intelligence storage
        self.intelligence_cache = {}
        self.indicators = set()
        self.hunt_queries = {}
        
        # Feed configurations
        self.feed_configs = {
            'commercial': {
                'threatconnect': {
                    'enabled': config.get('threatconnect', {}).get('enabled', False),
                    'api_url': config.get('threatconnect', {}).get('api_url'),
                    'api_key': config.get('threatconnect', {}).get('api_key'),
                    'rate_limit': config.get('threatconnect', {}).get('rate_limit', 100)
                },
                'RecordedFuture': {
                    'enabled': config.get('recorded_future', {}).get('enabled', False),
                    'api_url': config.get('recorded_future', {}).get('api_url'),
                    'api_key': config.get('recorded_future', {}).get('api_key'),
                    'rate_limit': config.get('recorded_future', {}).get('rate_limit', 100)
                },
                'Anomali': {
                    'enabled': config.get('anomali', {}).get('enabled', False),
                    'api_url': config.get('anomali', {}).get('api_url'),
                    'api_key': config.get('anomali', {}).get('api_key'),
                    'rate_limit': config.get('anomali', {}).get('rate_limit', 100)
                },
                'IBM X-Force': {
                    'enabled': config.get('ibm_xforce', {}).get('enabled', False),
                    'api_url': config.get('ibm_xforce', {}).get('api_url'),
                    'api_key': config.get('ibm_xforce', {}).get('api_key'),
                    'rate_limit': config.get('ibm_xforce', {}).get('rate_limit', 100)
                },
                'VirusTotal': {
                    'enabled': config.get('virustotal', {}).get('enabled', False),
                    'api_url': config.get('virustotal', {}).get('api_url'),
                    'api_key': config.get('virustotal', {}).get('api_key'),
                    'rate_limit': config.get('virustotal', {}).get('rate_limit', 100)
                },
                'AlienVault OTX': {
                    'enabled': config.get('otx', {}).get('enabled', False),
                    'api_url': config.get('otx', {}).get('api_url'),
                    'api_key': config.get('otx', {}).get('api_key'),
                    'rate_limit': config.get('otx', {}).get('rate_limit', 100)
                }
            },
            'government': {
                'nist_nvd': {
                    'enabled': config.get('nist_nvd', {}).get('enabled', True),
                    'api_url': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
                    'rate_limit': config.get('nist_nvd', {}).get('rate_limit', 50)
                },
                'us_cert': {
                    'enabled': config.get('us_cert', {}).get('enabled', True),
                    'api_url': 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv',
                    'rate_limit': config.get('us_cert', {}).get('rate_limit', 10)
                },
                'cisa_aa22': {
                    'enabled': config.get('cisa_aa22', {}).get('enabled', True),
                    'api_url': 'https://www.cisa.gov/sites/default/files/csv/AA22-257A_indicators.csv',
                    'rate_limit': config.get('cisa_aa22', {}).get('rate_limit', 10)
                }
            },
            'open_source': {
                'abuse_ch': {
                    'enabled': config.get('abuse_ch', {}).get('enabled', True),
                    'urls': {
                        'malware': 'https://urlhaus.abuse.ch/downloads/csv/',
                        'phishing': 'https://phishstats.info/phishing.yml',
                        'botnet': 'https://feeds.dshield.org/suspiciousdomains.txt'
                    },
                    'rate_limit': config.get('abuse_ch', {}).get('rate_limit', 100)
                },
                'alienvault_reputation': {
                    'enabled': config.get('alienvault_reputation', {}).get('enabled', True),
                    'url': 'https://reputation.alienvault.com/reputation.data',
                    'rate_limit': config.get('alienvault_reputation', {}).get('rate_limit', 100)
                },
                'spamhaus': {
                    'enabled': config.get('spamhaus', {}).get('enabled', True),
                    'urls': {
                        'drop': 'https://www.spamhaus.org/drop/drop.txt',
                        'edrop': 'https://www.spamhaus.org/drop/edrop.txt',
                        'block': 'https://www.spamhaus.org/blocklists/justdomains.txt'
                    },
                    'rate_limit': config.get('spamhaus', {}).get('rate_limit', 100)
                },
                'virusshare': {
                    'enabled': config.get('virusshare', {}).get('enabled', True),
                    'url': 'https://virusshare.com/torrents.asc',
                    'rate_limit': config.get('virusshare', {}).get('rate_limit', 50)
                },
                'malshare': {
                    'enabled': config.get('malshare', {}).get('enabled', True),
                    'api_url': 'https://api.malshare.com/api.php',
                    'api_key': config.get('malshare', {}).get('api_key'),
                    'rate_limit': config.get('malshare', {}).get('rate_limit', 100)
                }
            },
            'industry_specific': {
                'financial': {
                    'fs_isac': {
                        'enabled': config.get('fs_isac', {}).get('enabled', False),
                        'api_url': config.get('fs_isac', {}).get('api_url'),
                        'api_key': config.get('fs_isac', {}).get('api_key'),
                        'rate_limit': config.get('fs_isac', {}).get('rate_limit', 50)
                    }
                },
                'healthcare': {
                    'hhs_cyber': {
                        'enabled': config.get('hhs_cyber', {}).get('enabled', True),
                        'api_url': 'https://www.hhs.gov/sites/default/files/cybersec-indicator-alerts.xml',
                        'rate_limit': config.get('hhs_cyber', {}).get('rate_limit', 10)
                    }
                },
                'energy': {
                    'energy_isac': {
                        'enabled': config.get('energy_isac', {}).get('enabled', False),
                        'api_url': config.get('energy_isac', {}).get('api_url'),
                        'api_key': config.get('energy_isac', {}).get('api_key'),
                        'rate_limit': config.get('energy_isac', {}).get('rate_limit', 50)
                    }
                },
                'automotive': {
                    'automotive_isac': {
                        'enabled': config.get('automotive_isac', {}).get('enabled', False),
                        'api_url': config.get('automotive_isac', {}).get('api_url'),
                        'api_key': config.get('automotive_isac', {}).get('api_key'),
                        'rate_limit': config.get('automotive_isac', {}).get('rate_limit', 50)
                    }
                }
            }
        }
        
        # Initialize threat hunting queries
        self._initialize_hunt_queries()
        
        # Rate limiting
        self.rate_limits = {}
        
    def _initialize_hunt_queries(self):
        """Initialize predefined threat hunting queries."""
        self.hunt_queries = {
            'suspicious_login_patterns': ThreatHuntQuery(
                id='hunt_001',
                name='Suspicious Login Patterns',
                description='Detect anomalous login patterns that may indicate compromise',
                query='index=security (failed_login OR successful_login) | eval hour=strftime(_time, "%H") | stats count by user, source_ip, hour | where count > 10 OR hour<6 OR hour>22',
                platform='splunk',
                severity_threshold='medium',
                tags=['authentication', 'anomaly', 'brute_force'],
                enabled=True,
                last_run=None
            ),
            'lateral_movement_indicators': ThreatHuntQuery(
                id='hunt_002',
                name='Lateral Movement Indicators',
                description='Detect potential lateral movement within the network',
                query='index=security (netstat OR "admin$" OR "C$" OR "IPC$") | stats count by source_ip, destination_ip, process_name | where count > 5',
                platform='elk',
                severity_threshold='high',
                tags=['lateral_movement', 'network', 'persistence'],
                enabled=True,
                last_run=None
            ),
            'data_exfiltration_patterns': ThreatHuntQuery(
                id='hunt_003',
                name='Data Exfiltration Patterns',
                description='Detect potential data exfiltration activities',
                query='index=network (large_upload OR unusual_data_transfer) | stats sum(bytes_sent) by source_ip, user | where sum_bytes_sent > 1000000000',
                platform='elk',
                severity_threshold='high',
                tags=['data_exfiltration', 'network', 'policy_violation'],
                enabled=True,
                last_run=None
            ),
            'malware_communication': ThreatHuntQuery(
                id='hunt_004',
                name='Malware Communication',
                description='Detect communication with known malware C&C servers',
                query='index=dns (query_type=A OR query_type=AAAA) | lookup malware_domains domain OUTPUT threat_type | where isnotnull(threat_type)',
                platform='splunk',
                severity_threshold='critical',
                tags=['malware', 'command_control', 'dns'],
                enabled=True,
                last_run=None
            ),
            'privilege_escalation': ThreatHuntQuery(
                id='hunt_005',
                name='Privilege Escalation Attempts',
                description='Detect attempts to escalate privileges',
                query='index=security (sudo OR "useradd" OR "usermod") | stats count by user, source_ip | where count > 3',
                platform='splunk',
                severity_threshold='high',
                tags=['privilege_escalation', 'persistence', 'authentication'],
                enabled=True,
                last_run=None
            ),
            'ransomware_indicators': ThreatHuntQuery(
                id='hunt_006',
                name='Ransomware Indicators',
                description='Detect activities commonly associated with ransomware',
                query='index=security (file_encryption OR ransom_note OR shadowcopy_delete) | stats count by host, user | where count > 0',
                platform='elk',
                severity_threshold='critical',
                tags=['ransomware', 'file_encryption', 'destruction'],
                enabled=True,
                last_run=None
            )
        }
    
    async def start(self):
        """Start the threat intelligence system."""
        self.logger.info("Starting Threat Intelligence System...")
        
        # Start background tasks
        asyncio.create_task(self._intelligence_update_loop())
        asyncio.create_task(self._threat_hunting_loop())
        asyncio.create_task(self._cache_maintenance_loop())
        
        self.logger.info("Threat Intelligence System started")
    
    async def _intelligence_update_loop(self):
        """Background loop to update threat intelligence."""
        while True:
            try:
                await self._update_all_feeds()
                await asyncio.sleep(3600)  # Update every hour
            except Exception as e:
                self.logger.error(f"Error in intelligence update loop: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
    
    async def _threat_hunting_loop(self):
        """Background loop for automated threat hunting."""
        while True:
            try:
                await self._run_enabled_hunts()
                await asyncio.sleep(1800)  # Run hunts every 30 minutes
            except Exception as e:
                self.logger.error(f"Error in threat hunting loop: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
    
    async def _cache_maintenance_loop(self):
        """Background loop to maintain the intelligence cache."""
        while True:
            try:
                await self._clean_expired_intelligence()
                await asyncio.sleep(86400)  # Run once per day
            except Exception as e:
                self.logger.error(f"Error in cache maintenance loop: {e}")
                await asyncio.sleep(3600)  # Wait 1 hour before retry
    
    async def _update_all_feeds(self):
        """Update threat intelligence from all configured feeds."""
        tasks = []
        
        # Update commercial feeds
        for feed_name, feed_config in self.feed_configs['commercial'].items():
            if feed_config.get('enabled', False):
                tasks.append(self._update_commercial_feed(feed_name, feed_config))
        
        # Update government feeds
        for feed_name, feed_config in self.feed_configs['government'].items():
            if feed_config.get('enabled', False):
                tasks.append(self._update_government_feed(feed_name, feed_config))
        
        # Update open source feeds
        for feed_name, feed_config in self.feed_configs['open_source'].items():
            if feed_config.get('enabled', False):
                tasks.append(self._update_open_source_feed(feed_name, feed_config))
        
        # Update industry-specific feeds
        for industry, feeds in self.feed_configs['industry_specific'].items():
            for feed_name, feed_config in feeds.items():
                if feed_config.get('enabled', False):
                    tasks.append(self._update_industry_feed(feed_name, feed_config, industry))
        
        # Execute all feed updates concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _update_commercial_feed(self, feed_name: str, config: Dict[str, Any]):
        """Update from a commercial threat intelligence feed."""
        try:
            if feed_name == 'threatconnect':
                await self._update_threatconnect(config)
            elif feed_name == 'RecordedFuture':
                await self._update_recorded_future(config)
            elif feed_name == 'Anomali':
                await self._update_anomali(config)
            elif feed_name == 'IBM X-Force':
                await self._update_ibm_xforce(config)
            elif feed_name == 'VirusTotal':
                await self._update_virustotal(config)
            elif feed_name == 'AlienVault OTX':
                await self._update_otx(config)
            
            self.logger.info(f"Updated commercial feed: {feed_name}")
            
        except Exception as e:
            self.logger.error(f"Error updating commercial feed {feed_name}: {e}")
    
    async def _update_threatconnect(self, config: Dict[str, Any]):
        """Update from ThreatConnect feed."""
        headers = {
            'Authorization': f'Tc {config["api_key"]}',
            'Content-Type': 'application/json'
        }
        
        async with aiohttp.ClientSession() as session:
            # Get indicators
            async with session.get(f"{config['api_url']}/indicators", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    for item in data.get('data', []):
                        intelligence = ThreatIntelligence(
                            id=f"threatconnect_{item['id']}",
                            indicator_type=item.get('type', 'unknown'),
                            indicator_value=item.get('value', ''),
                            threat_type=item.get('threat_type', 'unknown'),
                            confidence=item.get('confidence', 0.5),
                            severity=item.get('rating', 'medium'),
                            source='ThreatConnect',
                            first_seen=datetime.fromisoformat(item.get('first_seen', datetime.now().isoformat())),
                            last_seen=datetime.fromisoformat(item.get('last_seen', datetime.now().isoformat())),
                            tags=item.get('tags', []),
                            description=item.get('description', ''),
                            raw_data=item,
                            ttl=24
                        )
                        
                        await self._store_intelligence(intelligence)
    
    async def _update_recorded_future(self, config: Dict[str, Any]):
        """Update from Recorded Future feed."""
        headers = {
            'X-RFToken': config['api_key'],
            'Content-Type': 'application/json'
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{config['api_url']}/iprisk", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    for item in data.get('data', []):
                        intelligence = ThreatIntelligence(
                            id=f"recordedfuture_{item['entity']['id']}",
                            indicator_type='ip',
                            indicator_value=item['entity']['name'],
                            threat_type=item.get('intel_types', ['unknown'])[0],
                            confidence=item.get('score', 0) / 100.0,
                            severity=self._map_score_to_severity(item.get('score', 50)),
                            source='Recorded Future',
                            first_seen=datetime.fromisoformat(item.get('first_seen', datetime.now().isoformat())),
                            last_seen=datetime.fromisoformat(item.get('last_seen', datetime.now().isoformat())),
                            tags=item.get('intel_types', []),
                            description=item.get('desc', ''),
                            raw_data=item,
                            ttl=24
                        )
                        
                        await self._store_intelligence(intelligence)
    
    async def _update_government_feed(self, feed_name: str, config: Dict[str, Any]):
        """Update from government threat intelligence feeds."""
        try:
            if feed_name == 'nist_nvd':
                await self._update_nist_nvd(config)
            elif feed_name == 'us_cert':
                await self._update_us_cert(config)
            elif feed_name == 'cisa_aa22':
                await self._update_cisa_aa22(config)
            
            self.logger.info(f"Updated government feed: {feed_name}")
            
        except Exception as e:
            self.logger.error(f"Error updating government feed {feed_name}: {e}")
    
    async def _update_nist_nvd(self, config: Dict[str, Any]):
        """Update from NIST National Vulnerability Database."""
        params = {
            'pubStartDate': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000')
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.get(config['api_url'], params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    
                    for vuln in data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        
                        # Extract CVSS score
                        cvss_score = 0.0
                        cvss_vector = ''
                        for metric in cve.get('metrics', {}).get('cvssMetricV31', []):
                            if metric.get('cvssData'):
                                cvss_score = metric['cvssData'].get('baseScore', 0.0)
                                cvss_vector = metric['cvssData'].get('vectorString', '')
                                break
                        
                        # Extract indicators (IP addresses, domains, etc.)
                        indicators = self._extract_indicators_from_cve(cve)
                        
                        for indicator in indicators:
                            intelligence = ThreatIntelligence(
                                id=f"nist_nvd_{cve.get('id', 'unknown')}_{indicator['value']}",
                                indicator_type=indicator['type'],
                                indicator_value=indicator['value'],
                                threat_type='vulnerability',
                                confidence=1.0,  # Government source, high confidence
                                severity=self._map_cvss_to_severity(cvss_score),
                                source='NIST NVD',
                                first_seen=datetime.fromisoformat(cve.get('published', datetime.now().isoformat())),
                                last_seen=datetime.now(),
                                tags=cve.get('keywords', {}).get('keyword', []),
                                description=cve.get('descriptions', [{}])[0].get('value', ''),
                                raw_data=cve,
                                ttl=168  # 1 week for vulnerabilities
                            )
                            
                            await self._store_intelligence(intelligence)
    
    async def _update_open_source_feed(self, feed_name: str, config: Dict[str, Any]):
        """Update from open source threat intelligence feeds."""
        try:
            if feed_name == 'abuse_ch':
                await self._update_abuse_ch(config)
            elif feed_name == 'alienvault_reputation':
                await self._update_alienvault_reputation(config)
            elif feed_name == 'spamhaus':
                await self._update_spamhaus(config)
            
            self.logger.info(f"Updated open source feed: {feed_name}")
            
        except Exception as e:
            self.logger.error(f"Error updating open source feed {feed_name}: {e}")
    
    async def _update_abuse_ch(self, config: Dict[str, Any]):
        """Update from Abuse.ch feeds."""
        urls = config.get('urls', {})
        
        # Update malware URLs
        if 'malware' in urls:
            async with aiohttp.ClientSession() as session:
                async with session.get(urls['malware']) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        lines = content.strip().split('\n')
                        
                        for line in lines:
                            if line.startswith('#') or not line.strip():
                                continue
                            
                            parts = line.split(',')
                            if len(parts) >= 5:
                                url = parts[1].strip('"')
                                threat = parts[4].strip('"')
                                
                                intelligence = ThreatIntelligence(
                                    id=f"abuse_ch_malware_{hashlib.md5(url.encode()).hexdigest()}",
                                    indicator_type='url',
                                    indicator_value=url,
                                    threat_type='malware',
                                    confidence=0.8,
                                    severity='high',
                                    source='Abuse.ch URLhaus',
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=['malware', 'urlhaus'],
                                    description=f"Malicious URL: {threat}",
                                    raw_data={'threat': threat, 'csv_line': line},
                                    ttl=24
                                )
                                
                                await self._store_intelligence(intelligence)
    
    async def _update_alienvault_reputation(self, config: Dict[str, Any]):
        """Update from AlienVault IP reputation database."""
        async with aiohttp.ClientSession() as session:
            async with session.get(config['url']) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    lines = content.strip().split('\n')
                    
                    for line in lines:
                        if line.startswith('#') or not line.strip():
                            continue
                        
                        parts = line.split('#')[0].strip().split(';')
                        if len(parts) >= 2:
                            ip = parts[0].strip()
                            score = parts[1].strip()
                            
                            try:
                                score_int = int(score)
                                threat_type = 'suspicious' if score_int > 2 else 'unknown'
                                
                                intelligence = ThreatIntelligence(
                                    id=f"alienvault_ip_{ip}",
                                    indicator_type='ip',
                                    indicator_value=ip,
                                    threat_type=threat_type,
                                    confidence=0.6,
                                    severity='medium' if score_int > 2 else 'low',
                                    source='AlienVault Reputation',
                                    first_seen=datetime.now(),
                                    last_seen=datetime.now(),
                                    tags=['reputation', 'alienvault'],
                                    description=f"IP reputation score: {score}",
                                    raw_data={'score': score, 'raw_line': line},
                                    ttl=24
                                )
                                
                                await self._store_intelligence(intelligence)
                                
                            except ValueError:
                                continue
    
    async def _run_enabled_hunts(self):
        """Run enabled threat hunting queries."""
        for hunt_id, hunt_query in self.hunt_queries.items():
            if hunt_query.enabled:
                try:
                    await self._execute_hunt_query(hunt_query)
                    hunt_query.last_run = datetime.now()
                except Exception as e:
                    self.logger.error(f"Error executing hunt query {hunt_id}: {e}")
    
    async def _execute_hunt_query(self, hunt_query: ThreatHuntQuery):
        """Execute a threat hunting query."""
        self.logger.info(f"Executing threat hunt: {hunt_query.name}")
        
        # Simulate query execution
        # In a real implementation, this would connect to SIEM platforms
        simulated_results = [
            {
                'timestamp': datetime.now().isoformat(),
                'query_id': hunt_query.id,
                'result_type': 'potential_threat',
                'severity': hunt_query.severity_threshold,
                'indicators': ['192.168.1.100', 'suspicious-domain.com'],
                'confidence': 0.7,
                'tags': hunt_query.tags
            }
        ]
        
        for result in simulated_results:
            # Convert to threat intelligence
            for indicator in result['indicators']:
                intelligence = ThreatIntelligence(
                    id=f"hunt_{hunt_query.id}_{hashlib.md5(indicator.encode()).hexdigest()}",
                    indicator_type='ip' if self._is_ip(indicator) else 'domain',
                    indicator_value=indicator,
                    threat_type='hunt_result',
                    confidence=result['confidence'],
                    severity=result['severity'],
                    source=f"Threat Hunt: {hunt_query.name}",
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    tags=result['tags'],
                    description=f"Threat hunt result from query: {hunt_query.description}",
                    raw_data=result,
                    ttl=24
                )
                
                await self._store_intelligence(intelligence)
    
    async def _clean_expired_intelligence(self):
        """Remove expired threat intelligence."""
        current_time = datetime.now()
        expired_ids = []
        
        for intel_id, intelligence in self.intelligence_cache.items():
            if current_time > intelligence.last_seen + timedelta(hours=intelligence.ttl):
                expired_ids.append(intel_id)
        
        for intel_id in expired_ids:
            del self.intelligence_cache[intel_id]
            self.indicators.discard(intel_id)
        
        self.logger.info(f"Cleaned {len(expired_ids)} expired intelligence entries")
    
    async def _store_intelligence(self, intelligence: ThreatIntelligence):
        """Store threat intelligence in cache."""
        self.intelligence_cache[intelligence.id] = intelligence
        self.indicators.add(intelligence.indicator_value)
    
    def _map_score_to_severity(self, score: int) -> str:
        """Map numeric score to severity level."""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """Map CVSS score to severity level."""
        if cvss_score >= 9.0:
            return 'critical'
        elif cvss_score >= 7.0:
            return 'high'
        elif cvss_score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def _extract_indicators_from_cve(self, cve: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract indicators (IPs, domains, etc.) from CVE data."""
        indicators = []
        
        # Look for indicators in references, descriptions, etc.
        references = cve.get('references', [])
        descriptions = cve.get('descriptions', [])
        
        for ref in references:
            url = ref.get('url', '')
            if url:
                # Extract domain from URL
                if '://' in url:
                    domain = url.split('://')[1].split('/')[0]
                    indicators.append({'type': 'domain', 'value': domain})
        
        return indicators
    
    def _is_ip(self, indicator: str) -> bool:
        """Check if indicator is an IP address."""
        parts = indicator.split('.')
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
    
    async def lookup_indicator(self, indicator: str, indicator_type: str = None) -> Optional[ThreatIntelligence]:
        """Lookup threat intelligence for a specific indicator."""
        # Check cache first
        for intel in self.intelligence_cache.values():
            if intel.indicator_value == indicator:
                return intel
        
        # If not in cache, check external sources
        if not indicator_type:
            indicator_type = 'ip' if self._is_ip(indicator) else 'domain'
        
        # Simulate external lookup
        return ThreatIntelligence(
            id=f"lookup_{hashlib.md5(indicator.encode()).hexdigest()}",
            indicator_type=indicator_type,
            indicator_value=indicator,
            threat_type='unknown',
            confidence=0.0,
            severity='unknown',
            source='External Lookup',
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=[],
            description='No threat intelligence found',
            raw_data={},
            ttl=0
        )
    
    async def get_indicators_by_type(self, indicator_type: str) -> List[ThreatIntelligence]:
        """Get all indicators of a specific type."""
        return [
            intel for intel in self.intelligence_cache.values()
            if intel.indicator_type == indicator_type
        ]
    
    async def get_indicators_by_threat_type(self, threat_type: str) -> List[ThreatIntelligence]:
        """Get all indicators of a specific threat type."""
        return [
            intel for intel in self.intelligence_cache.values()
            if intel.threat_type == threat_type
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            'total_intelligence': len(self.intelligence_cache),
            'indicators_by_type': {
                indicator_type: len([i for i in self.intelligence_cache.values() if i.indicator_type == indicator_type])
                for indicator_type in set(i.indicator_type for i in self.intelligence_cache.values())
            },
            'indicators_by_threat_type': {
                threat_type: len([i for i in self.intelligence_cache.values() if i.threat_type == threat_type])
                for threat_type in set(i.threat_type for i in self.intelligence_cache.values())
            },
            'threat_hunts_enabled': len([h for h in self.hunt_queries.values() if h.enabled]),
            'last_update': datetime.now().isoformat()
        }