"""
Commercial Platform Integrations

Provides integrations with major commercial security platforms including
SIEM systems, SOAR platforms, and enterprise security tools.
"""

import asyncio
import aiohttp
import logging
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import base64
import ssl
import certifi


class IntegrationStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    AUTHENTICATION_FAILED = "auth_failed"


@dataclass
class PlatformAlert:
    """Structured alert from commercial platforms."""
    id: str
    platform: str
    title: str
    description: str
    severity: str
    status: str
    created_time: datetime
    assigned_to: Optional[str]
    indicators: List[str]
    raw_data: Dict[str, Any]


class SplunkIntegration:
    """Integration with Splunk SIEM platform."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.base_url = config.get('base_url', '')
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.token = config.get('token', '')
        self.status = IntegrationStatus.DISCONNECTED
        
        # Splunk-specific settings
        self.search_timeout = config.get('search_timeout', 60)
        self.max_results = config.get('max_results', 1000)
        self.earliest_time = config.get('earliest_time', '-24h')
        self.latest_time = config.get('latest_time', 'now')
        
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to Splunk instance."""
        try:
            self.status = IntegrationStatus.CONNECTING
            
            # Setup authentication
            auth = None
            headers = {}
            
            if self.token:
                # Token-based authentication
                headers['Authorization'] = f'Splunk {self.token}'
            elif self.username and self.password:
                # Basic authentication
                auth = aiohttp.BasicAuth(self.username, self.password)
            
            # Create SSL context
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            
            # Create session
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            self.session = aiohttp.ClientSession(
                auth=auth,
                headers=headers,
                connector=connector,
                timeout=timeout
            )
            
            # Test connection
            await self._test_connection()
            
            self.status = IntegrationStatus.CONNECTED
            self.logger.info("Successfully connected to Splunk")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Splunk: {e}")
            self.status = IntegrationStatus.ERROR
            return False
    
    async def _test_connection(self):
        """Test Splunk connection."""
        async with self.session.get(f"{self.base_url}/services/authentication/users") as response:
            if response.status != 200:
                raise Exception(f"Authentication failed: {response.status}")
    
    async def search(self, query: str, earliest_time: str = None, latest_time: str = None) -> List[Dict[str, Any]]:
        """Execute Splunk search query."""
        if self.status != IntegrationStatus.CONNECTED:
            raise Exception("Not connected to Splunk")
        
        try:
            # Use default times if not specified
            earliest = earliest_time or self.earliest_time
            latest = latest_time or self.latest_time
            
            # Prepare search parameters
            search_params = {
                'search': query if query.startswith('search ') else f'search {query}',
                'earliest_time': earliest,
                'latest_time': latest,
                'output_mode': 'json',
                'count': str(self.max_results)
            }
            
            # Execute search
            async with self.session.get(
                f"{self.base_url}/services/search/jobs",
                params=search_params
            ) as response:
                
                if response.status != 201:
                    error_text = await response.text()
                    raise Exception(f"Search failed: {response.status} - {error_text}")
                
                # Get search job SID
                response_data = await response.json()
                sid = response_data['sid']
                
                # Wait for search completion
                await self._wait_for_search_completion(sid)
                
                # Get results
                return await self._get_search_results(sid)
                
        except Exception as e:
            self.logger.error(f"Search execution failed: {e}")
            return []
    
    async def _wait_for_search_completion(self, sid: str, timeout: int = 60):
        """Wait for Splunk search to complete."""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            async with self.session.get(
                f"{self.base_url}/services/search/jobs/{sid}"
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    content = data['entry'][0]['content']
                    
                    if content.get('isDone', False):
                        return True
                    
                    # Check for dispatchState
                    dispatch_state = content.get('dispatchState', '')
                    if dispatch_state in ['FAILED', 'CANCELED']:
                        raise Exception(f"Search {dispatch_state.lower()}")
            
            await asyncio.sleep(2)  # Wait 2 seconds before checking again
        
        raise Exception("Search timeout")
    
    async def _get_search_results(self, sid: str) -> List[Dict[str, Any]]:
        """Get search results from completed job."""
        async with self.session.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            params={'output_mode': 'json', 'count': str(self.max_results)}
        ) as response:
            
            if response.status == 200:
                data = await response.json()
                return data.get('results', [])
            else:
                raise Exception(f"Failed to get results: {response.status}")
    
    async def create_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Create alert in Splunk."""
        try:
            alert_params = {
                'name': alert_data.get('name', ''),
                'search': alert_data.get('search', ''),
                'is_scheduled': '1',
                'cron_schedule': alert_data.get('cron_schedule', '0 */6 * * *'),
                'actions': 'email,webhook',
                'email.to': alert_data.get('email_to', ''),
                'webhook.url': alert_data.get('webhook_url', ''),
                'alert.track': '1',
                'alert.severity': alert_data.get('severity', '3')
            }
            
            async with self.session.post(
                f"{self.base_url}/services/saved/searches",
                data=alert_params
            ) as response:
                
                return response.status == 201
                
        except Exception as e:
            self.logger.error(f"Failed to create Splunk alert: {e}")
            return False
    
    async def get_alerts(self, limit: int = 100) -> List[PlatformAlert]:
        """Get alerts from Splunk."""
        try:
            query = '''
            search index=_internal alert_manager
            | eval alert_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
            | eval severity=case(
                severity=1, "critical",
                severity=2, "high", 
                severity=3, "medium",
                severity=4, "low",
                1=1, "unknown"
            )
            | table alert_id, alert_time, severity, source, message
            | sort -_time
            '''
            
            results = await self.search(query, earliest_time='-7d')
            
            alerts = []
            for result in results[:limit]:
                alert = PlatformAlert(
                    id=result.get('alert_id', ''),
                    platform='splunk',
                    title=result.get('source', 'Splunk Alert'),
                    description=result.get('message', ''),
                    severity=result.get('severity', 'unknown'),
                    status='new',
                    created_time=datetime.fromisoformat(result.get('alert_time', datetime.now().isoformat())),
                    assigned_to=None,
                    indicators=[],
                    raw_data=result
                )
                alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get Splunk alerts: {e}")
            return []
    
    async def send_data(self, data: Dict[str, Any], sourcetype: str = 'cyberguard:event') -> bool:
        """Send data to Splunk."""
        try:
            # Format data for Splunk
            event_data = {
                'time': str(int(datetime.now().timestamp())),
                'host': data.get('host', 'cyberguard'),
                'source': data.get('source', 'cyberguard'),
                'sourcetype': sourcetype,
                'event': json.dumps(data)
            }
            
            # Send to Splunk HTTP Event Collector (if configured)
            hec_url = f"{self.base_url}/services/collector"
            if self.token:
                headers = {'Authorization': f'Splunk {self.token}'}
            else:
                headers = {}
                auth = aiohttp.BasicAuth(self.username, self.password)
            
            async with self.session.post(
                hec_url,
                data=json.dumps(event_data),
                headers=headers,
                auth=auth
            ) as response:
                
                return response.status == 200
                
        except Exception as e:
            self.logger.error(f"Failed to send data to Splunk: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Splunk."""
        if self.session:
            await self.session.close()
        self.status = IntegrationStatus.DISCONNECTED


class IBMQRadarIntegration:
    """Integration with IBM QRadar SIEM platform."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.base_url = config.get('base_url', '')
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.status = IntegrationStatus.DISCONNECTED
        
        # QRadar-specific settings
        self.version = config.get('version', '16.0')
        self.max_results = config.get('max_results', 1000)
        
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to QRadar instance."""
        try:
            self.status = IntegrationStatus.CONNECTING
            
            # Setup SSL context
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            # Create session with authentication
            auth = aiohttp.BasicAuth(self.username, self.password)
            
            self.session = aiohttp.ClientSession(
                auth=auth,
                connector=connector,
                timeout=timeout
            )
            
            # Test connection
            await self._test_connection()
            
            self.status = IntegrationStatus.CONNECTED
            self.logger.info("Successfully connected to IBM QRadar")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to QRadar: {e}")
            self.status = IntegrationStatus.ERROR
            return False
    
    async def _test_connection(self):
        """Test QRadar connection."""
        async with self.session.get(f"{self.base_url}/api/available_endpoints") as response:
            if response.status != 200:
                raise Exception(f"Connection failed: {response.status}")
    
    async def search(self, query: str) -> List[Dict[str, Any]]:
        """Execute QRadar AQL search."""
        try:
            search_data = {
                'query_expression': query,
                'range': f'1-{self.max_results}',
                'fields': '*',
                'sort': '-startTime'
            }
            
            async with self.session.post(
                f"{self.base_url}/api/ariel/searches",
                json=search_data
            ) as response:
                
                if response.status != 201:
                    error_text = await response.text()
                    raise Exception(f"Search failed: {response.status} - {error_text}")
                
                # Get search ID
                search_info = await response.json()
                search_id = search_info['search_id']
                
                # Wait for search completion
                await self._wait_for_search_completion(search_id)
                
                # Get results
                return await self._get_search_results(search_id)
                
        except Exception as e:
            self.logger.error(f"QRadar search execution failed: {e}")
            return []
    
    async def _wait_for_search_completion(self, search_id: str, timeout: int = 60):
        """Wait for QRadar search to complete."""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            async with self.session.get(
                f"{self.base_url}/api/ariel/searches/{search_id}"
            ) as response:
                
                if response.status == 200:
                    search_info = await response.json()
                    
                    if search_info.get('status') == 'COMPLETED':
                        return True
                    elif search_info.get('status') in ['ERROR', 'CANCELED']:
                        raise Exception(f"Search {search_info['status'].lower()}")
            
            await asyncio.sleep(2)
        
        raise Exception("Search timeout")
    
    async def _get_search_results(self, search_id: str) -> List[Dict[str, Any]]:
        """Get QRadar search results."""
        async with self.session.get(
            f"{self.base_url}/api/ariel/searches/{search_id}/results"
        ) as response:
            
            if response.status == 200:
                return await response.json()
            else:
                raise Exception(f"Failed to get results: {response.status}")
    
    async def create_offense(self, offense_data: Dict[str, Any]) -> Optional[str]:
        """Create offense in QRadar."""
        try:
            offense = {
                'description': offense_data.get('description', ''),
                'offense_type': offense_data.get('offense_type', 0),  # 0 = Source
                'magnitude': offense_data.get('magnitude', 3),
                'assigned_to': offense_data.get('assigned_to', ''),
                'source_address': offense_data.get('source_address', ''),
                'destination_address': offense_data.get('destination_address', ''),
                'username': offense_data.get('username', ''),
                'remote_destination_count': offense_data.get('remote_destination_count', 0)
            }
            
            async with self.session.post(
                f"{self.base_url}/api/siem/offenses",
                json=offense
            ) as response:
                
                if response.status == 201:
                    response_data = await response.json()
                    return response_data.get('id')
                else:
                    raise Exception(f"Failed to create offense: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"Failed to create QRadar offense: {e}")
            return None
    
    async def get_offenses(self, limit: int = 100) -> List[PlatformAlert]:
        """Get offenses from QRadar."""
        try:
            # Get offenses
            async with self.session.get(
                f"{self.base_url}/api/siem/offenses",
                params={'filter': f'status=OPEN&range=1-{limit}'}
            ) as response:
                
                if response.status != 200:
                    return []
                
                offenses = await response.json()
                
                alerts = []
                for offense in offenses:
                    # Map magnitude to severity
                    magnitude = offense.get('magnitude', 3)
                    severity = 'low' if magnitude <= 2 else 'medium' if magnitude <= 5 else 'high'
                    
                    alert = PlatformAlert(
                        id=str(offense.get('id', '')),
                        platform='qradar',
                        title=f"QRadar Offense #{offense.get('id', '')}",
                        description=offense.get('description', ''),
                        severity=severity,
                        status=offense.get('status', 'OPEN'),
                        created_time=datetime.fromtimestamp(offense.get('start_time', 0) / 1000),
                        assigned_to=offense.get('assigned_to_user_name'),
                        indicators=[offense.get('source_address', '')],
                        raw_data=offense
                    )
                    alerts.append(alert)
                
                return alerts
                
        except Exception as e:
            self.logger.error(f"Failed to get QRadar offenses: {e}")
            return []
    
    async def disconnect(self):
        """Disconnect from QRadar."""
        if self.session:
            await self.session.close()
        self.status = IntegrationStatus.DISCONNECTED


class MicrosoftSentinelIntegration:
    """Integration with Microsoft Sentinel."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.subscription_id = config.get('subscription_id', '')
        self.resource_group = config.get('resource_group', '')
        self.workspace_name = config.get('workspace_name', '')
        self.client_id = config.get('client_id', '')
        self.client_secret = config.get('client_secret', '')
        self.tenant_id = config.get('tenant_id', '')
        self.status = IntegrationStatus.DISCONNECTED
        
        self.access_token = None
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to Microsoft Sentinel."""
        try:
            self.status = IntegrationStatus.CONNECTING
            
            # Get access token
            await self._get_access_token()
            
            # Setup session with authorization
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            self.session = aiohttp.ClientSession(
                headers=headers,
                connector=connector,
                timeout=timeout
            )
            
            # Test connection
            await self._test_connection()
            
            self.status = IntegrationStatus.CONNECTED
            self.logger.info("Successfully connected to Microsoft Sentinel")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Microsoft Sentinel: {e}")
            self.status = IntegrationStatus.ERROR
            return False
    
    async def _get_access_token(self):
        """Get Microsoft Graph access token."""
        try:
            token_data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'scope': 'https://management.azure.com/.default',
                'grant_type': 'client_credentials'
            }
            
            async with aiohttp.ClientSession() as token_session:
                async with token_session.post(
                    f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token',
                    data=token_data
                ) as response:
                    
                    if response.status == 200:
                        token_info = await response.json()
                        self.access_token = token_info.get('access_token')
                    else:
                        raise Exception(f"Token request failed: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Failed to get access token: {e}")
            raise
    
    async def _test_connection(self):
        """Test Microsoft Sentinel connection."""
        base_url = f"https://management.azure.com/subscriptions/{self.subscription_id}"
        
        async with self.session.get(base_url) as response:
            if response.status != 200:
                raise Exception(f"Connection test failed: {response.status}")
    
    async def search(self, query: str) -> List[Dict[str, Any]]:
        """Execute KQL query in Sentinel."""
        try:
            workspace_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            
            search_data = {
                'query': query,
                'timespan': 'P1D'  # Last 24 hours
            }
            
            async with self.session.post(
                f"{workspace_url}/api/query",
                json=search_data
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    return data.get('tables', [])
                else:
                    raise Exception(f"Search failed: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"Sentinel search execution failed: {e}")
            return []
    
    async def create_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Create alert rule in Sentinel."""
        try:
            workspace_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            
            alert_rule = {
                'name': alert_data.get('name', ''),
                'type': 'Microsoft.SecurityInsights/alertRules',
                'kind': 'Scheduled',
                'properties': {
                    'displayName': alert_data.get('display_name', ''),
                    'description': alert_data.get('description', ''),
                    'severity': alert_data.get('severity', 'Medium'),
                    'enabled': True,
                    'query': alert_data.get('query', ''),
                    'queryFrequency': 'PT1H',
                    'queryPeriod': 'PT1H',
                    'triggerOperator': 'GreaterThan',
                    'triggerThreshold': 0,
                    'suppressionDuration': 'PT1H',
                    'suppressionEnabled': False,
                    'tactics': alert_data.get('tactics', []),
                    'techniques': alert_data.get('techniques', [])
                }
            }
            
            async with self.session.put(
                f"{workspace_url}/providers/Microsoft.SecurityInsights/alertRules/{alert_data.get('name', '')}",
                json=alert_rule
            ) as response:
                
                return response.status in [200, 201]
                
        except Exception as e:
            self.logger.error(f"Failed to create Sentinel alert: {e}")
            return False
    
    async def get_incidents(self, limit: int = 100) -> List[PlatformAlert]:
        """Get incidents from Sentinel."""
        try:
            workspace_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            
            async with self.session.get(
                f"{workspace_url}/providers/Microsoft.SecurityInsights/incidents",
                params={'$filter': 'properties/status eq \'Active\'', '$top': str(limit)}
            ) as response:
                
                if response.status != 200:
                    return []
                
                incidents = await response.json()
                
                alerts = []
                for incident in incidents.get('value', []):
                    props = incident.get('properties', {})
                    
                    alert = PlatformAlert(
                        id=incident.get('name', ''),
                        platform='sentinel',
                        title=props.get('displayName', 'Sentinel Incident'),
                        description=props.get('description', ''),
                        severity=props.get('severity', 'Medium'),
                        status=props.get('status', 'Active'),
                        created_time=datetime.fromisoformat(props.get('createdTimeUtc', datetime.now().isoformat())),
                        assigned_to=props.get('owner', {}).get('assignedTo'),
                        indicators=[],
                        raw_data=incident
                    )
                    alerts.append(alert)
                
                return alerts
                
        except Exception as e:
            self.logger.error(f"Failed to get Sentinel incidents: {e}")
            return []
    
    async def send_data(self, data: Dict[str, Any], log_type: str = 'CyberGuard_CL') -> bool:
        """Send data to Sentinel."""
        try:
            workspace_url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            
            # Format data for Sentinel
            records = [{
                'Time': datetime.now().isoformat(),
                'Computer': data.get('host', 'cyberguard'),
                'Source': data.get('source', 'cyberguard'),
                'EventType': data.get('event_type', 'SecurityEvent'),
                'Details': json.dumps(data)
            }]
            
            async with self.session.post(
                f"{workspace_url}/api/logs/{log_type}?api-version=2020-08-01",
                json={'records': records}
            ) as response:
                
                return response.status == 200
                
        except Exception as e:
            self.logger.error(f"Failed to send data to Sentinel: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Microsoft Sentinel."""
        if self.session:
            await self.session.close()
        self.status = IntegrationStatus.DISCONNECTED


class AlienVaultUSMIntegration:
    """Integration with AlienVault USM (now Open Threat Connect)."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.base_url = config.get('base_url', '')
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.api_key = config.get('api_key', '')
        self.status = IntegrationStatus.DISCONNECTED
        
        self.session = None
        
    async def connect(self) -> bool:
        """Connect to AlienVault USM."""
        try:
            self.status = IntegrationStatus.CONNECTING
            
            headers = {}
            auth = None
            
            if self.api_key:
                headers['X-OTX-API-KEY'] = self.api_key
            elif self.username and self.password:
                auth = aiohttp.BasicAuth(self.username, self.password)
            
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            self.session = aiohttp.ClientSession(
                auth=auth,
                headers=headers,
                connector=connector,
                timeout=timeout
            )
            
            # Test connection
            await self._test_connection()
            
            self.status = IntegrationStatus.CONNECTED
            self.logger.info("Successfully connected to AlienVault USM")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to AlienVault USM: {e}")
            self.status = IntegrationStatus.ERROR
            return False
    
    async def _test_connection(self):
        """Test AlienVault USM connection."""
        async with self.session.get(f"{self.base_url}/health") as response:
            if response.status != 200:
                raise Exception(f"Connection failed: {response.status}")
    
    async def search_events(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search events in AlienVault USM."""
        try:
            search_params = {
                'query': query,
                'limit': limit,
                'sort': 'timestamp:desc'
            }
            
            async with self.session.get(
                f"{self.base_url}/api/2.0/events",
                params=search_params
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    return data.get('events', [])
                else:
                    raise Exception(f"Search failed: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"AlienVault USM search failed: {e}")
            return []
    
    async def create_indicator(self, indicator_data: Dict[str, Any]) -> bool:
        """Create threat indicator in AlienVault."""
        try:
            indicator = {
                'type': indicator_data.get('type', 'IPv4'),
                'indicator': indicator_data.get('indicator', ''),
                'title': indicator_data.get('title', ''),
                'description': indicator_data.get('description', ''),
                'tlp': indicator_data.get('tlp', 'AMBER'),
                'confidence': indicator_data.get('confidence', 50),
                'tags': indicator_data.get('tags', [])
            }
            
            async with self.session.post(
                f"{self.base_url}/api/2.0/indicators",
                json=indicator
            ) as response:
                
                return response.status in [200, 201]
                
        except Exception as e:
            self.logger.error(f"Failed to create AlienVault indicator: {e}")
            return False
    
    async def get_threat_indicators(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get threat indicators from AlienVault."""
        try:
            async with self.session.get(
                f"{self.base_url}/api/2.0/indicators",
                params={'limit': limit, 'type': 'IPv4'}
            ) as response:
                
                if response.status == 200:
                    data = await response.json()
                    return data.get('results', [])
                else:
                    return []
                    
        except Exception as e:
            self.logger.error(f"Failed to get AlienVault indicators: {e}")
            return []
    
    async def disconnect(self):
        """Disconnect from AlienVault USM."""
        if self.session:
            await self.session.close()
        self.status = IntegrationStatus.DISCONNECTED


class CommercialIntegrationManager:
    """Manages all commercial platform integrations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize platform integrations
        self.integrations = {}
        
        # Splunk
        if config.get('splunk', {}).get('enabled', False):
            self.integrations['splunk'] = SplunkIntegration(config.get('splunk', {}))
        
        # IBM QRadar
        if config.get('qradar', {}).get('enabled', False):
            self.integrations['qradar'] = IBMQRadarIntegration(config.get('qradar', {}))
        
        # Microsoft Sentinel
        if config.get('sentinel', {}).get('enabled', False):
            self.integrations['sentinel'] = MicrosoftSentinelIntegration(config.get('sentinel', {}))
        
        # AlienVault USM
        if config.get('alienvault', {}).get('enabled', False):
            self.integrations['alienvault'] = AlienVaultUSMIntegration(config.get('alienvault', {}))
        
        self.logger.info(f"Initialized {len(self.integrations)} commercial integrations")
    
    async def connect_all(self) -> Dict[str, bool]:
        """Connect to all configured platforms."""
        results = {}
        
        for platform, integration in self.integrations.items():
            try:
                success = await integration.connect()
                results[platform] = success
                
                if success:
                    self.logger.info(f"Successfully connected to {platform}")
                else:
                    self.logger.warning(f"Failed to connect to {platform}")
                    
            except Exception as e:
                self.logger.error(f"Error connecting to {platform}: {e}")
                results[platform] = False
        
        return results
    
    async def disconnect_all(self):
        """Disconnect from all platforms."""
        for integration in self.integrations.values():
            await integration.disconnect()
    
    async def search_all_platforms(self, query: str) -> Dict[str, List[Dict[str, Any]]]:
        """Execute search query across all connected platforms."""
        results = {}
        
        for platform, integration in self.integrations.items():
            if integration.status == IntegrationStatus.CONNECTED:
                try:
                    platform_results = await integration.search(query)
                    results[platform] = platform_results
                except Exception as e:
                    self.logger.error(f"Search failed on {platform}: {e}")
                    results[platform] = []
            else:
                results[platform] = []
        
        return results
    
    async def get_all_alerts(self) -> List[PlatformAlert]:
        """Get alerts from all connected platforms."""
        all_alerts = []
        
        for platform, integration in self.integrations.items():
            if integration.status == IntegrationStatus.CONNECTED:
                try:
                    alerts = await integration.get_alerts()
                    all_alerts.extend(alerts)
                except Exception as e:
                    self.logger.error(f"Failed to get alerts from {platform}: {e}")
        
        return all_alerts
    
    async def send_threat_to_all_platforms(self, threat_data: Dict[str, Any]) -> Dict[str, bool]:
        """Send threat data to all connected platforms."""
        results = {}
        
        for platform, integration in self.integrations.items():
            if integration.status == IntegrationStatus.CONNECTED:
                try:
                    if hasattr(integration, 'send_data'):
                        success = await integration.send_data(threat_data)
                        results[platform] = success
                    else:
                        results[platform] = False
                except Exception as e:
                    self.logger.error(f"Failed to send threat to {platform}: {e}")
                    results[platform] = False
            else:
                results[platform] = False
        
        return results
    
    def get_integration_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all integrations."""
        status_info = {}
        
        for platform, integration in self.integrations.items():
            status_info[platform] = {
                'status': integration.status.value,
                'connected': integration.status == IntegrationStatus.CONNECTED,
                'platform_type': type(integration).__name__
            }
        
        return status_info
    
    def get_platform_statistics(self) -> Dict[str, Any]:
        """Get statistics from all platforms."""
        total_alerts = 0
        connected_platforms = 0
        platform_stats = {}
        
        for platform, integration in self.integrations.items():
            if integration.status == IntegrationStatus.CONNECTED:
                connected_platforms += 1
                platform_stats[platform] = {
                    'status': 'connected',
                    'type': type(integration).__name__
                }
            else:
                platform_stats[platform] = {
                    'status': integration.status.value,
                    'type': type(integration).__name__
                }
        
        return {
            'total_integrations': len(self.integrations),
            'connected_platforms': connected_platforms,
            'platform_details': platform_stats
        }