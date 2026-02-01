"""
Integration Manager for CyberGuard

Coordinates all third-party integrations including threat intelligence feeds,
threat hunting engines, commercial platforms, and external security tools.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from .threat_intelligence import ThreatIntelligenceManager
from .threat_hunting import ThreatHuntingEngine
from .commercial import CommercialIntegrationManager
from .cloud import IntegrationManager as CloudIntegrationManager


class CyberGuardIntegrationManager:
    """Main integration manager coordinating all CyberGuard integrations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the integration manager."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Integration components
        self.threat_intelligence = None
        self.threat_hunting = None
        self.commercial_platforms = None
        self.cloud_integration = None
        
        # Integration status
        self.status = {
            'threat_intelligence': False,
            'threat_hunting': False,
            'commercial_platforms': False,
            'cloud_integration': False
        }
        
        # Initialize components
        self._initialize_integrations()
    
    def _initialize_integrations(self):
        """Initialize all integration components."""
        try:
            # Initialize threat intelligence
            ti_config = self.config.get('threat_intelligence', {})
            if ti_config.get('enabled', True):
                self.threat_intelligence = ThreatIntelligenceManager(ti_config)
                self.logger.info("Threat Intelligence Manager initialized")
            
            # Initialize threat hunting
            th_config = self.config.get('threat_hunting', {})
            if th_config.get('enabled', True):
                self.threat_hunting = ThreatHuntingEngine(th_config)
                # Set threat intelligence reference for hunting
                if self.threat_intelligence:
                    self.threat_hunting.threat_intelligence = self.threat_intelligence
                self.logger.info("Threat Hunting Engine initialized")
            
            # Initialize commercial platforms
            commercial_config = self.config.get('commercial_platforms', {})
            if commercial_config.get('enabled', False):
                self.commercial_platforms = CommercialIntegrationManager(commercial_config)
                self.logger.info("Commercial Platform Integrations initialized")
            
            # Initialize cloud integration
            cloud_config = self.config.get('cloud_integration', {})
            if cloud_config.get('enabled', False):
                self.cloud_integration = CloudIntegrationManager(cloud_config)
                self.logger.info("Cloud Integration initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing integrations: {e}")
    
    async def start_all(self):
        """Start all integration components."""
        try:
            self.logger.info("Starting all integration components...")
            
            # Start threat intelligence
            if self.threat_intelligence:
                await self.threat_intelligence.start()
                self.status['threat_intelligence'] = True
                self.logger.info("Threat Intelligence started")
            
            # Start threat hunting
            if self.threat_hunting:
                await self.threat_hunting.start()
                self.status['threat_hunting'] = True
                self.logger.info("Threat Hunting started")
            
            # Connect to commercial platforms
            if self.commercial_platforms:
                results = await self.commercial_platforms.connect_all()
                self.status['commercial_platforms'] = any(results.values())
                self.logger.info(f"Commercial platforms connection results: {results}")
            
            # Start cloud integration
            if self.cloud_integration:
                await self.cloud_integration.initialize()
                self.status['cloud_integration'] = True
                self.logger.info("Cloud integration started")
            
            self.logger.info("All integration components started")
            
        except Exception as e:
            self.logger.error(f"Error starting integration components: {e}")
            raise
    
    async def stop_all(self):
        """Stop all integration components."""
        try:
            self.logger.info("Stopping all integration components...")
            
            # Stop threat intelligence
            if self.threat_intelligence:
                self.logger.info("Stopping Threat Intelligence...")
            
            # Stop threat hunting
            if self.threat_hunting:
                self.logger.info("Stopping Threat Hunting...")
            
            # Disconnect commercial platforms
            if self.commercial_platforms:
                await self.commercial_platforms.disconnect_all()
                self.status['commercial_platforms'] = False
            
            # Stop cloud integration
            if self.cloud_integration:
                self.logger.info("Stopping Cloud Integration...")
            
            # Reset status
            self.status = {key: False for key in self.status.keys()}
            
            self.logger.info("All integration components stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping integration components: {e}")
    
    async def enhance_threat_detection(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance threat detection using external intelligence."""
        enhanced_threat = threat_data.copy()
        
        try:
            # Extract indicators from threat
            indicators = self._extract_indicators_from_threat(threat_data)
            
            # Look up indicators in threat intelligence
            if self.threat_intelligence and indicators:
                threat_intel_matches = []
                
                for indicator in indicators:
                    intel_match = await self.threat_intelligence.lookup_indicator(indicator)
                    if intel_match and intel_match.confidence > 0.5:
                        threat_intel_matches.append({
                            'indicator': indicator,
                            'threat_type': intel_match.threat_type,
                            'confidence': intel_match.confidence,
                            'source': intel_match.source,
                            'severity': intel_match.severity
                        })
                
                if threat_intel_matches:
                    enhanced_threat['threat_intelligence'] = {
                        'matches': threat_intel_matches,
                        'overall_confidence': max(match['confidence'] for match in threat_intel_matches),
                        'enhanced_severity': self._calculate_enhanced_severity(threat_data, threat_intel_matches)
                    }
            
            # Check against commercial platform intelligence
            if self.commercial_platforms:
                platform_matches = await self._check_commercial_platforms(indicators)
                if platform_matches:
                    enhanced_threat['commercial_intelligence'] = platform_matches
            
            # Use cloud integration for additional context
            if self.cloud_integration:
                cloud_context = await self._get_cloud_security_context(indicators)
                if cloud_context:
                    enhanced_threat['cloud_context'] = cloud_context
            
        except Exception as e:
            self.logger.error(f"Error enhancing threat detection: {e}")
        
        return enhanced_threat
    
    async def run_automated_threat_hunting(self) -> List[Dict[str, Any]]:
        """Run automated threat hunting across all platforms."""
        hunting_results = []
        
        try:
            if self.threat_hunting:
                # Run hunting statistics
                hunt_stats = self.threat_hunting.get_hunt_statistics()
                hunting_results.append({
                    'type': 'hunting_statistics',
                    'data': hunt_stats,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Get recent hunt results
                hunt_results = self.threat_hunting.get_hunt_results(limit=10)
                for result in hunt_results:
                    hunting_results.append({
                        'type': 'hunt_result',
                        'data': result,
                        'timestamp': datetime.now().isoformat()
                    })
                
                # Get hypothesis status
                hypotheses = self.threat_hunting.get_hypotheses_status()
                hunting_results.append({
                    'type': 'hypotheses_status',
                    'data': hypotheses,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Search across commercial platforms
            if self.commercial_platforms:
                platform_alerts = await self.commercial_platforms.get_all_alerts()
                for alert in platform_alerts:
                    hunting_results.append({
                        'type': 'platform_alert',
                        'data': alert,
                        'timestamp': datetime.now().isoformat()
                    })
            
        except Exception as e:
            self.logger.error(f"Error in automated threat hunting: {e}")
        
        return hunting_results
    
    async def correlate_threat_intelligence(self, indicators: List[str]) -> Dict[str, Any]:
        """Correlate threat intelligence across multiple sources."""
        correlation_result = {
            'indicators': indicators,
            'matches': {},
            'overall_confidence': 0.0,
            'sources': [],
            'recommendations': []
        }
        
        try:
            # Check threat intelligence sources
            if self.threat_intelligence:
                for indicator in indicators:
                    intel_match = await self.threat_intelligence.lookup_indicator(indicator)
                    if intel_match:
                        correlation_result['matches'][indicator] = {
                            'threat_intelligence': {
                                'threat_type': intel_match.threat_type,
                                'confidence': intel_match.confidence,
                                'severity': intel_match.severity,
                                'source': intel_match.source,
                                'tags': intel_match.tags
                            }
                        }
                        correlation_result['sources'].append(f"TI_{intel_match.source}")
            
            # Check commercial platforms
            if self.commercial_platforms:
                platform_results = await self.commercial_platforms.search_all_platforms(' OR '.join([f'"{ind}"' for ind in indicators]))
                for platform, results in platform_results.items():
                    if results:
                        for indicator in indicators:
                            if indicator not in correlation_result['matches']:
                                correlation_result['matches'][indicator] = {}
                            
                            correlation_result['matches'][indicator][f'platform_{platform}'] = {
                                'results': results,
                                'platform': platform
                            }
                            correlation_result['sources'].append(f"Platform_{platform}")
            
            # Calculate overall confidence
            if correlation_result['matches']:
                all_confidences = []
                for indicator_matches in correlation_result['matches'].values():
                    for source, data in indicator_matches.items():
                        if isinstance(data, dict) and 'confidence' in data:
                            all_confidences.append(data['confidence'])
                
                if all_confidences:
                    correlation_result['overall_confidence'] = max(all_confidences)
            
            # Generate recommendations
            correlation_result['recommendations'] = self._generate_correlation_recommendations(correlation_result)
            
        except Exception as e:
            self.logger.error(f"Error correlating threat intelligence: {e}")
        
        return correlation_result
    
    async def get_integration_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics from all integrations."""
        stats = {
            'integration_status': self.status.copy(),
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Threat intelligence statistics
            if self.threat_intelligence:
                stats['threat_intelligence'] = self.threat_intelligence.get_statistics()
            
            # Threat hunting statistics
            if self.threat_hunting:
                stats['threat_hunting'] = self.threat_hunting.get_hunt_statistics()
            
            # Commercial platform statistics
            if self.commercial_platforms:
                stats['commercial_platforms'] = self.commercial_platforms.get_platform_statistics()
            
            # Cloud integration statistics
            if self.cloud_integration:
                stats['cloud_integration'] = {
                    'status': 'active',
                    'platforms': list(self.cloud_integration.integrations.keys()) if hasattr(self.cloud_integration, 'integrations') else []
                }
            
        except Exception as e:
            self.logger.error(f"Error getting integration statistics: {e}")
        
        return stats
    
    def _extract_indicators_from_threat(self, threat_data: Dict[str, Any]) -> List[str]:
        """Extract threat indicators from threat data."""
        indicators = []
        
        # Common indicator fields
        indicator_fields = [
            'source_ip', 'destination_ip', 'ip', 'domain', 'url', 'hash',
            'filename', 'user', 'process_name', 'command_line'
        ]
        
        for field in indicator_fields:
            if field in threat_data:
                value = threat_data[field]
                if isinstance(value, str) and value.strip():
                    indicators.append(value.strip())
                elif isinstance(value, list):
                    indicators.extend([v for v in value if isinstance(v, str) and v.strip()])
        
        return list(set(indicators))  # Remove duplicates
    
    async def _check_commercial_platforms(self, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Check indicators against commercial platform intelligence."""
        if not self.commercial_platforms:
            return None
        
        try:
            # Search each platform for indicators
            all_results = {}
            
            for indicator in indicators[:5]:  # Limit to 5 indicators
                query = f'"{indicator}" OR {indicator}'
                results = await self.commercial_platforms.search_all_platforms(query)
                
                for platform, platform_results in results.items():
                    if platform_results:
                        if platform not in all_results:
                            all_results[platform] = []
                        all_results[platform].extend(platform_results)
            
            return all_results if all_results else None
            
        except Exception as e:
            self.logger.error(f"Error checking commercial platforms: {e}")
            return None
    
    async def _get_cloud_security_context(self, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Get cloud security context for indicators."""
        if not self.cloud_integration:
            return None
        
        try:
            context_data = {}
            
            # Get external threat intelligence from cloud integration
            threats = await self.cloud_integration.get_external_threat_intelligence()
            
            # Filter threats by indicators
            for threat in threats:
                for indicator in indicators:
                    if indicator in str(threat):
                        if 'cloud_threats' not in context_data:
                            context_data['cloud_threats'] = []
                        context_data['cloud_threats'].append(threat)
            
            return context_data if context_data else None
            
        except Exception as e:
            self.logger.error(f"Error getting cloud security context: {e}")
            return None
    
    def _calculate_enhanced_severity(self, original_threat: Dict[str, Any], intel_matches: List[Dict[str, Any]]) -> str:
        """Calculate enhanced severity based on threat intelligence."""
        original_severity = original_threat.get('severity', 'medium')
        original_score = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(original_severity, 2)
        
        # Factor in intelligence matches
        enhanced_score = original_score
        
        for match in intel_matches:
            intel_severity = match.get('severity', 'medium')
            intel_score = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(intel_severity, 2)
            confidence = match.get('confidence', 0.5)
            
            # Weight the intelligence score by confidence
            weighted_score = intel_score * confidence
            enhanced_score = max(enhanced_score, weighted_score)
        
        # Map back to severity
        score_to_severity = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        enhanced_score = min(4, max(1, round(enhanced_score)))
        
        return score_to_severity.get(enhanced_score, 'medium')
    
    def _generate_correlation_recommendations(self, correlation_result: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on threat intelligence correlation."""
        recommendations = []
        
        try:
            matches = correlation_result.get('matches', {})
            
            if not matches:
                return ["No threat intelligence matches found for provided indicators"]
            
            # High confidence recommendations
            high_confidence_matches = 0
            critical_severity_matches = 0
            
            for indicator_data in matches.values():
                for source_data in indicator_data.values():
                    if isinstance(source_data, dict):
                        confidence = source_data.get('confidence', 0)
                        severity = source_data.get('severity', '').lower()
                        
                        if confidence > 0.8:
                            high_confidence_matches += 1
                        
                        if severity == 'critical':
                            critical_severity_matches += 1
            
            # Generate specific recommendations
            if critical_severity_matches > 0:
                recommendations.append("CRITICAL: Immediate investigation required - critical threat intelligence matches found")
            
            if high_confidence_matches > 2:
                recommendations.append("HIGH: Multiple high-confidence threat intelligence matches - prioritize investigation")
            
            if len(matches) > 5:
                recommendations.append("MEDIUM: Multiple indicators have threat intelligence matches - review and monitor")
            
            # Source-specific recommendations
            sources = correlation_result.get('sources', [])
            if any('TI_Commercial' in source for source in sources):
                recommendations.append("Commercial threat intelligence sources confirm threat indicators")
            
            if any('Platform_Splunk' in source for source in sources):
                recommendations.append("Splunk platform contains related threat activity")
            
            if any('Platform_QRadar' in source for source in sources):
                recommendations.append("QRadar platform contains related threat activity")
            
            # Default recommendation
            if not recommendations:
                recommendations.append("Review threat intelligence matches and consider additional investigation")
                
        except Exception as e:
            self.logger.error(f"Error generating correlation recommendations: {e}")
            recommendations.append("Error generating recommendations - manual review recommended")
        
        return recommendations
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of all integration statuses."""
        active_integrations = sum(1 for status in self.status.values() if status)
        total_integrations = len(self.status)
        
        return {
            'overall_status': 'active' if active_integrations > 0 else 'inactive',
            'active_integrations': active_integrations,
            'total_integrations': total_integrations,
            'integration_details': self.status.copy(),
            'components': {
                'threat_intelligence': bool(self.threat_intelligence),
                'threat_hunting': bool(self.threat_hunting),
                'commercial_platforms': bool(self.commercial_platforms),
                'cloud_integration': bool(self.cloud_integration)
            }
        }