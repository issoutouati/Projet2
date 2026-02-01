#!/usr/bin/env python3
"""
CLI interface for ACARS (Automated Cyber Attack Response System).
"""

import asyncio
import sys
import json
import click
from pathlib import Path
from typing import Dict, Any
import time
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from acars.main import ACARSApplication
from config.config_manager import ConfigManager


@click.group()
@click.option('--config', '-c', default='/home/engine/project/config/config.yaml', help='Configuration file path')
@click.pass_context
def cli(ctx, config):
    """ACARS - Automated Cyber Attack Response System CLI"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['app'] = None


@cli.command()
@click.option('--daemon', '-d', is_flag=True, help='Run as daemon')
@click.pass_context
def start(ctx, daemon):
    """Start the ACARS system."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    click.echo("Starting ACARS system...")
    
    async def start_app():
        app = ACARSApplication()
        await app.initialize()
        
        if daemon:
            # Run as daemon
            await app.start()
        else:
            # Interactive mode
            try:
                await app.start()
            except KeyboardInterrupt:
                click.echo("\nShutting down ACARS...")
                await app.stop()
                
    if daemon:
        try:
            asyncio.run(start_app())
        except KeyboardInterrupt:
            click.echo("ACARS daemon stopped")
    else:
        asyncio.run(start_app())


@cli.command()
@click.pass_context
def stop(ctx):
    """Stop the ACARS system."""
    click.echo("Stop command not implemented - use Ctrl+C to stop interactive mode")
    
    
@cli.command()
@click.pass_context
def status(ctx):
    """Get ACARS system status."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    async def get_status():
        app = ACARSApplication()
        await app.initialize()
        status = await app.get_status()
        
        # Display status
        click.echo("ACARS System Status")
        click.echo("=" * 50)
        click.echo(f"Running: {status['running']}")
        click.echo(f"Version: {status['version']}")
        click.echo(f"Timestamp: {status['timestamp']}")
        
        if status['statistics']:
            stats = status['statistics']
            click.echo(f"Threats Detected: {stats.get('threats_detected', 0)}")
            click.echo(f"Responses Executed: {stats.get('responses_executed', 0)}")
            
        click.echo("\nDetectors:")
        for name, info in status['detectors'].items():
            click.echo(f"  {name}: {'✓' if info['enabled'] else '✗'}")
            
        click.echo("\nResponse Handlers:")
        for name, info in status['response_handlers'].items():
            click.echo(f"  {name}: {'✓' if info['enabled'] else '✗'}")
            
        click.echo("\nMonitors:")
        for name, info in status['monitors'].items():
            click.echo(f"  {name}: {'✓' if info.get('monitoring', False) else '✗'}")
            
        if 'ml_engine' in status:
            click.echo("\nML Engine:")
            ml_info = status['ml_engine']
            click.echo(f"  Classifier Model: {'✓' if ml_info['classifier']['model_loaded'] else '✗'}")
            click.echo(f"  Anomaly Detector: {'✓' if ml_info['anomaly_detector']['model_trained'] else '✗'}")
            click.echo(f"  Threat Predictor: {'✓' if ml_info['predictor']['model_loaded'] else '✗'}")
            
    asyncio.run(get_status())


@cli.command()
@click.option('--format', 'output_format', default='json', type=click.Choice(['json', 'yaml']), help='Output format')
@click.pass_context
def config_show(ctx, output_format):
    """Show current configuration."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    try:
        config_manager = ConfigManager(config_path)
        config = config_manager.load_config()
        
        if output_format == 'json':
            click.echo(json.dumps(config, indent=2, default=str))
        else:
            import yaml
            click.echo(yaml.dump(config, default_flow_style=False))
            
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--key', required=True, help='Configuration key (dot notation)')
@click.option('--value', required=True, help='New value')
@click.pass_context
def config_set(ctx, key, value):
    """Set configuration value."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    try:
        config_manager = ConfigManager(config_path)
        
        # Try to parse value as appropriate type
        if value.lower() in ('true', 'false'):
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        else:
            try:
                value = float(value)
            except ValueError:
                pass  # Keep as string
                
        config_manager.set(key, value)
        click.echo(f"Configuration updated: {key} = {value}")
        
    except Exception as e:
        click.echo(f"Error updating configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('threat_data', required=False)
@click.pass_context
def test_threat(ctx, threat_data):
    """Test threat detection with provided data."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    async def test_detection():
        app = ACARSApplication()
        await app.initialize()
        
        if threat_data:
            try:
                data = json.loads(threat_data)
            except json.JSONDecodeError:
                click.echo("Invalid JSON data provided", err=True)
                sys.exit(1)
        else:
            # Default test data
            data = {
                'url': '/api/users?id=1 UNION SELECT * FROM users',
                'method': 'GET',
                'source_ip': '192.168.1.100',
                'target': 'web_server'
            }
            click.echo("Using default test data")
            
        click.echo(f"Testing threat detection with: {json.dumps(data, indent=2)}")
        
        # Test through detectors
        from detectors.web_attacks import WebAttackDetector
        from core.system import ThreatEvent, AttackType, ThreatLevel
        
        detector = WebAttackDetector({})
        threat = detector.detect(data)
        
        if threat:
            click.echo(f"Threat Detected!")
            click.echo(f"Type: {threat.attack_type.value}")
            click.echo(f"Level: {threat.threat_level.value}")
            click.echo(f"Confidence: {threat.confidence}")
            click.echo(f"Description: {threat.description}")
            
            # Test ML analysis if available
            if app.ml_engine:
                ml_results = await app.ml_engine.analyze_threat(threat.to_dict())
                click.echo(f"ML Classification: {ml_results.get('classification', {}).get('predicted_type', 'unknown')}")
                click.echo(f"ML Confidence: {ml_results.get('classification', {}).get('confidence', 0.0)}")
        else:
            click.echo("No threat detected")
            
    asyncio.run(test_detection())


@cli.command()
@click.option('--duration', default=10, help='Simulation duration in seconds')
@click.pass_context
def simulate(ctx, duration):
    """Simulate threat detection for testing."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    async def run_simulation():
        app = ACARSApplication()
        await app.initialize()
        
        click.echo(f"Running threat simulation for {duration} seconds...")
        
        end_time = time.time() + duration
        threats_detected = 0
        
        while time.time() < end_time:
            # Simulate threat
            import random
            
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
                }
            ]
            
            threat_data = random.choice(threats)
            
            # Create threat event
            from core.system import ThreatEvent, AttackType, ThreatLevel
            threat = ThreatEvent(
                id=f"sim_{int(time.time())}_{random.randint(1000, 9999)}",
                timestamp=datetime.now(),
                source_ip=threat_data.get('source_ip', 'unknown'),
                target_system=threat_data.get('target', 'system'),
                attack_type=random.choice([AttackType.SQL_INJECTION, AttackType.XSS, AttackType.DDOS]),
                threat_level=random.choice([ThreatLevel.MEDIUM, ThreatLevel.HIGH]),
                confidence=random.uniform(0.6, 0.9),
                description="Simulated threat for testing",
                raw_data=threat_data,
                tags=['simulation']
            )
            
            # Process threat
            app.core.threat_queue.put(threat)
            threats_detected += 1
            
            click.echo(f"[{datetime.now().strftime('%H:%M:%S')}] Threat detected: {threat.attack_type.value} from {threat.source_ip}")
            
            await asyncio.sleep(1)
            
        click.echo(f"\nSimulation completed. Total threats detected: {threats_detected}")
        
    asyncio.run(run_simulation())


@cli.command()
@click.option('--format', 'output_format', default='json', type=click.Choice(['json', 'table']), help='Output format')
@click.pass_context
def threats(ctx, output_format):
    """View recent threats (simulated data)."""
    # This would typically fetch from a database or log file
    # For now, we'll show simulated data
    
    threats = [
        {
            'id': 'threat_001',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '192.168.1.100',
            'attack_type': 'sql_injection',
            'threat_level': 'high',
            'confidence': 0.85,
            'description': 'SQL injection attempt detected'
        },
        {
            'id': 'threat_002',
            'timestamp': datetime.now().isoformat(),
            'source_ip': '10.0.0.50',
            'attack_type': 'xss',
            'threat_level': 'medium',
            'confidence': 0.72,
            'description': 'Cross-site scripting attempt detected'
        }
    ]
    
    if output_format == 'json':
        click.echo(json.dumps(threats, indent=2))
    else:
        click.echo("Recent Threats:")
        click.echo("-" * 80)
        for threat in threats:
            click.echo(f"ID: {threat['id']}")
            click.echo(f"Time: {threat['timestamp']}")
            click.echo(f"Source: {threat['source_ip']}")
            click.echo(f"Type: {threat['attack_type']}")
            click.echo(f"Level: {threat['threat_level']}")
            click.echo(f"Description: {threat['description']}")
            click.echo("-" * 80)


@cli.command()
@click.option('--action', type=click.Choice(['block', 'allow', 'quarantine']), required=True)
@click.argument('target')
@click.pass_context
def response(ctx, action, target):
    """Execute manual response action."""
    config_path = ctx.obj['config']
    
    if not Path(config_path).exists():
        click.echo(f"Configuration file not found: {config_path}", err=True)
        sys.exit(1)
        
    async def execute_response():
        app = ACARSApplication()
        await app.initialize()
        
        from core.system import ThreatEvent, AttackType, ThreatLevel
        
        # Create a manual threat for the response
        threat = ThreatEvent(
            id=f"manual_{int(time.time())}",
            timestamp=datetime.now(),
            source_ip=target,
            target_system='manual',
            attack_type=AttackType.UNKNOWN,
            threat_level=ThreatLevel.HIGH,
            confidence=1.0,
            description=f"Manual {action} action triggered",
            raw_data={'manual_action': action, 'target': target},
            tags=['manual', 'admin']
        )
        
        click.echo(f"Executing {action} action for target: {target}")
        
        # Execute response
        if action == 'block':
            if 'block_ip_handler' in app.core.response_handlers:
                result = await app.core.response_handlers['block_ip_handler'].execute(threat)
                click.echo(f"Block result: {result.message}")
            else:
                click.echo("Block IP handler not available", err=True)
                
        elif action == 'quarantine':
            if 'quarantine_system_handler' in app.core.response_handlers:
                result = await app.core.response_handlers['quarantine_system_handler'].execute(threat)
                click.echo(f"Quarantine result: {result.message}")
            else:
                click.echo("Quarantine handler not available", err=True)
                
        elif action == 'allow':
            click.echo("Allow action - no blocking or restrictions applied")
            
    asyncio.run(execute_response())


if __name__ == '__main__':
    cli()