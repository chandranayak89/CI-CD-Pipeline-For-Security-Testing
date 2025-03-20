#!/usr/bin/env python3
"""
Security Telemetry Integration

This script collects, processes, and ships security events from the CI/CD pipeline
to monitoring systems like ELK Stack, Prometheus, and Grafana for centralized
visibility and alerting on security issues.
"""

import argparse
import json
import logging
import os
import sys
import time
import uuid
import yaml
from datetime import datetime
from typing import Dict, List, Any, Union, Optional
import threading
import queue

# Third-party imports - these will need to be installed
try:
    import requests
    import elasticsearch
    from prometheus_client import CollectorRegistry, Gauge, Counter, push_to_gateway
except ImportError:
    print("Please install required packages: pip install requests elasticsearch prometheus_client pyyaml")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("security-telemetry")


class TelemetryConfigError(Exception):
    """Exception raised for errors in the telemetry configuration."""
    pass


class TelemetryEvent:
    """Class representing a telemetry event."""
    
    def __init__(self, event_type: str, source: str, data: Dict[str, Any]):
        """
        Initialize a telemetry event.
        
        Args:
            event_type: Type of event (scan, gate, deployment, etc.)
            source: Source of the event (tool name, pipeline step, etc.)
            data: Event data (findings, status, etc.)
        """
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.event_type = event_type
        self.source = source
        self.data = data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'source': self.source,
            'data': self.data
        }
    
    def __str__(self) -> str:
        """String representation of the event."""
        return f"Event[{self.event_type}] from {self.source} at {self.timestamp}"


class SecurityTelemetry:
    """Main class for security telemetry processing."""
    
    def __init__(self, config_file: str, log_level: str = "INFO"):
        """
        Initialize the security telemetry system.
        
        Args:
            config_file: Path to telemetry configuration file
            log_level: Logging level
        """
        # Set up logging
        log_level_enum = getattr(logging, log_level.upper(), logging.INFO)
        logger.setLevel(log_level_enum)
        
        # Load configuration
        self.config = self._load_config(config_file)
        
        # Check if telemetry is enabled
        if not self.config.get('settings', {}).get('enabled', True):
            logger.info("Security telemetry is disabled in configuration")
            sys.exit(0)
        
        # Initialize providers
        self.providers = {}
        self._init_providers()
        
        # Set up event queue
        self.event_queue = queue.Queue(maxsize=self.config.get('settings', {}).get('buffer_size', 1000))
        self.stop_event = threading.Event()
        
        # Create processing thread
        self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Dictionary containing configuration
        """
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                logger.debug(f"Loaded configuration from {config_file}")
                return config
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_file}: {str(e)}")
            raise TelemetryConfigError(f"Failed to load configuration: {str(e)}")
    
    def _init_providers(self) -> None:
        """Initialize telemetry providers based on configuration."""
        provider_configs = self.config.get('providers', {})
        
        # Initialize Elasticsearch if enabled
        if provider_configs.get('elasticsearch', {}).get('enabled', False):
            try:
                self._init_elasticsearch(provider_configs['elasticsearch'])
                logger.info("Elasticsearch provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Elasticsearch provider: {str(e)}")
        
        # Initialize Prometheus if enabled
        if provider_configs.get('prometheus', {}).get('enabled', False):
            try:
                self._init_prometheus(provider_configs['prometheus'])
                logger.info("Prometheus provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Prometheus provider: {str(e)}")
        
        # Initialize Grafana if enabled
        if provider_configs.get('grafana', {}).get('enabled', False):
            try:
                # We'll create dashboards on demand, no need to initialize here
                logger.info("Grafana provider initialized")
                self.providers['grafana'] = provider_configs['grafana']
            except Exception as e:
                logger.error(f"Failed to initialize Grafana provider: {str(e)}")
        
        # Initialize Slack if enabled
        if provider_configs.get('slack', {}).get('enabled', False):
            try:
                self.providers['slack'] = provider_configs['slack']
                logger.info("Slack provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Slack provider: {str(e)}")
    
    def _init_elasticsearch(self, config: Dict[str, Any]) -> None:
        """
        Initialize Elasticsearch client.
        
        Args:
            config: Elasticsearch configuration
        """
        # Get configuration values with environment variable fallbacks
        es_url = self._resolve_env_var(config.get('url', 'http://elasticsearch:9200'))
        es_username = self._resolve_env_var(config.get('username', 'elastic'))
        es_password = self._resolve_env_var(config.get('password', ''))
        
        # Create Elasticsearch client
        es_client = elasticsearch.Elasticsearch(
            [es_url],
            http_auth=(es_username, es_password) if es_username and es_password else None,
            verify_certs=config.get('ssl_verify', True)
        )
        
        # Test connection
        if not es_client.ping():
            raise ConnectionError(f"Cannot connect to Elasticsearch at {es_url}")
        
        self.providers['elasticsearch'] = {
            'client': es_client,
            'index_prefix': config.get('index_prefix', 'security-pipeline'),
            'mappings': config.get('mappings', {})
        }
    
    def _init_prometheus(self, config: Dict[str, Any]) -> None:
        """
        Initialize Prometheus metrics.
        
        Args:
            config: Prometheus configuration
        """
        # Create Prometheus registry
        registry = CollectorRegistry()
        
        # Create metrics from configuration
        metrics = {}
        for metric_config in config.get('metrics', []):
            metric_name = metric_config.get('name')
            metric_type = metric_config.get('type', 'gauge')
            metric_help = metric_config.get('help', '')
            metric_labels = metric_config.get('labels', [])
            
            if metric_type == 'gauge':
                metrics[metric_name] = Gauge(
                    metric_name, 
                    metric_help, 
                    metric_labels,
                    registry=registry
                )
            elif metric_type == 'counter':
                metrics[metric_name] = Counter(
                    metric_name, 
                    metric_help, 
                    metric_labels,
                    registry=registry
                )
        
        self.providers['prometheus'] = {
            'registry': registry,
            'metrics': metrics,
            'push_gateway': self._resolve_env_var(config.get('push_gateway', 'http://prometheus-pushgateway:9091')),
            'job_prefix': config.get('job_prefix', 'security-pipeline')
        }
    
    def _process_events(self) -> None:
        """Process events from the queue and ship to providers."""
        last_flush_time = time.time()
        batch_interval = self.config.get('settings', {}).get('batch_interval', 60)
        events_batch = []
        
        while not self.stop_event.is_set() or not self.event_queue.empty():
            try:
                # Try to get an event with a timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    events_batch.append(event)
                    self.event_queue.task_done()
                except queue.Empty:
                    pass
                
                # Check if we should flush based on time or batch size
                current_time = time.time()
                if (current_time - last_flush_time >= batch_interval or 
                        len(events_batch) >= self.config.get('settings', {}).get('buffer_size', 1000) // 2):
                    if events_batch:
                        self._ship_events(events_batch)
                        events_batch = []
                        last_flush_time = current_time
            
            except Exception as e:
                logger.error(f"Error processing events: {str(e)}")
        
        # Final flush of any remaining events
        if events_batch:
            try:
                self._ship_events(events_batch)
            except Exception as e:
                logger.error(f"Error shipping final events batch: {str(e)}")
    
    def _ship_events(self, events: List[TelemetryEvent]) -> None:
        """
        Ship events to all configured providers.
        
        Args:
            events: List of events to ship
        """
        if 'elasticsearch' in self.providers:
            self._ship_to_elasticsearch(events)
        
        if 'prometheus' in self.providers:
            self._ship_to_prometheus(events)
        
        # Check if any events require alerting via Slack
        if 'slack' in self.providers:
            self._send_alerts_to_slack(events)
    
    def _ship_to_elasticsearch(self, events: List[TelemetryEvent]) -> None:
        """
        Ship events to Elasticsearch.
        
        Args:
            events: List of events to ship
        """
        es_provider = self.providers['elasticsearch']
        es_client = es_provider['client']
        index_prefix = es_provider['index_prefix']
        mappings = es_provider['mappings']
        
        # Group events by type for bulk indexing
        events_by_type = {}
        for event in events:
            event_type = event.event_type
            if event_type not in events_by_type:
                events_by_type[event_type] = []
            events_by_type[event_type].append(event.to_dict())
        
        # Index each group of events
        for event_type, event_list in events_by_type.items():
            # Determine index name
            index_name = f"{index_prefix}-{mappings.get(event_type, 'events')}"
            
            # Prepare bulk actions
            actions = []
            for event_data in event_list:
                actions.append({
                    "_index": index_name,
                    "_id": event_data['id'],
                    "_source": event_data
                })
            
            # Execute bulk indexing
            if actions:
                try:
                    elasticsearch.helpers.bulk(es_client, actions)
                    logger.debug(f"Indexed {len(actions)} events to {index_name}")
                except Exception as e:
                    logger.error(f"Failed to index events to Elasticsearch: {str(e)}")
    
    def _ship_to_prometheus(self, events: List[TelemetryEvent]) -> None:
        """
        Ship events as metrics to Prometheus.
        
        Args:
            events: List of events to ship
        """
        prom_provider = self.providers['prometheus']
        registry = prom_provider['registry']
        metrics = prom_provider['metrics']
        push_gateway = prom_provider['push_gateway']
        job_prefix = prom_provider['job_prefix']
        
        # Update metrics based on events
        for event in events:
            event_data = event.to_dict()
            
            # Process security gate status events
            if event.event_type == 'security_gates' and 'security_gate_status' in metrics:
                if 'result' in event_data['data']:
                    environment = event_data['data'].get('environment', 'unknown')
                    gate_type = event_data['data'].get('gate_type', 'unknown')
                    status_value = 1 if event_data['data']['result'] else 0
                    metrics['security_gate_status'].labels(environment=environment, gate_type=gate_type).set(status_value)
            
            # Process security findings count
            elif event.event_type == 'security_scans' and 'security_findings_count' in metrics:
                if 'findings' in event_data['data']:
                    tool = event.source
                    for severity, count in event_data['data'].get('findings_by_severity', {}).items():
                        metrics['security_findings_count'].labels(tool=tool, severity=severity).set(count)
            
            # Process security scan duration
            elif event.event_type == 'security_scans' and 'security_scan_duration' in metrics:
                if 'duration' in event_data['data']:
                    scan_type = event.source
                    duration = event_data['data']['duration']
                    metrics['security_scan_duration'].labels(scan_type=scan_type).set(duration)
            
            # Process deployment success rate
            elif event.event_type == 'deployments' and 'deployment_success_rate' in metrics:
                environment = event_data['data'].get('environment', 'unknown')
                success = event_data['data'].get('success', False)
                # We'll use a gauge to track success (1) or failure (0)
                metrics['deployment_success_rate'].labels(environment=environment).set(1 if success else 0)
        
        # Push metrics to Prometheus gateway
        try:
            job_name = f"{job_prefix}-{int(time.time())}"
            push_to_gateway(push_gateway, job=job_name, registry=registry)
            logger.debug(f"Pushed metrics to Prometheus gateway with job {job_name}")
        except Exception as e:
            logger.error(f"Failed to push metrics to Prometheus gateway: {str(e)}")
    
    def _send_alerts_to_slack(self, events: List[TelemetryEvent]) -> None:
        """
        Send alerts to Slack for relevant events.
        
        Args:
            events: List of events to check for alerts
        """
        slack_config = self.providers['slack']
        webhook_url = self._resolve_env_var(slack_config.get('webhook_url', ''))
        channel = slack_config.get('channel', '#security-alerts')
        notify_on = slack_config.get('notify_on', {})
        
        if not webhook_url:
            logger.warning("Slack webhook URL not configured, skipping alerts")
            return
        
        # Check each event for alert conditions
        for event in events:
            event_data = event.to_dict()
            alert_sent = False
            
            # Check for gate failures
            if (event.event_type == 'security_gates' and 
                    event_data['data'].get('result') is False and 
                    notify_on.get('gate_failure', False)):
                self._send_slack_alert(
                    webhook_url,
                    channel,
                    "🚨 Security Gate Failure",
                    f"Security gate '{event_data['data'].get('gate_type', 'unknown')}' failed for environment '{event_data['data'].get('environment', 'unknown')}'.",
                    "danger",
                    event_data
                )
                alert_sent = True
            
            # Check for critical vulnerabilities
            elif (event.event_type == 'security_scans' and 
                    event_data['data'].get('findings_by_severity', {}).get('critical', 0) > 0 and 
                    notify_on.get('critical_vulnerability', False)):
                critical_count = event_data['data']['findings_by_severity']['critical']
                self._send_slack_alert(
                    webhook_url,
                    channel,
                    "🔥 Critical Vulnerabilities Detected",
                    f"{critical_count} critical vulnerabilities found by {event.source}.",
                    "danger",
                    event_data
                )
                alert_sent = True
            
            # Check for deployment failures
            elif (event.event_type == 'deployments' and 
                    event_data['data'].get('success') is False and 
                    notify_on.get('deployment_failure', False)):
                self._send_slack_alert(
                    webhook_url,
                    channel,
                    "❌ Deployment Failure",
                    f"Deployment to '{event_data['data'].get('environment', 'unknown')}' failed due to security issues.",
                    "danger",
                    event_data
                )
                alert_sent = True
            
            # Check for compliance failures
            elif (event.event_type == 'compliance' and 
                    event_data['data'].get('compliant') is False and 
                    notify_on.get('compliance_failure', False)):
                framework = event_data['data'].get('framework', 'unknown')
                self._send_slack_alert(
                    webhook_url,
                    channel,
                    "⚠️ Compliance Failure",
                    f"Failed to meet compliance requirements for {framework}.",
                    "warning",
                    event_data
                )
                alert_sent = True
            
            if alert_sent:
                logger.debug(f"Sent Slack alert for event {event.id}")
    
    def _send_slack_alert(self, webhook_url: str, channel: str, title: str, message: str, 
                         color: str, event_data: Dict[str, Any]) -> None:
        """
        Send a formatted alert to Slack.
        
        Args:
            webhook_url: Slack webhook URL
            channel: Slack channel to send to
            title: Alert title
            message: Alert message
            color: Alert color (good, warning, danger)
            event_data: Full event data for details
        """
        try:
            # Format the message with details
            payload = {
                "channel": channel,
                "attachments": [
                    {
                        "fallback": title,
                        "color": color,
                        "title": title,
                        "text": message,
                        "fields": [
                            {
                                "title": "Source",
                                "value": event_data['source'],
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": event_data['timestamp'],
                                "short": True
                            }
                        ],
                        "footer": "Security Telemetry",
                        "ts": int(time.time())
                    }
                ]
            }
            
            # Add details based on event type
            if event_data['event_type'] == 'security_gates':
                payload['attachments'][0]['fields'].append({
                    "title": "Gate Type",
                    "value": event_data['data'].get('gate_type', 'unknown'),
                    "short": True
                })
                payload['attachments'][0]['fields'].append({
                    "title": "Environment",
                    "value": event_data['data'].get('environment', 'unknown'),
                    "short": True
                })
            
            elif event_data['event_type'] == 'security_scans':
                findings = event_data['data'].get('findings_by_severity', {})
                findings_text = "\n".join([f"{sev}: {count}" for sev, count in findings.items()])
                payload['attachments'][0]['fields'].append({
                    "title": "Findings",
                    "value": findings_text or "None",
                    "short": False
                })
            
            # Send the message
            response = requests.post(webhook_url, json=payload)
            if response.status_code != 200:
                logger.error(f"Failed to send Slack alert: {response.status_code} {response.text}")
        
        except Exception as e:
            logger.error(f"Error sending Slack alert: {str(e)}")
    
    def _create_grafana_dashboards(self) -> None:
        """Create or update Grafana dashboards for security telemetry."""
        if 'grafana' not in self.providers:
            return
        
        grafana_config = self.providers['grafana']
        grafana_url = self._resolve_env_var(grafana_config.get('url', 'http://grafana:3000'))
        api_key = self._resolve_env_var(grafana_config.get('api_key', ''))
        dashboard_folder = grafana_config.get('dashboard_folder', 'Security Pipeline')
        org_id = grafana_config.get('organization_id', 1)
        
        if not api_key:
            logger.warning("Grafana API key not configured, skipping dashboard creation")
            return
        
        # Dashboard definitions from config
        dashboard_configs = self.config.get('dashboards', {})
        
        # Check if folder exists, create if not
        folder_id = self._get_or_create_grafana_folder(grafana_url, api_key, dashboard_folder, org_id)
        
        # Create each dashboard
        for dashboard_key, dashboard_config in dashboard_configs.items():
            try:
                self._create_grafana_dashboard(
                    grafana_url, 
                    api_key, 
                    dashboard_config, 
                    folder_id, 
                    org_id
                )
                logger.info(f"Created/updated Grafana dashboard: {dashboard_config.get('title')}")
            except Exception as e:
                logger.error(f"Failed to create Grafana dashboard {dashboard_key}: {str(e)}")
    
    def _get_or_create_grafana_folder(self, grafana_url: str, api_key: str, 
                                     folder_name: str, org_id: int) -> int:
        """
        Get or create a folder in Grafana.
        
        Args:
            grafana_url: Grafana URL
            api_key: Grafana API key
            folder_name: Folder name
            org_id: Organization ID
            
        Returns:
            Folder ID
        """
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        # Check if folder exists
        response = requests.get(
            f"{grafana_url}/api/folders",
            headers=headers
        )
        response.raise_for_status()
        
        folders = response.json()
        for folder in folders:
            if folder['title'] == folder_name:
                return folder['id']
        
        # Create folder if it doesn't exist
        payload = {
            "title": folder_name
        }
        
        response = requests.post(
            f"{grafana_url}/api/folders",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        
        return response.json()['id']
    
    def _create_grafana_dashboard(self, grafana_url: str, api_key: str, 
                                dashboard_config: Dict[str, Any], folder_id: int, org_id: int) -> None:
        """
        Create or update a Grafana dashboard.
        
        Args:
            grafana_url: Grafana URL
            api_key: Grafana API key
            dashboard_config: Dashboard configuration
            folder_id: Folder ID
            org_id: Organization ID
        """
        # This is a simplified implementation that would need to be expanded
        # for actual dashboard generation with real panels
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        # Create a basic dashboard structure
        dashboard = {
            "dashboard": {
                "id": None,
                "title": dashboard_config.get('title', 'Security Dashboard'),
                "tags": ["security", "ci-cd", "telemetry"],
                "timezone": "browser",
                "refresh": dashboard_config.get('refresh', '5m'),
                "schemaVersion": 26,
                "version": 1,
                "panels": []
            },
            "folderId": folder_id,
            "overwrite": True
        }
        
        # This is where you would add panels based on dashboard_config['panels']
        # The actual implementation would be quite complex and depends on the
        # specific types of panels you want to create
        
        response = requests.post(
            f"{grafana_url}/api/dashboards/db",
            headers=headers,
            json=dashboard
        )
        response.raise_for_status()
    
    def _resolve_env_var(self, value: str) -> str:
        """
        Resolve environment variables in string values.
        
        Args:
            value: String that may contain environment variable references
            
        Returns:
            Resolved string with environment variables replaced
        """
        if not isinstance(value, str):
            return value
        
        # Check if the value contains an environment variable reference
        if '${' in value and '}' in value:
            # Extract variable name and default value
            start = value.find('${') + 2
            end = value.find('}', start)
            if start < end:
                var_spec = value[start:end]
                if ':' in var_spec:
                    var_name, default_value = var_spec.split(':', 1)
                else:
                    var_name, default_value = var_spec, ''
                
                # Replace with environment variable or default
                env_value = os.environ.get(var_name, default_value)
                return value.replace('${' + var_spec + '}', env_value)
        
        return value
    
    def start(self) -> None:
        """Start the telemetry system."""
        self.processing_thread.start()
        logger.info("Security telemetry system started")
    
    def stop(self) -> None:
        """Stop the telemetry system."""
        logger.info("Stopping security telemetry system")
        self.stop_event.set()
        
        # Wait for processing thread to complete
        self.processing_thread.join(timeout=30)
        
        logger.info("Security telemetry system stopped")
    
    def send_event(self, event_type: str, source: str, data: Dict[str, Any]) -> None:
        """
        Send a telemetry event.
        
        Args:
            event_type: Type of event (scan, gate, deployment, etc.)
            source: Source of the event (tool name, pipeline step, etc.)
            data: Event data (findings, status, etc.)
        """
        if not self.config.get('collect', {}).get(event_type, {}).get('enabled', True):
            return
        
        event = TelemetryEvent(event_type, source, data)
        try:
            self.event_queue.put(event, block=False)
            logger.debug(f"Queued event: {event}")
        except queue.Full:
            logger.warning("Event queue full, dropping event")
    
    def process_security_scan_results(self, tool: str, results_file: str, 
                                    scan_type: str, scan_duration: float = 0) -> None:
        """
        Process security scan results and send telemetry.
        
        Args:
            tool: Tool name (bandit, semgrep, etc.)
            results_file: Path to results file
            scan_type: Type of scan (SAST, DAST, etc.)
            scan_duration: Duration of scan in seconds
        """
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            # Extract findings count by severity
            findings_by_severity = self._extract_findings_by_severity(tool, results)
            
            # Send telemetry event
            self.send_event(
                'security_scans',
                tool,
                {
                    'scan_type': scan_type,
                    'duration': scan_duration,
                    'findings_count': sum(findings_by_severity.values()),
                    'findings_by_severity': findings_by_severity,
                    'results_file': results_file
                }
            )
            
            logger.info(f"Processed {scan_type} results from {tool}: {sum(findings_by_severity.values())} findings")
        
        except Exception as e:
            logger.error(f"Failed to process {tool} results: {str(e)}")
    
    def _extract_findings_by_severity(self, tool: str, results: Dict[str, Any]) -> Dict[str, int]:
        """
        Extract findings count by severity from scan results.
        
        Args:
            tool: Tool name
            results: Scan results
            
        Returns:
            Dictionary of findings count by severity
        """
        findings = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Different tools have different output formats
        if tool == 'bandit':
            if 'results' in results:
                for finding in results['results']:
                    severity = finding.get('issue_severity', '').lower()
                    if severity in findings:
                        findings[severity] += 1
        
        elif tool == 'semgrep':
            if 'results' in results:
                for finding in results['results']:
                    severity = finding.get('extra', {}).get('severity', '').lower()
                    if severity in findings:
                        findings[severity] += 1
        
        elif tool == 'zap':
            if 'site' in results and isinstance(results['site'], list):
                for site in results['site']:
                    if 'alerts' in site and isinstance(site['alerts'], list):
                        for alert in site['alerts']:
                            risk = alert.get('riskdesc', '').lower()
                            if 'high' in risk:
                                findings['high'] += 1
                            elif 'medium' in risk:
                                findings['medium'] += 1
                            elif 'low' in risk:
                                findings['low'] += 1
                            elif 'info' in risk:
                                findings['info'] += 1
        
        elif tool == 'trivy':
            if 'Results' in results:
                for result in results['Results']:
                    if 'Vulnerabilities' in result:
                        for vuln in result['Vulnerabilities']:
                            severity = vuln.get('Severity', '').lower()
                            if severity in findings:
                                findings[severity] += 1
        
        elif tool in ['safety', 'pip-audit']:
            if isinstance(results, list):
                for vuln in results:
                    if isinstance(vuln, list) and len(vuln) >= 5:
                        severity = vuln[4].lower() if len(vuln) > 4 else 'unknown'
                        if severity == 'critical':
                            findings['critical'] += 1
                        elif severity == 'high':
                            findings['high'] += 1
                        elif severity == 'medium':
                            findings['medium'] += 1
                        elif severity == 'low':
                            findings['low'] += 1
        
        elif tool == 'trufflehog':
            if isinstance(results, list):
                for finding in results:
                    severity = finding.get('severity', '').lower()
                    if severity in findings:
                        findings[severity] += 1
        
        return findings
    
    def record_security_gate_result(self, gate_type: str, environment: str, passed: bool, 
                                   details: Dict[str, Any] = None) -> None:
        """
        Record a security gate evaluation result.
        
        Args:
            gate_type: Type of security gate
            environment: Target environment
            passed: Whether the gate passed
            details: Additional details
        """
        self.send_event(
            'security_gates',
            'security-pipeline',
            {
                'gate_type': gate_type,
                'environment': environment,
                'result': passed,
                'details': details or {}
            }
        )
        
        logger.info(f"Security gate {gate_type} for {environment}: {'PASSED' if passed else 'FAILED'}")
    
    def record_deployment_event(self, event: str, environment: str, success: bool = None, 
                               details: Dict[str, Any] = None) -> None:
        """
        Record a deployment event.
        
        Args:
            event: Deployment event type
            environment: Target environment
            success: Whether the deployment was successful
            details: Additional details
        """
        data = {
            'event': event,
            'environment': environment,
            'details': details or {}
        }
        
        if success is not None:
            data['success'] = success
        
        self.send_event(
            'deployments',
            'security-pipeline',
            data
        )
        
        logger.info(f"Deployment event: {event} for {environment}")
    
    def record_compliance_check(self, framework: str, compliant: bool, 
                              score: float, details: Dict[str, Any] = None) -> None:
        """
        Record a compliance check result.
        
        Args:
            framework: Compliance framework
            compliant: Whether the system is compliant
            score: Compliance score
            details: Additional details
        """
        self.send_event(
            'compliance',
            'security-pipeline',
            {
                'framework': framework,
                'compliant': compliant,
                'score': score,
                'details': details or {}
            }
        )
        
        logger.info(f"Compliance check for {framework}: {'COMPLIANT' if compliant else 'NON-COMPLIANT'} ({score}%)")


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description='Security Telemetry Integration')
    parser.add_argument('--config', default='config/telemetry-config.yaml', help='Path to configuration file')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Logging level')
    parser.add_argument('--action', required=True, choices=['start', 'stop', 'process_results', 'create_dashboards'], help='Action to perform')
    parser.add_argument('--tool', help='Tool name for process_results action')
    parser.add_argument('--results-file', help='Results file for process_results action')
    parser.add_argument('--scan-type', help='Scan type for process_results action')
    parser.add_argument('--scan-duration', type=float, default=0, help='Scan duration in seconds')
    args = parser.parse_args()
    
    try:
        # Initialize telemetry system
        telemetry = SecurityTelemetry(args.config, args.log_level)
        
        # Perform requested action
        if args.action == 'start':
            telemetry.start()
            
            # Keep running for a while
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Interrupted, stopping telemetry")
                telemetry.stop()
        
        elif args.action == 'stop':
            # This would typically be called from another process
            logger.info("Stopping telemetry system is only valid when run as a service")
        
        elif args.action == 'process_results':
            if not args.tool or not args.results_file or not args.scan_type:
                parser.error("process_results action requires --tool, --results-file, and --scan-type arguments")
            
            telemetry.start()
            telemetry.process_security_scan_results(
                args.tool,
                args.results_file,
                args.scan_type,
                args.scan_duration
            )
            # Give time for events to be processed
            time.sleep(5)
            telemetry.stop()
        
        elif args.action == 'create_dashboards':
            telemetry._create_grafana_dashboards()
    
    except Exception as e:
        logger.error(f"Error in telemetry system: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 