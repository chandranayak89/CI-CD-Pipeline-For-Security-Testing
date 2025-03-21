#!/usr/bin/env python3
"""
Security Monitoring Script for Canary Deployments

This script performs real-time security monitoring for canary deployments, detecting
anomalies and potential security issues. It integrates with various monitoring systems
and security tools to provide comprehensive security observations during canary testing.

Features:
- Traffic pattern analysis for anomaly detection
- Runtime vulnerability scanning
- Security telemetry collection
- Privilege escalation monitoring
- Network egress/ingress analysis
- Security log analysis
- Behavior comparison with baseline

Usage:
    python security_monitoring.py --canary-id CANARY_ID --iteration ITERATION --output OUTPUT_FILE
"""

import argparse
import datetime
import json
import logging
import os
import random  # For demo purposes only
import re
import requests
import sys
import time
from typing import Dict, List, Any, Tuple, Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security_monitoring')

# Try to import specific monitoring libraries
try:
    import prometheus_client
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("Prometheus client not available, metrics collection will be limited")

try:
    from opensearch import OpenSearch
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False
    logger.warning("OpenSearch client not available, log analysis will be limited")

class SecurityAnomaly:
    """Represents a security anomaly detected during monitoring."""
    
    def __init__(
        self,
        anomaly_type: str,
        severity: str,
        description: str,
        evidence: Dict[str, Any],
        timestamp: str = None
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.timestamp = timestamp or datetime.datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the anomaly to a dictionary."""
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp
        }

class SecurityMonitor:
    """Main class for security monitoring operations."""
    
    def __init__(self, canary_id: str, iteration: int):
        self.canary_id = canary_id
        self.iteration = iteration
        self.start_time = datetime.datetime.utcnow()
        self.anomalies = []
        self.metrics = {}
        self.baseline_metrics = self._load_baseline_metrics()
        
        # Load security credentials from environment
        self.credentials = self._load_credentials()
        
        # Initialize monitoring clients
        self.prometheus_client = self._init_prometheus() if PROMETHEUS_AVAILABLE else None
        self.opensearch_client = self._init_opensearch() if OPENSEARCH_AVAILABLE else None
    
    def _load_credentials(self) -> Dict[str, str]:
        """Load security monitoring credentials from environment variables."""
        creds = {}
        for key in os.environ:
            if key.startswith('SECURITY_MONITORING_'):
                creds[key.replace('SECURITY_MONITORING_', '').lower()] = os.environ[key]
        return creds
    
    def _load_baseline_metrics(self) -> Dict[str, Any]:
        """Load baseline metrics for the application from previous runs."""
        baseline_path = os.path.join(
            os.environ.get('BASELINE_DIR', './baselines'),
            f"security_baseline_{os.environ.get('ENVIRONMENT', 'default')}.json"
        )
        
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse baseline metrics from {baseline_path}")
        
        logger.warning(f"No baseline metrics found at {baseline_path}, comparison will be limited")
        return {}
    
    def _init_prometheus(self) -> Any:
        """Initialize Prometheus client for metrics collection."""
        if not PROMETHEUS_AVAILABLE:
            return None
            
        try:
            prometheus_url = os.environ.get('PROMETHEUS_URL', 'http://localhost:9090')
            return prometheus_client.CollectorRegistry()
        except Exception as e:
            logger.error(f"Failed to initialize Prometheus client: {e}")
            return None
    
    def _init_opensearch(self) -> Any:
        """Initialize OpenSearch client for log analysis."""
        if not OPENSEARCH_AVAILABLE:
            return None
            
        try:
            hosts = [{'host': os.environ.get('OPENSEARCH_HOST', 'localhost'), 
                      'port': int(os.environ.get('OPENSEARCH_PORT', 9200))}]
            auth = (self.credentials.get('opensearch_user', ''), 
                    self.credentials.get('opensearch_password', ''))
            
            return OpenSearch(
                hosts=hosts,
                http_auth=auth,
                use_ssl=True,
                verify_certs=True,
                ssl_show_warn=False
            )
        except Exception as e:
            logger.error(f"Failed to initialize OpenSearch client: {e}")
            return None
    
    def run_security_checks(self) -> Dict[str, Any]:
        """Execute all security checks and return results."""
        logger.info(f"Starting security monitoring for canary {self.canary_id}, iteration {self.iteration}")
        
        # Run all monitoring checks
        self.check_traffic_patterns()
        self.check_runtime_vulnerabilities()
        self.check_network_activity()
        self.check_privilege_escalation()
        self.analyze_security_logs()
        self.check_resource_usage()
        self.check_service_connections()
        
        # Collect all metrics and results
        end_time = datetime.datetime.utcnow()
        duration = (end_time - self.start_time).total_seconds()
        
        result = {
            "canary_id": self.canary_id,
            "iteration": self.iteration,
            "timestamp": end_time.isoformat(),
            "duration_seconds": duration,
            "anomaly_detected": len(self.anomalies) > 0,
            "anomalies": [anomaly.to_dict() for anomaly in self.anomalies],
            "metrics": self.metrics
        }
        
        return result
    
    def check_traffic_patterns(self) -> None:
        """Analyze traffic patterns for security anomalies."""
        logger.info("Checking traffic patterns")
        
        try:
            # In a real implementation, you would:
            # 1. Query your API gateway/load balancer for request patterns
            # 2. Analyze for unusual traffic spikes, patterns, or sources
            # 3. Compare with baseline traffic patterns
            
            # Mock implementation for demonstration
            if PROMETHEUS_AVAILABLE and self.prometheus_client:
                # Collect traffic metrics from Prometheus
                query = f'sum(rate(http_requests_total{{service="{self.canary_id}"}}[5m])) by (status_code)'
                # In a real implementation, make API call to Prometheus
            
            # Check for suspicious traffic patterns (mock logic)
            suspicious_patterns = self._detect_suspicious_patterns()
            if suspicious_patterns:
                self.anomalies.append(SecurityAnomaly(
                    anomaly_type="suspicious_traffic",
                    severity="medium",
                    description="Unusual traffic pattern detected in canary deployment",
                    evidence=suspicious_patterns
                ))
            
            # Record traffic metrics
            self.metrics["traffic"] = {
                "requests_per_second": 42.5,  # Mock value
                "error_rate": 0.02,  # Mock value
                "suspicious_ips": []  # Mock value
            }
            
        except Exception as e:
            logger.error(f"Error in traffic pattern analysis: {e}")
    
    def _detect_suspicious_patterns(self) -> Dict[str, Any]:
        """Detect suspicious traffic patterns (mock implementation)."""
        # In a real implementation, this would analyze traffic data
        # For demo, randomly return an anomaly occasionally
        if random.random() < 0.05:  # 5% chance of anomaly for demo
            return {
                "high_error_rate": True,
                "unusual_user_agents": ["suspicious-crawler/1.0"],
                "traffic_spike": {
                    "normal": 10.5,
                    "current": 85.2,
                    "percent_increase": 711.4
                }
            }
        return {}
    
    def check_runtime_vulnerabilities(self) -> None:
        """Check for runtime vulnerabilities in the canary deployment."""
        logger.info("Checking runtime vulnerabilities")
        
        try:
            # In a real implementation, you might:
            # 1. Query runtime security tools (Falco, Sysdig, etc.)
            # 2. Check for suspicious process executions
            # 3. Look for unexpected file system changes
            
            # Record vulnerability metrics (mock data)
            self.metrics["vulnerabilities"] = {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 3
            }
            
            # Check if vulnerability thresholds are exceeded
            if self.metrics["vulnerabilities"]["critical"] > 0:
                self.anomalies.append(SecurityAnomaly(
                    anomaly_type="critical_vulnerability",
                    severity="critical",
                    description="Critical vulnerability detected in runtime",
                    evidence={"vulnerability_count": self.metrics["vulnerabilities"]}
                ))
            
        except Exception as e:
            logger.error(f"Error in runtime vulnerability check: {e}")
    
    def check_network_activity(self) -> None:
        """Monitor network activity for suspicious connections."""
        logger.info("Checking network activity")
        
        try:
            # In a real implementation, you would:
            # 1. Check network flow logs
            # 2. Look for unexpected egress traffic
            # 3. Verify connections against allowlists
            
            # Detect suspicious connections (mock implementation)
            suspicious_connections = self._detect_suspicious_connections()
            if suspicious_connections:
                self.anomalies.append(SecurityAnomaly(
                    anomaly_type="suspicious_network",
                    severity="high",
                    description="Suspicious network activity detected",
                    evidence=suspicious_connections
                ))
            
            # Record network metrics
            self.metrics["network"] = {
                "egress_connections": 12,  # Mock value
                "connection_countries": ["US", "DE", "FR"],  # Mock value
                "unexpected_ports": []  # Mock value
            }
            
        except Exception as e:
            logger.error(f"Error in network activity monitoring: {e}")
    
    def _detect_suspicious_connections(self) -> Dict[str, Any]:
        """Detect suspicious network connections (mock implementation)."""
        # For demo, randomly return an anomaly occasionally
        if random.random() < 0.03:  # 3% chance of anomaly for demo
            return {
                "unexpected_destination": "203.0.113.42:8080",
                "protocol": "TCP",
                "country": "XX",  # Suspicious country code
                "known_bad_reputation": True
            }
        return {}
    
    def check_privilege_escalation(self) -> None:
        """Monitor for privilege escalation attempts."""
        logger.info("Checking for privilege escalation")
        
        try:
            # In a real implementation, you would check for:
            # 1. Unexpected role/permission changes
            # 2. Authentication anomalies
            # 3. Unusual admin activity
            
            # Check for privilege issues (mock implementation)
            privilege_issues = self._detect_privilege_issues()
            if privilege_issues:
                self.anomalies.append(SecurityAnomaly(
                    anomaly_type="privilege_anomaly",
                    severity="critical",
                    description="Potential privilege escalation detected",
                    evidence=privilege_issues
                ))
            
            # Record privilege metrics
            self.metrics["privileges"] = {
                "role_changes": 0,  # Mock value
                "permission_changes": 0,  # Mock value
                "admin_actions": 1  # Mock value
            }
            
        except Exception as e:
            logger.error(f"Error in privilege escalation monitoring: {e}")
    
    def _detect_privilege_issues(self) -> Dict[str, Any]:
        """Detect privilege-related issues (mock implementation)."""
        # For demo, randomly return an anomaly occasionally
        if random.random() < 0.02:  # 2% chance of anomaly for demo
            return {
                "unexpected_role_change": True,
                "new_permissions": ["admin", "system"],
                "affected_service": "api-gateway"
            }
        return {}
    
    def analyze_security_logs(self) -> None:
        """Analyze security logs for suspicious patterns."""
        logger.info("Analyzing security logs")
        
        try:
            # In a real implementation, you would:
            # 1. Query logs from your centralized logging system
            # 2. Apply security-focused log analysis
            # 3. Look for known attack patterns
            
            if OPENSEARCH_AVAILABLE and self.opensearch_client:
                # Query for security events (mock implementation)
                # In a real setup, query OpenSearch/Elasticsearch
                pass
            
            # Detect suspicious log patterns (mock implementation)
            log_anomalies = self._detect_log_anomalies()
            if log_anomalies:
                self.anomalies.append(SecurityAnomaly(
                    anomaly_type="suspicious_logs",
                    severity="medium",
                    description="Suspicious patterns in security logs",
                    evidence=log_anomalies
                ))
            
            # Record log analysis metrics
            self.metrics["logs"] = {
                "error_count": 5,  # Mock value
                "security_events": 1,  # Mock value
                "warning_count": 8  # Mock value
            }
            
        except Exception as e:
            logger.error(f"Error in security log analysis: {e}")
    
    def _detect_log_anomalies(self) -> Dict[str, Any]:
        """Detect anomalies in security logs (mock implementation)."""
        # For demo, randomly return an anomaly occasionally
        if random.random() < 0.04:  # 4% chance of anomaly for demo
            return {
                "attack_pattern_detected": True,
                "log_examples": [
                    "Failed login attempts from multiple IPs",
                    "SQL injection pattern detected in query parameter"
                ],
                "event_count": 12
            }
        return {}
    
    def check_resource_usage(self) -> None:
        """Monitor resource usage for security-related anomalies."""
        logger.info("Checking resource usage")
        
        try:
            # In a real implementation, you would:
            # 1. Check CPU, memory, disk, and network usage
            # 2. Look for unexplained spikes that could indicate compromise
            # 3. Compare with baseline metrics
            
            # Get current resource usage (mock implementation)
            current_usage = {
                "cpu": 35.2,  # percentage
                "memory": 42.8,  # percentage
                "disk_io": 12.5,  # MB/s
                "network_io": 8.7  # MB/s
            }
            
            # Compare with baseline if available
            if "resource_usage" in self.baseline_metrics:
                baseline = self.baseline_metrics["resource_usage"]
                # Check for significant deviations
                if (current_usage["cpu"] > baseline["cpu"] * 3 or 
                    current_usage["memory"] > baseline["memory"] * 2):
                    self.anomalies.append(SecurityAnomaly(
                        anomaly_type="resource_anomaly",
                        severity="medium",
                        description="Unusual resource usage detected",
                        evidence={
                            "current": current_usage,
                            "baseline": baseline,
                            "cpu_increase": f"{current_usage['cpu'] / baseline['cpu']:.1f}x",
                            "memory_increase": f"{current_usage['memory'] / baseline['memory']:.1f}x"
                        }
                    ))
            
            # Record resource metrics
            self.metrics["resources"] = current_usage
            
        except Exception as e:
            logger.error(f"Error in resource usage monitoring: {e}")
    
    def check_service_connections(self) -> None:
        """Monitor service connections for unexpected behavior."""
        logger.info("Checking service connections")
        
        try:
            # In a real implementation, you would:
            # 1. Check service mesh data for connections
            # 2. Verify against expected service connections
            # 3. Look for unexpected services or connection patterns
            
            # Detect unexpected connections (mock implementation)
            unexpected = self._detect_unexpected_services()
            if unexpected:
                self.anomalies.append(SecurityAnomaly(
                    anomaly_type="unexpected_service",
                    severity="high",
                    description="Connection to unexpected service detected",
                    evidence=unexpected
                ))
            
            # Record service metrics
            self.metrics["services"] = {
                "total_connections": 8,  # Mock value
                "unique_services": 5,  # Mock value
                "unexpected_services": len(unexpected) > 0
            }
            
        except Exception as e:
            logger.error(f"Error in service connection monitoring: {e}")
    
    def _detect_unexpected_services(self) -> Dict[str, Any]:
        """Detect connections to unexpected services (mock implementation)."""
        # For demo, randomly return an anomaly occasionally
        if random.random() < 0.03:  # 3% chance of anomaly for demo
            return {
                "service": "unknown-external-api",
                "connections": 12,
                "first_seen": datetime.datetime.utcnow().isoformat(),
                "not_in_allowlist": True
            }
        return {}

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Security monitoring for canary deployments")
    parser.add_argument("--canary-id", required=True, help="Identifier for the canary deployment")
    parser.add_argument("--iteration", type=int, required=True, help="Monitoring iteration number")
    parser.add_argument("--output", required=True, help="Output file for monitoring results")
    return parser.parse_args()

def main() -> int:
    """Main function."""
    args = parse_args()
    
    try:
        # Create security monitor and run checks
        monitor = SecurityMonitor(args.canary_id, args.iteration)
        results = monitor.run_security_checks()
        
        # Write results to output file
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Security monitoring completed. Results written to {args.output}")
        logger.info(f"Anomalies detected: {len(results['anomalies'])}")
        
        # Return non-zero exit code if anomalies were detected
        return 1 if results["anomaly_detected"] else 0
        
    except Exception as e:
        logger.error(f"Error in security monitoring: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 