#!/usr/bin/env python3
"""
SIEM Integration Module

This script forwards security events from the CI/CD pipeline to Security Information
and Event Management (SIEM) systems. It normalizes data for SIEM consumption, adds
MITRE ATT&CK mappings, and enables advanced security monitoring and alerting.
"""

import argparse
import json
import logging
import os
import sys
import time
import uuid
import yaml
import re
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Union, Optional, Tuple
import threading
import queue
import ssl

# Third-party imports
try:
    import requests
    import urllib3
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Please install required packages: pip install requests urllib3 cryptography")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("siem-integration")


class SIEMConfigError(Exception):
    """Exception raised for errors in the SIEM configuration."""
    pass


class SIEMConnectionError(Exception):
    """Exception raised for SIEM connection errors."""
    pass


class SIEMDataFormatError(Exception):
    """Exception raised for errors in data formatting for SIEM."""
    pass


class SIEMEvent:
    """Class representing a security event formatted for SIEM systems."""
    
    def __init__(self, source_type: str, event_type: str, source: str, 
                data: Dict[str, Any], source_ip: str = None):
        """
        Initialize a SIEM event.
        
        Args:
            source_type: Type of security source (e.g., SAST, DAST, Container)
            event_type: Type of event (e.g., vulnerability, compliance, gate)
            source: Source of the event (e.g., tool name, pipeline step)
            data: Event data
            source_ip: Source IP address (defaults to local machine IP)
        """
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.source_type = source_type
        self.event_type = event_type
        self.source = source
        self.data = data
        self.source_ip = source_ip or self._get_local_ip()
        
        # Add MITRE ATT&CK mappings if applicable
        self.mitre_mappings = self._map_to_mitre_attack()
        
        # Add severity based on event data
        self.severity = self._determine_severity()
        
        # Calculate risk score (0-100)
        self.risk_score = self._calculate_risk_score()
    
    def _get_local_ip(self) -> str:
        """Get local machine IP address."""
        try:
            # Connect to a public DNS server to determine the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            # Fallback to localhost if unable to determine
            return "127.0.0.1"
    
    def _map_to_mitre_attack(self) -> List[Dict[str, str]]:
        """Map security event to MITRE ATT&CK framework techniques."""
        mappings = []
        
        # Dictionary mapping event characteristics to MITRE techniques
        mitre_map = {
            # Credential Access
            "hardcoded credentials": {
                "tactic": "Credential Access",
                "technique_id": "T1552",
                "technique_name": "Unsecured Credentials",
                "sub_technique_id": "T1552.001",
                "sub_technique_name": "Credentials In Files"
            },
            "api key": {
                "tactic": "Credential Access",
                "technique_id": "T1552",
                "technique_name": "Unsecured Credentials",
                "sub_technique_id": "T1552.001",
                "sub_technique_name": "Credentials In Files"
            },
            "password": {
                "tactic": "Credential Access",
                "technique_id": "T1552",
                "technique_name": "Unsecured Credentials",
                "sub_technique_id": "T1552.001",
                "sub_technique_name": "Credentials In Files"
            },
            
            # Defense Evasion
            "sql injection": {
                "tactic": "Defense Evasion",
                "technique_id": "T1562",
                "technique_name": "Impair Defenses",
                "sub_technique_id": "T1562.001",
                "sub_technique_name": "Disable or Modify Tools"
            },
            
            # Initial Access
            "insecure deserialization": {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            },
            "remote code execution": {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application"
            },
            
            # Execution
            "command injection": {
                "tactic": "Execution",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter"
            },
            "os command injection": {
                "tactic": "Execution",
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "sub_technique_id": "T1059.004",
                "sub_technique_name": "Unix Shell"
            },
            
            # Persistence
            "backdoor": {
                "tactic": "Persistence",
                "technique_id": "T1505",
                "technique_name": "Server Software Component",
                "sub_technique_id": "T1505.003",
                "sub_technique_name": "Web Shell"
            },
            
            # Privilege Escalation
            "insecure permissions": {
                "tactic": "Privilege Escalation",
                "technique_id": "T1574",
                "technique_name": "Hijack Execution Flow"
            }
        }
        
        # Search for keywords in event data to map to MITRE ATT&CK
        event_str = json.dumps(self.data).lower()
        
        for keyword, mapping in mitre_map.items():
            if keyword in event_str:
                mappings.append(mapping)
        
        # Add container escape techniques for container security events
        if self.source_type == "Container" and "escape" in event_str:
            mappings.append({
                "tactic": "Privilege Escalation",
                "technique_id": "T1611",
                "technique_name": "Escape to Host"
            })
        
        # Special handling for dependency vulnerabilities
        if self.source_type == "Dependencies" and self.event_type == "vulnerability":
            mappings.append({
                "tactic": "Initial Access",
                "technique_id": "T1195",
                "technique_name": "Supply Chain Compromise",
                "sub_technique_id": "T1195.001",
                "sub_technique_name": "Compromise Software Dependencies and Development Tools"
            })
        
        return mappings
    
    def _determine_severity(self) -> str:
        """Determine event severity based on data."""
        # Default to medium severity
        severity = "medium"
        
        # Check if the data explicitly includes severity
        if "severity" in self.data:
            severity = self.data["severity"].lower()
        
        # For vulnerabilities, use the highest severity if multiple exist
        elif "findings_by_severity" in self.data:
            findings = self.data["findings_by_severity"]
            if findings.get("critical", 0) > 0:
                severity = "critical"
            elif findings.get("high", 0) > 0:
                severity = "high"
            elif findings.get("medium", 0) > 0:
                severity = "medium"
            elif findings.get("low", 0) > 0:
                severity = "low"
        
        # For gate events, failed gates are high severity
        elif self.event_type == "gate" and "result" in self.data:
            if not self.data["result"]:
                severity = "high"
        
        # For deployment events, failures are high severity
        elif self.event_type == "deployment" and "success" in self.data:
            if not self.data["success"]:
                severity = "high"
            else:
                severity = "info"
        
        return severity
    
    def _calculate_risk_score(self) -> int:
        """Calculate a risk score from 0-100 based on event data."""
        # Base score depends on severity
        severity_scores = {
            "critical": 90,
            "high": 70,
            "medium": 40,
            "low": 20,
            "info": 5
        }
        
        base_score = severity_scores.get(self.severity, 30)
        
        # Adjust score based on other factors
        modifiers = 0
        
        # Increase score for events with MITRE mappings
        if self.mitre_mappings:
            modifiers += min(len(self.mitre_mappings) * 5, 20)
        
        # Adjust for deployment environment if present
        if "environment" in self.data:
            env = self.data["environment"].lower()
            if env == "production":
                modifiers += 10
            elif env == "staging":
                modifiers += 5
        
        # Calculate final score with ceiling of 100
        final_score = min(base_score + modifiers, 100)
        
        return final_score
    
    def to_common_event_format(self) -> Dict[str, Any]:
        """Convert to Common Event Format (CEF) dictionary."""
        cef = {
            "event_id": self.id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "event_type": self.event_type,
            "source": self.source,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "source_ip": self.source_ip,
            "data": self.data
        }
        
        if self.mitre_mappings:
            cef["mitre_attack"] = self.mitre_mappings
        
        return cef
    
    def to_syslog_cef(self) -> str:
        """Format event as CEF syslog message."""
        # CEF Header fields
        device_vendor = "SecurityPipeline"
        device_product = f"CI-CD-{self.source_type}"
        device_version = "1.0"
        signature_id = f"{self.source_type}:{self.event_type}"
        name = f"{self.source_type} {self.event_type} from {self.source}"
        severity = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 0}.get(self.severity, 5)
        
        # CEF Header
        header = f"CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}"
        
        # CEF Extensions
        extensions = []
        extensions.append(f"rt={self.timestamp}")
        extensions.append(f"src={self.source_ip}")
        extensions.append(f"suid={self.source}")
        extensions.append(f"msg={json.dumps(self.data)}")
        extensions.append(f"cs1Label=eventType")
        extensions.append(f"cs1={self.event_type}")
        extensions.append(f"cs2Label=riskScore")
        extensions.append(f"cs2={self.risk_score}")
        
        # Add MITRE ATT&CK information if available
        if self.mitre_mappings:
            mitre_str = ", ".join([f"{m.get('technique_id', '')}: {m.get('technique_name', '')}" for m in self.mitre_mappings])
            extensions.append(f"cs3Label=mitreAttack")
            extensions.append(f"cs3={mitre_str}")
        
        return f"{header}|{'|'.join(extensions)}"
    
    def to_leef(self) -> str:
        """Format event as LEEF (Log Event Extended Format) for QRadar."""
        # LEEF Header fields
        leef_version = "1.0"
        vendor = "SecurityPipeline"
        product = f"CI-CD-{self.source_type}"
        product_version = "1.0"
        event_id = f"{self.source_type}:{self.event_type}"
        
        # LEEF Header
        header = f"LEEF:{leef_version}|{vendor}|{product}|{product_version}|{event_id}"
        
        # LEEF Attributes
        attributes = []
        attributes.append(f"cat={self.source_type}")
        attributes.append(f"devTime={self.timestamp}")
        attributes.append(f"src={self.source_ip}")
        attributes.append(f"usrName={self.source}")
        attributes.append(f"msg={json.dumps(self.data)}")
        attributes.append(f"severity={self.severity}")
        attributes.append(f"riskScore={self.risk_score}")
        
        # Add MITRE ATT&CK information if available
        if self.mitre_mappings:
            mitre_str = ", ".join([f"{m.get('technique_id', '')}: {m.get('technique_name', '')}" for m in self.mitre_mappings])
            attributes.append(f"mitreAttack={mitre_str}")
        
        return f"{header}\t{''.join(attributes)}"
    
    def to_splunk(self) -> Dict[str, Any]:
        """Format event for Splunk HEC (HTTP Event Collector)."""
        splunk_event = {
            "time": datetime.fromisoformat(self.timestamp.replace('Z', '+00:00')).timestamp(),
            "host": self.source_ip,
            "source": f"ci-cd-pipeline:{self.source_type.lower()}",
            "sourcetype": f"security:{self.source_type.lower()}:{self.event_type.lower()}",
            "index": "security",
            "event": {
                "id": self.id,
                "source_type": self.source_type,
                "event_type": self.event_type,
                "source": self.source,
                "severity": self.severity,
                "risk_score": self.risk_score,
                "data": self.data
            }
        }
        
        if self.mitre_mappings:
            splunk_event["event"]["mitre_attack"] = self.mitre_mappings
        
        return splunk_event
    
    def to_elastic(self) -> Dict[str, Any]:
        """Format event for Elasticsearch."""
        elastic_event = {
            "@timestamp": self.timestamp,
            "host": {
                "ip": self.source_ip
            },
            "event": {
                "id": self.id,
                "category": ["security", self.source_type.lower()],
                "type": self.event_type,
                "severity": self.severity,
                "risk_score": self.risk_score
            },
            "source": {
                "name": self.source
            },
            "security": {
                "data": self.data
            }
        }
        
        if self.mitre_mappings:
            elastic_event["threat"] = {
                "framework": "MITRE ATT&CK",
                "technique": [
                    {
                        "id": m.get("technique_id"),
                        "name": m.get("technique_name"),
                        "reference": f"https://attack.mitre.org/techniques/{m.get('technique_id')}/",
                        "subtechnique": {
                            "id": m.get("sub_technique_id"),
                            "name": m.get("sub_technique_name")
                        } if m.get("sub_technique_id") else None
                    }
                    for m in self.mitre_mappings
                ]
            }
        
        return elastic_event
    
    def __str__(self) -> str:
        """String representation of the event."""
        return f"SIEMEvent[{self.source_type}:{self.event_type}] from {self.source} - {self.severity} severity (risk: {self.risk_score})"


class SIEMIntegration:
    """Main class for SIEM integration."""
    
    def __init__(self, config_file: str, log_level: str = "INFO"):
        """
        Initialize the SIEM integration.
        
        Args:
            config_file: Path to SIEM configuration file
            log_level: Logging level
        """
        # Set up logging
        log_level_enum = getattr(logging, log_level.upper(), logging.INFO)
        logger.setLevel(log_level_enum)
        
        # Load configuration
        self.config = self._load_config(config_file)
        
        # Check if SIEM integration is enabled
        if not self.config.get("settings", {}).get("enabled", True):
            logger.info("SIEM integration is disabled in configuration")
            sys.exit(0)
        
        # Initialize SIEM providers
        self.providers = {}
        self._init_providers()
        
        # Set up event queue
        self.event_queue = queue.Queue(
            maxsize=self.config.get("settings", {}).get("buffer_size", 1000)
        )
        self.stop_event = threading.Event()
        
        # Create processing thread
        self.processing_thread = threading.Thread(
            target=self._process_events, daemon=True
        )
        
        # Instance variables for batch processing
        self.last_flush_time = time.time()
        self.events_batch = {provider: [] for provider in self.providers}
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Dictionary containing configuration
        """
        try:
            with open(config_file, "r") as f:
                config = yaml.safe_load(f)
                logger.debug(f"Loaded configuration from {config_file}")
                return config
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_file}: {str(e)}")
            raise SIEMConfigError(f"Failed to load configuration: {str(e)}")
    
    def _init_providers(self) -> None:
        """Initialize SIEM providers based on configuration."""
        provider_configs = self.config.get("providers", {})
        
        # Initialize Splunk if enabled
        if provider_configs.get("splunk", {}).get("enabled", False):
            try:
                self._init_splunk(provider_configs["splunk"])
                logger.info("Splunk provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Splunk provider: {str(e)}")
        
        # Initialize Elasticsearch if enabled
        if provider_configs.get("elasticsearch", {}).get("enabled", False):
            try:
                self._init_elasticsearch(provider_configs["elasticsearch"])
                logger.info("Elasticsearch provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Elasticsearch provider: {str(e)}")
        
        # Initialize Wazuh if enabled
        if provider_configs.get("wazuh", {}).get("enabled", False):
            try:
                self._init_wazuh(provider_configs["wazuh"])
                logger.info("Wazuh provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Wazuh provider: {str(e)}")
        
        # Initialize QRadar if enabled
        if provider_configs.get("qradar", {}).get("enabled", False):
            try:
                self._init_qradar(provider_configs["qradar"])
                logger.info("QRadar provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize QRadar provider: {str(e)}")
        
        # Initialize Syslog if enabled
        if provider_configs.get("syslog", {}).get("enabled", False):
            try:
                self._init_syslog(provider_configs["syslog"])
                logger.info("Syslog provider initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Syslog provider: {str(e)}")
    
    def _init_splunk(self, config: Dict[str, Any]) -> None:
        """
        Initialize Splunk provider.
        
        Args:
            config: Splunk configuration
        """
        # Get configuration values with environment variable fallbacks
        hec_url = self._resolve_env_var(config.get("hec_url", ""))
        hec_token = self._resolve_env_var(config.get("hec_token", ""))
        verify_ssl = config.get("verify_ssl", True)
        source_type = config.get("source_type", "security:cicd")
        index = config.get("index", "security")
        
        if not hec_url:
            raise SIEMConfigError("Splunk HEC URL not configured")
        
        if not hec_token:
            raise SIEMConfigError("Splunk HEC token not configured")
        
        # Test connection
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        }
        
        try:
            # Use health endpoint to validate connection
            health_url = f"{hec_url}/services/collector/health"
            response = requests.get(health_url, headers=headers, verify=verify_ssl)
            
            if response.status_code != 200:
                raise SIEMConnectionError(
                    f"Failed to connect to Splunk HEC: {response.status_code} {response.text}"
                )
        except requests.exceptions.RequestException as e:
            raise SIEMConnectionError(f"Failed to connect to Splunk HEC: {str(e)}")
        
        self.providers["splunk"] = {
            "hec_url": hec_url,
            "hec_token": hec_token,
            "verify_ssl": verify_ssl,
            "source_type": source_type,
            "index": index,
            "batch_size": config.get("batch_size", 10)
        }
    
    def _init_elasticsearch(self, config: Dict[str, Any]) -> None:
        """
        Initialize Elasticsearch provider.
        
        Args:
            config: Elasticsearch configuration
        """
        # Get configuration values with environment variable fallbacks
        es_url = self._resolve_env_var(config.get("url", ""))
        es_username = self._resolve_env_var(config.get("username", ""))
        es_password = self._resolve_env_var(config.get("password", ""))
        es_api_key = self._resolve_env_var(config.get("api_key", ""))
        verify_ssl = config.get("verify_ssl", True)
        index_pattern = config.get("index_pattern", "security-cicd-events")
        
        if not es_url:
            raise SIEMConfigError("Elasticsearch URL not configured")
        
        # Test connection
        headers = {}
        
        if es_api_key:
            headers["Authorization"] = f"ApiKey {es_api_key}"
        elif es_username and es_password:
            import base64
            auth_str = base64.b64encode(f"{es_username}:{es_password}".encode()).decode()
            headers["Authorization"] = f"Basic {auth_str}"
        
        try:
            # Use health endpoint to validate connection
            health_url = f"{es_url}/_cluster/health"
            response = requests.get(health_url, headers=headers, verify=verify_ssl)
            
            if response.status_code != 200:
                raise SIEMConnectionError(
                    f"Failed to connect to Elasticsearch: {response.status_code} {response.text}"
                )
        except requests.exceptions.RequestException as e:
            raise SIEMConnectionError(f"Failed to connect to Elasticsearch: {str(e)}")
        
        self.providers["elasticsearch"] = {
            "url": es_url,
            "username": es_username,
            "password": es_password,
            "api_key": es_api_key,
            "verify_ssl": verify_ssl,
            "index_pattern": index_pattern,
            "batch_size": config.get("batch_size", 10)
        }
    
    def _init_wazuh(self, config: Dict[str, Any]) -> None:
        """
        Initialize Wazuh provider.
        
        Args:
            config: Wazuh configuration
        """
        # Wazuh integration can work in multiple ways:
        # 1. Direct to Wazuh API
        # 2. Via Filebeat to Wazuh indexer
        # 3. Via syslog to Wazuh manager
        
        # We'll implement the syslog method as it's most commonly used
        syslog_host = self._resolve_env_var(config.get("syslog_host", ""))
        syslog_port = int(self._resolve_env_var(config.get("syslog_port", "514")))
        syslog_protocol = config.get("syslog_protocol", "udp").lower()
        
        if not syslog_host:
            raise SIEMConfigError("Wazuh syslog host not configured")
        
        # Test connection
        try:
            if syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((syslog_host, syslog_port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # For UDP we can't really test the connection, but we can create the socket
            
            sock.close()
        except socket.error as e:
            raise SIEMConnectionError(f"Failed to connect to Wazuh syslog: {str(e)}")
        
        self.providers["wazuh"] = {
            "syslog_host": syslog_host,
            "syslog_port": syslog_port,
            "syslog_protocol": syslog_protocol,
            "syslog_format": config.get("syslog_format", "cef"),
            "batch_size": 1  # Syslog should be sent one by one
        }
    
    def _init_qradar(self, config: Dict[str, Any]) -> None:
        """
        Initialize QRadar provider.
        
        Args:
            config: QRadar configuration
        """
        # QRadar integration can work in multiple ways:
        # 1. Direct to QRadar API
        # 2. Via syslog to QRadar
        
        # We'll implement the syslog method as it's most commonly used
        syslog_host = self._resolve_env_var(config.get("syslog_host", ""))
        syslog_port = int(self._resolve_env_var(config.get("syslog_port", "514")))
        syslog_protocol = config.get("syslog_protocol", "tcp").lower()
        
        if not syslog_host:
            raise SIEMConfigError("QRadar syslog host not configured")
        
        # Test connection
        try:
            if syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((syslog_host, syslog_port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # For UDP we can't really test the connection, but we can create the socket
            
            sock.close()
        except socket.error as e:
            raise SIEMConnectionError(f"Failed to connect to QRadar syslog: {str(e)}")
        
        self.providers["qradar"] = {
            "syslog_host": syslog_host,
            "syslog_port": syslog_port,
            "syslog_protocol": syslog_protocol,
            "syslog_format": config.get("syslog_format", "leef"),
            "batch_size": 1  # Syslog should be sent one by one
        }
    
    def _init_syslog(self, config: Dict[str, Any]) -> None:
        """
        Initialize generic syslog provider.
        
        Args:
            config: Syslog configuration
        """
        syslog_host = self._resolve_env_var(config.get("host", ""))
        syslog_port = int(self._resolve_env_var(config.get("port", "514")))
        syslog_protocol = config.get("protocol", "udp").lower()
        syslog_facility = config.get("facility", "local7")
        
        if not syslog_host:
            raise SIEMConfigError("Syslog host not configured")
        
        # Map facility name to value
        facility_map = {
            "kern": 0,
            "user": 1,
            "mail": 2,
            "daemon": 3,
            "auth": 4,
            "syslog": 5,
            "lpr": 6,
            "news": 7,
            "uucp": 8,
            "cron": 9,
            "authpriv": 10,
            "ftp": 11,
            "local0": 16,
            "local1": 17,
            "local2": 18,
            "local3": 19,
            "local4": 20,
            "local5": 21,
            "local6": 22,
            "local7": 23
        }
        
        facility_value = facility_map.get(syslog_facility.lower(), 23)
        
        # Test connection
        try:
            if syslog_protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((syslog_host, syslog_port))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # For UDP we can't really test the connection, but we can create the socket
            
            sock.close()
        except socket.error as e:
            raise SIEMConnectionError(f"Failed to connect to syslog server: {str(e)}")
        
        self.providers["syslog"] = {
            "host": syslog_host,
            "port": syslog_port,
            "protocol": syslog_protocol,
            "facility": facility_value,
            "format": config.get("format", "cef"),
            "batch_size": 1  # Syslog should be sent one by one
        }
    
    def _process_events(self) -> None:
        """Process events from the queue and ship to SIEM providers."""
        while not self.stop_event.is_set() or not self.event_queue.empty():
            try:
                # Try to get an event with a timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    
                    # Add to batch for each provider
                    for provider in self.providers:
                        self.events_batch[provider].append(event)
                        
                        # Check if we need to flush this provider's batch
                        batch_size = self.providers[provider].get("batch_size", 10)
                        if len(self.events_batch[provider]) >= batch_size:
                            self._ship_events_to_provider(provider, self.events_batch[provider])
                            self.events_batch[provider] = []
                    
                    self.event_queue.task_done()
                except queue.Empty:
                    pass
                
                # Check if we should flush based on time
                current_time = time.time()
                batch_interval = self.config.get("settings", {}).get("batch_interval", 60)
                
                if current_time - self.last_flush_time >= batch_interval:
                    self._flush_all_batches()
                    self.last_flush_time = current_time
            
            except Exception as e:
                logger.error(f"Error processing events: {str(e)}")
        
        # Final flush of any remaining events
        self._flush_all_batches()
    
    def _flush_all_batches(self) -> None:
        """Flush all event batches to their respective providers."""
        for provider, events in self.events_batch.items():
            if events:
                try:
                    self._ship_events_to_provider(provider, events)
                    self.events_batch[provider] = []
                except Exception as e:
                    logger.error(f"Error shipping events to {provider}: {str(e)}")
    
    def _ship_events_to_provider(self, provider: str, events: List[SIEMEvent]) -> None:
        """
        Ship events to a specific SIEM provider.
        
        Args:
            provider: Provider name
            events: List of events to ship
        """
        if not events:
            return
        
        if provider == "splunk":
            self._ship_to_splunk(events)
        elif provider == "elasticsearch":
            self._ship_to_elasticsearch(events)
        elif provider == "wazuh":
            self._ship_to_syslog(events, "wazuh")
        elif provider == "qradar":
            self._ship_to_syslog(events, "qradar")
        elif provider == "syslog":
            self._ship_to_syslog(events, "syslog")
    
    def _ship_to_splunk(self, events: List[SIEMEvent]) -> None:
        """
        Ship events to Splunk.
        
        Args:
            events: List of events to ship
        """
        provider_config = self.providers["splunk"]
        hec_url = provider_config["hec_url"]
        hec_token = provider_config["hec_token"]
        verify_ssl = provider_config["verify_ssl"]
        
        # Format events for Splunk HEC
        splunk_events = [event.to_splunk() for event in events]
        
        # Prepare request
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        }
        
        # Send events in batches to Splunk
        for i in range(0, len(splunk_events), 10):
            batch = splunk_events[i:i+10]
            try:
                response = requests.post(
                    f"{hec_url}/services/collector/event",
                    headers=headers,
                    json={"events": batch},
                    verify=verify_ssl
                )
                
                if response.status_code != 200:
                    logger.error(
                        f"Failed to send events to Splunk: {response.status_code} {response.text}"
                    )
                else:
                    logger.debug(f"Sent {len(batch)} events to Splunk successfully")
            except requests.exceptions.RequestException as e:
                logger.error(f"Error sending events to Splunk: {str(e)}")
    
    def _ship_to_elasticsearch(self, events: List[SIEMEvent]) -> None:
        """
        Ship events to Elasticsearch.
        
        Args:
            events: List of events to ship
        """
        provider_config = self.providers["elasticsearch"]
        es_url = provider_config["url"]
        es_username = provider_config["username"]
        es_password = provider_config["password"]
        es_api_key = provider_config["api_key"]
        verify_ssl = provider_config["verify_ssl"]
        index_pattern = provider_config["index_pattern"]
        
        # Prepare headers
        headers = {
            "Content-Type": "application/json"
        }
        
        if es_api_key:
            headers["Authorization"] = f"ApiKey {es_api_key}"
        elif es_username and es_password:
            import base64
            auth_str = base64.b64encode(f"{es_username}:{es_password}".encode()).decode()
            headers["Authorization"] = f"Basic {auth_str}"
        
        # Format for Elasticsearch bulk API
        bulk_data = []
        for event in events:
            # Index name with date
            index_name = f"{index_pattern}-{datetime.now().strftime('%Y.%m.%d')}"
            
            # Add index action
            bulk_data.append(json.dumps({"index": {"_index": index_name, "_id": event.id}}))
            
            # Add event data
            bulk_data.append(json.dumps(event.to_elastic()))
        
        # Add newline at the end
        bulk_data_str = "\n".join(bulk_data) + "\n"
        
        try:
            response = requests.post(
                f"{es_url}/_bulk",
                headers=headers,
                data=bulk_data_str,
                verify=verify_ssl
            )
            
            if response.status_code not in (200, 201):
                logger.error(
                    f"Failed to send events to Elasticsearch: {response.status_code} {response.text}"
                )
            else:
                bulk_response = response.json()
                if bulk_response.get("errors", False):
                    logger.warning("Some events failed to index in Elasticsearch")
                    for item in bulk_response.get("items", []):
                        if "error" in item.get("index", {}):
                            logger.warning(
                                f"Elasticsearch indexing error: {item['index']['error']}"
                            )
                else:
                    logger.debug(f"Indexed {len(events)} events to Elasticsearch successfully")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending events to Elasticsearch: {str(e)}")
    
    def _ship_to_syslog(self, events: List[SIEMEvent], provider_type: str) -> None:
        """
        Ship events to syslog-based providers (Wazuh, QRadar, generic syslog).
        
        Args:
            events: List of events to ship
            provider_type: Type of syslog provider (wazuh, qradar, syslog)
        """
        provider_config = self.providers[provider_type]
        host = provider_config.get("host", provider_config.get("syslog_host", ""))
        port = provider_config.get("port", provider_config.get("syslog_port", 514))
        protocol = provider_config.get("protocol", provider_config.get("syslog_protocol", "udp")).lower()
        format_type = provider_config.get("format", provider_config.get("syslog_format", "cef")).lower()
        
        # Create socket based on protocol
        try:
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
            else:  # UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send each event
            for event in events:
                if format_type == "leef":
                    message = event.to_leef()
                else:  # Default to CEF
                    message = event.to_syslog_cef()
                
                # Add syslog header if it's a generic syslog provider
                if provider_type == "syslog":
                    # Calculate priority value (facility * 8 + severity)
                    facility = provider_config.get("facility", 23)  # Default to local7
                    severity_map = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
                    severity = severity_map.get(event.severity, 5)
                    pri = (facility * 8) + severity
                    
                    # Add timestamp and hostname
                    timestamp = datetime.now().strftime("%b %d %H:%M:%S")
                    hostname = socket.gethostname()
                    
                    # Format according to RFC 5424
                    message = f"<{pri}>{timestamp} {hostname} {message}"
                
                # Convert to bytes and send
                try:
                    message_bytes = message.encode('utf-8')
                    if protocol == "udp":
                        sock.sendto(message_bytes, (host, port))
                    else:  # TCP
                        sock.sendall(message_bytes + b'\n')
                    
                    logger.debug(f"Sent event to {provider_type} syslog: {event.id}")
                except Exception as e:
                    logger.error(f"Error sending event to {provider_type} syslog: {str(e)}")
            
            # Close socket if TCP
            if protocol == "tcp":
                sock.close()
                
        except socket.error as e:
            logger.error(f"Socket error sending to {provider_type} syslog: {str(e)}")
    
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
        """Start the SIEM integration system."""
        self.processing_thread.start()
        logger.info("SIEM integration system started")
    
    def stop(self) -> None:
        """Stop the SIEM integration system."""
        logger.info("Stopping SIEM integration system")
        self.stop_event.set()
        
        # Wait for processing thread to complete
        self.processing_thread.join(timeout=30)
        
        logger.info("SIEM integration system stopped")
    
    def send_event(self, source_type: str, event_type: str, source: str, 
                  data: Dict[str, Any], source_ip: str = None) -> None:
        """
        Send a security event to SIEM systems.
        
        Args:
            source_type: Type of security source (e.g., SAST, DAST, Container)
            event_type: Type of event (e.g., vulnerability, compliance, gate)
            source: Source of the event (e.g., tool name, pipeline step)
            data: Event data
            source_ip: Source IP address (defaults to local machine IP)
        """
        # Skip if event type is not enabled in configuration
        event_types_config = self.config.get("event_types", {})
        if source_type.lower() in event_types_config:
            if not event_types_config[source_type.lower()].get("enabled", True):
                logger.debug(f"Event type {source_type} is disabled, skipping")
                return
        
        # Create SIEM event
        event = SIEMEvent(source_type, event_type, source, data, source_ip)
        
        try:
            # Add to queue
            self.event_queue.put(event, block=False)
            logger.debug(f"Queued SIEM event: {event}")
        except queue.Full:
            logger.warning("Event queue full, dropping SIEM event")
    
    def process_security_scan_results(self, scan_type: str, tool: str, results_file: str) -> None:
        """
        Process security scan results and send to SIEM.
        
        Args:
            scan_type: Type of security scan (SAST, DAST, Container, etc.)
            tool: Tool name (bandit, semgrep, zap, etc.)
            results_file: Path to results file
        """
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            
            # Extract findings
            findings_by_severity = self._extract_findings_by_severity(tool, results)
            total_findings = sum(findings_by_severity.values())
            
            # Add metadata about the scan
            data = {
                "scan_type": scan_type,
                "tool": tool,
                "results_file": results_file,
                "findings_count": total_findings,
                "findings_by_severity": findings_by_severity,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Add additional context based on tool and findings
            if total_findings > 0:
                # Collect some sample findings for context
                data["sample_findings"] = self._extract_sample_findings(tool, results)
                
                # Determine event type based on severity
                if findings_by_severity.get("critical", 0) > 0:
                    event_type = "critical_vulnerability"
                elif findings_by_severity.get("high", 0) > 0:
                    event_type = "high_vulnerability"
                else:
                    event_type = "vulnerability"
            else:
                event_type = "scan_success"
            
            # Send to SIEM
            self.send_event(scan_type, event_type, tool, data)
            
            logger.info(f"Processed {scan_type} results from {tool}: {total_findings} findings")
        
        except Exception as e:
            logger.error(f"Failed to process {tool} results for SIEM: {str(e)}")
            # Send error event
            self.send_event(
                scan_type, 
                "scan_error", 
                tool, 
                {"error": str(e), "results_file": results_file}
            )
    
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
    
    def _extract_sample_findings(self, tool: str, results: Dict[str, Any], max_samples: int = 5) -> List[Dict[str, Any]]:
        """
        Extract sample findings for context.
        
        Args:
            tool: Tool name
            results: Scan results
            max_samples: Maximum number of samples to extract
            
        Returns:
            List of sample findings
        """
        samples = []
        
        if tool == 'bandit':
            if 'results' in results:
                for i, finding in enumerate(results['results']):
                    if i >= max_samples:
                        break
                    
                    sample = {
                        "severity": finding.get('issue_severity', ''),
                        "issue_text": finding.get('issue_text', ''),
                        "filename": finding.get('filename', ''),
                        "line": finding.get('line_number', 0),
                        "code": finding.get('code', '')
                    }
                    samples.append(sample)
        
        elif tool == 'semgrep':
            if 'results' in results:
                for i, finding in enumerate(results['results']):
                    if i >= max_samples:
                        break
                    
                    sample = {
                        "severity": finding.get('extra', {}).get('severity', ''),
                        "message": finding.get('extra', {}).get('message', ''),
                        "path": finding.get('path', ''),
                        "line": finding.get('start', {}).get('line', 0),
                        "rule_id": finding.get('check_id', '')
                    }
                    samples.append(sample)
        
        elif tool == 'trivy':
            count = 0
            if 'Results' in results:
                for result in results['Results']:
                    if 'Vulnerabilities' in result:
                        for vuln in result['Vulnerabilities']:
                            if count >= max_samples:
                                break
                            
                            sample = {
                                "severity": vuln.get('Severity', ''),
                                "vulnerability_id": vuln.get('VulnerabilityID', ''),
                                "package_name": vuln.get('PkgName', ''),
                                "installed_version": vuln.get('InstalledVersion', ''),
                                "fixed_version": vuln.get('FixedVersion', ''),
                                "description": vuln.get('Description', '')
                            }
                            samples.append(sample)
                            count += 1
        
        return samples
    
    def process_security_gate_result(self, gate_type: str, environment: str, 
                                    passed: bool, details: Dict[str, Any] = None) -> None:
        """
        Process security gate evaluation results and send to SIEM.
        
        Args:
            gate_type: Type of security gate
            environment: Target environment
            passed: Whether the gate passed
            details: Additional details
        """
        data = {
            "gate_type": gate_type,
            "environment": environment,
            "result": passed,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        # Determine event type based on result
        event_type = "gate_success" if passed else "gate_failure"
        
        # Send to SIEM
        self.send_event("SecurityGate", event_type, gate_type, data)
        
        logger.info(f"Processed security gate {gate_type} for {environment}: {'PASSED' if passed else 'FAILED'}")
    
    def process_deployment_event(self, event_type: str, environment: str, 
                               success: bool = None, details: Dict[str, Any] = None) -> None:
        """
        Process deployment events and send to SIEM.
        
        Args:
            event_type: Deployment event type
            environment: Target environment
            success: Whether the deployment was successful
            details: Additional details
        """
        data = {
            "event": event_type,
            "environment": environment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        if success is not None:
            data["success"] = success
        
        # Send to SIEM
        self.send_event("Deployment", event_type, environment, data)
        
        logger.info(f"Processed deployment event: {event_type} for {environment}")
    
    def process_compliance_check(self, framework: str, compliant: bool, 
                               score: float, details: Dict[str, Any] = None) -> None:
        """
        Process compliance check results and send to SIEM.
        
        Args:
            framework: Compliance framework
            compliant: Whether the system is compliant
            score: Compliance score
            details: Additional details
        """
        data = {
            "framework": framework,
            "compliant": compliant,
            "score": score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {}
        }
        
        # Determine event type based on compliance status
        event_type = "compliance_success" if compliant else "compliance_failure"
        
        # Send to SIEM
        self.send_event("Compliance", event_type, framework, data)
        
        logger.info(f"Processed compliance check for {framework}: {'COMPLIANT' if compliant else 'NON-COMPLIANT'} ({score}%)")


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(description='SIEM Integration Module')
    parser.add_argument('--config', default='config/siem-config.yaml', help='Path to SIEM configuration file')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Logging level')
    parser.add_argument('--action', required=True, 
                      choices=['start', 'stop', 'process_scan', 'process_gate', 'process_deployment', 'process_compliance'],
                      help='Action to perform')
    
    # Arguments for process_scan action
    parser.add_argument('--scan-type', help='Type of security scan (SAST, DAST, Container, etc.)')
    parser.add_argument('--tool', help='Tool name (bandit, semgrep, zap, etc.)')
    parser.add_argument('--results-file', help='Path to results file')
    
    # Arguments for process_gate action
    parser.add_argument('--gate-type', help='Type of security gate')
    parser.add_argument('--environment', help='Target environment')
    parser.add_argument('--passed', action='store_true', help='Whether the gate passed')
    parser.add_argument('--details-file', help='Path to details JSON file')
    
    # Arguments for process_deployment action
    parser.add_argument('--event-type', help='Deployment event type')
    parser.add_argument('--success', action='store_true', help='Whether the deployment was successful')
    
    # Arguments for process_compliance action
    parser.add_argument('--framework', help='Compliance framework')
    parser.add_argument('--compliant', action='store_true', help='Whether the system is compliant')
    parser.add_argument('--score', type=float, help='Compliance score')
    
    args = parser.parse_args()
    
    try:
        # Initialize SIEM integration
        siem = SIEMIntegration(args.config, args.log_level)
        
        # Perform requested action
        if args.action == 'start':
            siem.start()
            
            # Keep running for a while
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Interrupted, stopping SIEM integration")
                siem.stop()
        
        elif args.action == 'stop':
            # This would typically be called from another process
            logger.info("Stopping SIEM integration is only valid when run as a service")
        
        elif args.action == 'process_scan':
            if not args.scan_type or not args.tool or not args.results_file:
                parser.error("process_scan action requires --scan-type, --tool, and --results-file arguments")
            
            siem.start()
            siem.process_security_scan_results(args.scan_type, args.tool, args.results_file)
            # Give time for events to be processed
            time.sleep(5)
            siem.stop()
        
        elif args.action == 'process_gate':
            if not args.gate_type or not args.environment:
                parser.error("process_gate action requires --gate-type and --environment arguments")
            
            details = None
            if args.details_file:
                with open(args.details_file, 'r') as f:
                    details = json.load(f)
            
            siem.start()
            siem.process_security_gate_result(args.gate_type, args.environment, args.passed, details)
            time.sleep(5)
            siem.stop()
        
        elif args.action == 'process_deployment':
            if not args.event_type or not args.environment:
                parser.error("process_deployment action requires --event-type and --environment arguments")
            
            details = None
            if args.details_file:
                with open(args.details_file, 'r') as f:
                    details = json.load(f)
            
            siem.start()
            siem.process_deployment_event(args.event_type, args.environment, args.success, details)
            time.sleep(5)
            siem.stop()
        
        elif args.action == 'process_compliance':
            if not args.framework or args.score is None:
                parser.error("process_compliance action requires --framework and --score arguments")
            
            details = None
            if args.details_file:
                with open(args.details_file, 'r') as f:
                    details = json.load(f)
            
            siem.start()
            siem.process_compliance_check(args.framework, args.compliant, args.score, details)
            time.sleep(5)
            siem.stop()
    
    except Exception as e:
        logger.error(f"Error in SIEM integration: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()