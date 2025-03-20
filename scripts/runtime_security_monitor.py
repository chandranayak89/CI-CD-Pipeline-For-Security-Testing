#!/usr/bin/env python3
"""
Runtime Security Monitoring Script for the Security Testing Pipeline.
This script monitors Falco logs, processes alerts, and integrates them with the security dashboard.
"""

import argparse
import json
import os
import sys
import time
import logging
import socket
import datetime
from pathlib import Path
import threading
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("runtime_security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("RuntimeSecurityMonitor")

class FalcoAlertHandler(FileSystemEventHandler):
    """Watchdog handler for Falco log files."""
    
    def __init__(self, log_file, alert_processor):
        """Initialize the handler with path to log file and processor."""
        self.log_file = log_file
        self.alert_processor = alert_processor
        self.last_position = 0
        
        # Process existing content
        self._process_existing_content()
    
    def _process_existing_content(self):
        """Process existing content in the log file."""
        if not os.path.exists(self.log_file):
            return
            
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.last_position = len(content)
            
            # Process each line
            for line in content.splitlines():
                if line.strip():
                    self.alert_processor.process_alert(line)
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.src_path == self.log_file:
            self._process_new_content()
    
    def _process_new_content(self):
        """Process new content in the log file since last read."""
        with open(self.log_file, 'r') as f:
            f.seek(self.last_position)
            new_content = f.read()
            self.last_position = f.tell()
            
            # Process each new line
            for line in new_content.splitlines():
                if line.strip():
                    self.alert_processor.process_alert(line)

class RuntimeAlertProcessor:
    """Processes Falco runtime security alerts."""
    
    def __init__(self, dashboard_url=None, slack_webhook=None):
        """Initialize the alert processor."""
        self.dashboard_url = dashboard_url
        self.slack_webhook = slack_webhook
        self.alert_count = 0
        self.alerts_by_severity = {
            "CRITICAL": [],
            "ERROR": [],
            "WARNING": [],
            "NOTICE": [],
            "INFO": [],
            "DEBUG": []
        }
        
        # Create alerts directory
        self.alerts_dir = Path("runtime_alerts")
        self.alerts_dir.mkdir(exist_ok=True)
    
    def process_alert(self, alert_json_str):
        """Process a Falco alert from JSON string."""
        try:
            alert = json.loads(alert_json_str)
            self.alert_count += 1
            
            # Extract key information
            severity = alert.get("priority", "INFO").upper()
            rule = alert.get("rule", "unknown")
            output = alert.get("output", "No output")
            time_str = alert.get("time", datetime.datetime.now().isoformat())
            
            # Store by severity
            if severity in self.alerts_by_severity:
                self.alerts_by_severity[severity].append(alert)
            
            # Log the alert
            logger.info(f"[{severity}] {rule}: {output}")
            
            # Save to JSON file
            self._save_alert(alert)
            
            # Forward to integrations
            self._forward_to_dashboard(alert)
            
            # Send critical alerts to Slack
            if severity in ["CRITICAL", "ERROR"] and self.slack_webhook:
                self._send_to_slack(alert)
            
        except json.JSONDecodeError:
            logger.error(f"Failed to parse alert JSON: {alert_json_str}")
        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
    
    def _save_alert(self, alert):
        """Save alert to JSON file."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_id = f"{timestamp}_{self.alert_count}"
        
        # Ensure severity directory exists
        severity = alert.get("priority", "INFO").upper()
        severity_dir = self.alerts_dir / severity
        severity_dir.mkdir(exist_ok=True)
        
        # Save alert to file
        alert_file = severity_dir / f"{alert_id}.json"
        with open(alert_file, 'w') as f:
            json.dump(alert, f, indent=2)
    
    def _forward_to_dashboard(self, alert):
        """Forward alert to security dashboard."""
        if not self.dashboard_url:
            return
            
        try:
            # Format alert for dashboard
            dashboard_alert = {
                "source": "falco",
                "severity": alert.get("priority", "INFO").upper(),
                "type": alert.get("rule", "unknown"),
                "message": alert.get("output", "No output"),
                "timestamp": int(time.time()),
                "details": alert
            }
            
            # Send to dashboard API
            response = requests.post(
                f"{self.dashboard_url}/api/alerts",
                json=dashboard_alert,
                timeout=5
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to send alert to dashboard: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error forwarding alert to dashboard: {str(e)}")
    
    def _send_to_slack(self, alert):
        """Send critical alert to Slack."""
        if not self.slack_webhook:
            return
            
        try:
            # Format Slack message
            severity = alert.get("priority", "INFO").upper()
            rule = alert.get("rule", "unknown")
            output = alert.get("output", "No output")
            
            # Create color based on severity
            color = "#ff0000" if severity == "CRITICAL" else "#ff9900"
            
            slack_message = {
                "attachments": [
                    {
                        "fallback": f"[{severity}] {rule}: {output}",
                        "color": color,
                        "title": f"Container Security Alert: {rule}",
                        "text": output,
                        "fields": [
                            {
                                "title": "Severity",
                                "value": severity,
                                "short": True
                            },
                            {
                                "title": "Host",
                                "value": socket.gethostname(),
                                "short": True
                            }
                        ],
                        "footer": "Security Testing Pipeline",
                        "ts": int(time.time())
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(
                self.slack_webhook,
                json=slack_message,
                timeout=5
            )
            
            if response.status_code != 200:
                logger.warning(f"Failed to send alert to Slack: {response.status_code} {response.text}")
                
        except Exception as e:
            logger.error(f"Error sending alert to Slack: {str(e)}")
    
    def get_summary(self):
        """Get a summary of processed alerts."""
        return {
            "total_alerts": self.alert_count,
            "alerts_by_severity": {k: len(v) for k, v in self.alerts_by_severity.items()}
        }

def setup_argument_parser():
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(description='Runtime Security Monitoring Tool')
    parser.add_argument('--log-file', default='/var/log/falco/falco.log', 
                        help='Path to Falco log file')
    parser.add_argument('--dashboard-url', default='http://localhost:8080',
                        help='URL of the security dashboard')
    parser.add_argument('--slack-webhook', 
                        help='Slack webhook URL for notifications')
    return parser

def main():
    """Main function."""
    # Parse arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Set up alert processor
    alert_processor = RuntimeAlertProcessor(
        dashboard_url=args.dashboard_url,
        slack_webhook=args.slack_webhook
    )
    
    # Set up file system event handler for Falco log file
    event_handler = FalcoAlertHandler(args.log_file, alert_processor)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(args.log_file), recursive=False)
    
    try:
        logger.info(f"Starting runtime security monitoring of {args.log_file}")
        observer.start()
        
        # Keep the script running
        while True:
            time.sleep(60)
            summary = alert_processor.get_summary()
            logger.info(f"Alert summary: {json.dumps(summary)}")
            
    except KeyboardInterrupt:
        logger.info("Stopping runtime security monitoring")
        observer.stop()
    
    observer.join()

if __name__ == "__main__":
    main() 