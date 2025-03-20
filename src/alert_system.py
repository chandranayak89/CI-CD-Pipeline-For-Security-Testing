"""
Alert system module for the Security Testing Pipeline.
This module handles notifications and alerts for security threats.
"""

import logging
import time
import json
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger("Security-Pipeline-AlertSystem")

class AlertSystem:
    """
    Manages security alerts and notifications.
    """
    def __init__(self, config=None):
        """
        Initialize the alert system.
        
        Args:
            config: Configuration dictionary with alert settings
        """
        # Default configuration
        self.config = {
            "log_alerts": True,
            "alert_file": "security_alerts.log",
            "email_alerts": False,
            "email_config": {
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "smtp_user": "",
                "smtp_password": "",
                "from_email": "alerts@example.com",
                "to_emails": ["admin@example.com"]
            },
            "webhook_alerts": False,
            "webhook_url": "",
            "min_severity": "MEDIUM"  # Minimum severity to trigger alerts
        }
        
        # Update with provided configuration
        if config:
            self._update_config(config)
        
        # Create alerts directory if logging to file
        if self.config["log_alerts"]:
            os.makedirs(os.path.dirname(self.config["alert_file"]), exist_ok=True)
        
        # Maintain an in-memory record of recent alerts
        self.recent_alerts = []
        self.max_recent_alerts = 100
    
    def _update_config(self, config):
        """
        Update configuration with provided values.
        
        Args:
            config: Configuration dictionary with alert settings
        """
        # Deep merge for nested dictionaries
        for key, value in config.items():
            if isinstance(value, dict) and key in self.config and isinstance(self.config[key], dict):
                self.config[key].update(value)
            else:
                self.config[key] = value
    
    def trigger_alert(self, alert_data):
        """
        Trigger an alert based on the provided data.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        # Check alert severity against minimum configured severity
        if not self._check_severity(alert_data.get("severity", "MEDIUM")):
            logger.debug(f"Alert ignored due to low severity: {alert_data.get('type')}")
            return
        
        # Add timestamp if not present
        if "timestamp" not in alert_data:
            alert_data["timestamp"] = time.time()
        
        # Log the alert
        logger.warning(f"SECURITY ALERT: {alert_data.get('message', 'No message provided')}")
        
        # Add to recent alerts
        self._add_to_recent_alerts(alert_data)
        
        # Log to file if configured
        if self.config["log_alerts"]:
            self._log_to_file(alert_data)
        
        # Send email if configured
        if self.config["email_alerts"]:
            self._send_email_alert(alert_data)
        
        # Send webhook if configured
        if self.config["webhook_alerts"]:
            self._send_webhook_alert(alert_data)
    
    def _check_severity(self, alert_severity):
        """
        Check if an alert's severity meets the minimum threshold.
        
        Args:
            alert_severity: Severity of the alert
            
        Returns:
            bool: Whether the alert should be processed
        """
        severity_levels = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        
        alert_level = severity_levels.get(alert_severity, 2)
        min_level = severity_levels.get(self.config["min_severity"], 2)
        
        return alert_level >= min_level
    
    def _add_to_recent_alerts(self, alert_data):
        """
        Add an alert to the recent alerts list.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        self.recent_alerts.append(alert_data)
        
        # Trim if exceeded maximum
        if len(self.recent_alerts) > self.max_recent_alerts:
            self.recent_alerts = self.recent_alerts[-self.max_recent_alerts:]
    
    def _log_to_file(self, alert_data):
        """
        Log alert to a file.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        try:
            with open(self.config["alert_file"], "a") as f:
                f.write(json.dumps(alert_data) + "\n")
        except Exception as e:
            logger.error(f"Failed to log alert to file: {str(e)}")
    
    def _send_email_alert(self, alert_data):
        """
        Send an email alert.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg["From"] = self.config["email_config"]["from_email"]
            msg["To"] = ", ".join(self.config["email_config"]["to_emails"])
            msg["Subject"] = f"Security Alert: {alert_data.get('type', 'Unknown')} - {alert_data.get('severity', 'MEDIUM')}"
            
            # Create email body
            body = f"""
            Security Alert Details:
            
            Type: {alert_data.get('type', 'Unknown')}
            Severity: {alert_data.get('severity', 'MEDIUM')}
            Time: {time.ctime(alert_data.get('timestamp', time.time()))}
            Source: {alert_data.get('source', 'Unknown')}
            Target: {alert_data.get('target', 'Unknown')}
            
            Message: {alert_data.get('message', 'No details provided')}
            
            This is an automated alert from the Security Testing Pipeline.
            """
            
            msg.attach(MIMEText(body, "plain"))
            
            # Connect to server and send
            server = smtplib.SMTP(
                self.config["email_config"]["smtp_server"], 
                self.config["email_config"]["smtp_port"]
            )
            server.starttls()
            
            # Login if credentials provided
            if self.config["email_config"]["smtp_user"] and self.config["email_config"]["smtp_password"]:
                server.login(
                    self.config["email_config"]["smtp_user"], 
                    self.config["email_config"]["smtp_password"]
                )
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent for {alert_data.get('type')}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
    
    def _send_webhook_alert(self, alert_data):
        """
        Send a webhook alert.
        
        Args:
            alert_data: Dictionary containing alert information
        """
        if not self.config["webhook_url"]:
            return
            
        try:
            import requests
            
            # Send the webhook request
            response = requests.post(
                self.config["webhook_url"],
                json=alert_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"Webhook alert sent for {alert_data.get('type')}")
            else:
                logger.error(f"Webhook returned error: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {str(e)}")
    
    def get_recent_alerts(self, count=10, min_severity=None):
        """
        Get recent alerts, optionally filtered by severity.
        
        Args:
            count: Number of alerts to return
            min_severity: Minimum severity level to include
            
        Returns:
            list: Recent alerts
        """
        alerts = self.recent_alerts
        
        # Filter by severity if specified
        if min_severity:
            alerts = [a for a in alerts if self._check_severity(a.get("severity", "MEDIUM"))]
        
        # Return most recent first
        return sorted(alerts, key=lambda x: x.get("timestamp", 0), reverse=True)[:count] 