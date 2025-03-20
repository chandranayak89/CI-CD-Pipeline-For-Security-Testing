"""
Threat detector module for the Security Testing Pipeline.
This module detects potential security threats based on network traffic analysis.
"""

import logging
import time
from collections import defaultdict, Counter
from scapy.all import IP, TCP, UDP, ICMP

logger = logging.getLogger("Security-Pipeline-ThreatDetector")

class ThreatDetector:
    """
    Detects potential security threats based on network traffic patterns.
    """
    def __init__(self, alert_system, threshold_config=None):
        """
        Initialize the threat detector.
        
        Args:
            alert_system: The alert system to report threats to
            threshold_config: Configuration dictionary with detection thresholds
        """
        self.alert_system = alert_system
        
        # Default thresholds (can be overridden with threshold_config)
        self.thresholds = {
            "port_scan": 15,  # Number of different ports from same source in time window
            "syn_flood": 100,  # Number of SYN packets without ACK from same source
            "icmp_flood": 50,  # Number of ICMP packets from same source
            "connection_rate": 30,  # New connections per second from single source
            "unusual_ports": [6667, 4444, 31337, 1337],  # Known suspicious ports
        }
        
        # Update thresholds if provided
        if threshold_config:
            self.thresholds.update(threshold_config)
        
        # Tracking data structures
        self.connection_attempts = defaultdict(Counter)  # Source IP -> destination port -> count
        self.syn_packets = defaultdict(int)  # Source IP -> SYN packet count
        self.icmp_packets = defaultdict(int)  # Source IP -> ICMP packet count
        self.connection_times = defaultdict(list)  # Source IP -> list of connection timestamps
        
        # Track last cleanup time
        self.last_cleanup = time.time()
        self.time_window = 60  # 60 second window for detection
    
    def analyze_packet(self, packet, traffic_analyzer):
        """
        Analyze a packet for potential threats.
        
        Args:
            packet: The packet to analyze
            traffic_analyzer: Reference to the traffic analyzer for context
        """
        # Periodically clean old data
        current_time = time.time()
        if current_time - self.last_cleanup > 30:  # Clean every 30 seconds
            self._cleanup_old_data(current_time)
            self.last_cleanup = current_time
            
        # Skip non-IP packets
        if IP not in packet:
            return
        
        # Extract basic packet information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for port scanning
        self._check_port_scan(packet, src_ip, dst_ip)
        
        # Check for SYN flood
        self._check_syn_flood(packet, src_ip, dst_ip)
        
        # Check for ICMP flood
        self._check_icmp_flood(packet, src_ip)
        
        # Check for unusual ports
        self._check_unusual_ports(packet, src_ip, dst_ip)
        
        # Check for high connection rate
        self._check_connection_rate(packet, src_ip, current_time)
    
    def _check_port_scan(self, packet, src_ip, dst_ip):
        """
        Check for port scanning activity.
        
        Args:
            packet: The packet to analyze
            src_ip: Source IP address
            dst_ip: Destination IP address
        """
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            self.connection_attempts[src_ip][dst_port] += 1
            
            # Check if this IP has tried too many different ports
            if len(self.connection_attempts[src_ip]) >= self.thresholds["port_scan"]:
                message = f"Possible port scan detected from {src_ip} - {len(self.connection_attempts[src_ip])} ports"
                self._report_threat("PORT_SCAN", src_ip, dst_ip, message)
                # Reset counter to avoid repeated alerts
                self.connection_attempts[src_ip].clear()
    
    def _check_syn_flood(self, packet, src_ip, dst_ip):
        """
        Check for SYN flood attack.
        
        Args:
            packet: The packet to analyze
            src_ip: Source IP address
            dst_ip: Destination IP address
        """
        if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag is set
            self.syn_packets[src_ip] += 1
            
            if self.syn_packets[src_ip] >= self.thresholds["syn_flood"]:
                message = f"Possible SYN flood attack from {src_ip} - {self.syn_packets[src_ip]} SYN packets"
                self._report_threat("SYN_FLOOD", src_ip, dst_ip, message)
                # Reset counter to avoid repeated alerts
                self.syn_packets[src_ip] = 0
    
    def _check_icmp_flood(self, packet, src_ip):
        """
        Check for ICMP flood attack.
        
        Args:
            packet: The packet to analyze
            src_ip: Source IP address
        """
        if ICMP in packet:
            self.icmp_packets[src_ip] += 1
            
            if self.icmp_packets[src_ip] >= self.thresholds["icmp_flood"]:
                message = f"Possible ICMP flood attack from {src_ip} - {self.icmp_packets[src_ip]} ICMP packets"
                self._report_threat("ICMP_FLOOD", src_ip, "multiple", message)
                # Reset counter to avoid repeated alerts
                self.icmp_packets[src_ip] = 0
    
    def _check_unusual_ports(self, packet, src_ip, dst_ip):
        """
        Check for traffic on unusual or suspicious ports.
        
        Args:
            packet: The packet to analyze
            src_ip: Source IP address
            dst_ip: Destination IP address
        """
        suspicious_ports = self.thresholds["unusual_ports"]
        
        if TCP in packet:
            dst_port = packet[TCP].dport
            if dst_port in suspicious_ports:
                message = f"Traffic detected on suspicious port {dst_port} from {src_ip} to {dst_ip}"
                self._report_threat("SUSPICIOUS_PORT", src_ip, dst_ip, message)
        
        elif UDP in packet:
            dst_port = packet[UDP].dport
            if dst_port in suspicious_ports:
                message = f"Traffic detected on suspicious port {dst_port} from {src_ip} to {dst_ip}"
                self._report_threat("SUSPICIOUS_PORT", src_ip, dst_ip, message)
    
    def _check_connection_rate(self, packet, src_ip, current_time):
        """
        Check for abnormally high connection rate from a single source.
        
        Args:
            packet: The packet to analyze
            src_ip: Source IP address
            current_time: Current timestamp
        """
        if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag (new connection attempt)
            self.connection_times[src_ip].append(current_time)
            
            # Count connections in the last 10 seconds
            recent_connections = [t for t in self.connection_times[src_ip] 
                                 if t > current_time - 10]
            self.connection_times[src_ip] = recent_connections
            
            if len(recent_connections) > self.thresholds["connection_rate"]:
                message = f"High connection rate from {src_ip} - {len(recent_connections)} in 10 seconds"
                self._report_threat("HIGH_CONNECTION_RATE", src_ip, "multiple", message)
                # Don't reset to continue monitoring
    
    def _cleanup_old_data(self, current_time):
        """
        Clean up data structures to remove old entries.
        
        Args:
            current_time: Current timestamp
        """
        # Remove connection attempts older than the time window
        # This is a simplification - in a real system we would timestamp each attempt
        # For this implementation, we just periodically clear all data
        cutoff_time = current_time - self.time_window
        
        # Clear connection times older than the cutoff
        for ip in list(self.connection_times.keys()):
            self.connection_times[ip] = [t for t in self.connection_times[ip] if t > cutoff_time]
            if not self.connection_times[ip]:
                del self.connection_times[ip]
    
    def _report_threat(self, threat_type, source, target, message):
        """
        Report a detected threat to the alert system.
        
        Args:
            threat_type: Type of the threat detected
            source: Source of the threat (usually an IP)
            target: Target of the threat (IP or 'multiple')
            message: Detailed message about the threat
        """
        logger.warning(f"THREAT DETECTED: {message}")
        
        threat_data = {
            "type": threat_type,
            "source": source,
            "target": target,
            "timestamp": time.time(),
            "message": message,
            "severity": self._calculate_severity(threat_type)
        }
        
        self.alert_system.trigger_alert(threat_data)
    
    def _calculate_severity(self, threat_type):
        """
        Calculate the severity level of a threat.
        
        Args:
            threat_type: Type of the threat detected
            
        Returns:
            str: Severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
        """
        severity_map = {
            "PORT_SCAN": "MEDIUM",
            "SYN_FLOOD": "HIGH",
            "ICMP_FLOOD": "MEDIUM",
            "HIGH_CONNECTION_RATE": "MEDIUM",
            "SUSPICIOUS_PORT": "HIGH"
        }
        
        return severity_map.get(threat_type, "MEDIUM") 