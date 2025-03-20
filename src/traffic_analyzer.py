"""
Traffic analyzer module for the Security Testing Pipeline.
This module analyzes network packets to identify patterns and anomalies.
"""

import logging
import time
from collections import defaultdict, deque
from scapy.all import IP, TCP, UDP, ICMP

logger = logging.getLogger("Security-Pipeline-TrafficAnalyzer")

class TrafficAnalyzer:
    """
    Analyzes network traffic to identify patterns and anomalies.
    """
    def __init__(self, threat_detector, window_size=300):
        """
        Initialize the traffic analyzer.
        
        Args:
            threat_detector: The threat detector to report findings to
            window_size: Time window in seconds for traffic analysis
        """
        self.threat_detector = threat_detector
        self.window_size = window_size
        self.packet_history = deque(maxlen=100000)  # Store recent packets
        
        # Traffic statistics
        self.ip_stats = defaultdict(int)  # IP address counts
        self.port_stats = defaultdict(int)  # Port counts
        self.protocol_stats = defaultdict(int)  # Protocol counts
        self.connection_stats = defaultdict(int)  # Connection pair counts
        self.packet_sizes = []  # Packet sizes for anomaly detection
        
        # Timestamps for rate calculations
        self.last_cleanup = time.time()
    
    def analyze_packet(self, packet):
        """
        Analyze a single packet and update statistics.
        
        Args:
            packet: The packet to analyze
        """
        # Add timestamp to track when this packet was processed
        current_time = time.time()
        packet_with_time = (current_time, packet)
        self.packet_history.append(packet_with_time)
        
        # Extract basic packet information
        self._extract_packet_info(packet)
        
        # Periodically clean up old statistics
        if current_time - self.last_cleanup > 60:  # Every minute
            self._cleanup_old_data(current_time)
            self.last_cleanup = current_time
        
        # Pass packet to threat detector for deeper analysis
        self.threat_detector.analyze_packet(packet, self)
    
    def _extract_packet_info(self, packet):
        """
        Extract information from a packet and update statistics.
        
        Args:
            packet: The packet to extract information from
        """
        # Track packet size
        packet_size = len(packet)
        self.packet_sizes.append(packet_size)
        
        # Analyze IP packets
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Update IP statistics
            self.ip_stats[src_ip] += 1
            self.ip_stats[dst_ip] += 1
            
            # Update protocol statistics
            self.protocol_stats[protocol] += 1
            
            # Update connection pair statistics
            connection_pair = f"{src_ip}:{dst_ip}"
            self.connection_stats[connection_pair] += 1
            
            # Analyze TCP packets
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Update port statistics
                self.port_stats[f"TCP:{src_port}"] += 1
                self.port_stats[f"TCP:{dst_port}"] += 1
                
                # Check for common services
                self._check_service_ports(dst_port, "TCP", src_ip, dst_ip)
                
            # Analyze UDP packets
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                
                # Update port statistics
                self.port_stats[f"UDP:{src_port}"] += 1
                self.port_stats[f"UDP:{dst_port}"] += 1
                
                # Check for common services
                self._check_service_ports(dst_port, "UDP", src_ip, dst_ip)
                
            # Analyze ICMP packets
            elif ICMP in packet:
                icmp_type = packet[ICMP].type
                self.protocol_stats[f"ICMP:{icmp_type}"] += 1
    
    def _check_service_ports(self, port, protocol, src_ip, dst_ip):
        """
        Check if the port corresponds to a common service.
        
        Args:
            port: The port number
            protocol: The protocol (TCP/UDP)
            src_ip: Source IP address
            dst_ip: Destination IP address
        """
        common_services = {
            22: "SSH", 
            23: "Telnet",
            25: "SMTP", 
            53: "DNS",
            80: "HTTP", 
            443: "HTTPS",
            3306: "MySQL", 
            3389: "RDP"
        }
        
        if port in common_services:
            service = common_services[port]
            logger.debug(f"{protocol} {service} traffic: {src_ip} -> {dst_ip}:{port}")
    
    def _cleanup_old_data(self, current_time):
        """
        Remove data older than the window size.
        
        Args:
            current_time: Current timestamp
        """
        # Keep only packets within the time window
        cutoff_time = current_time - self.window_size
        
        while self.packet_history and self.packet_history[0][0] < cutoff_time:
            self.packet_history.popleft()
        
        # Recalculate statistics if needed (optimization: could just decrement counters)
        if len(self.packet_history) < 10000:  # Only recalculate if history is small enough
            self._recalculate_statistics()
    
    def _recalculate_statistics(self):
        """Recalculate all statistics from scratch using the packet history."""
        # Reset statistics
        self.ip_stats.clear()
        self.port_stats.clear()
        self.protocol_stats.clear()
        self.connection_stats.clear()
        self.packet_sizes = []
        
        # Recalculate from packet history
        for _, packet in self.packet_history:
            self._extract_packet_info(packet)
    
    def get_traffic_summary(self):
        """
        Get a summary of the traffic statistics.
        
        Returns:
            dict: Summary of traffic statistics
        """
        # Sort stats by count
        top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        top_protocols = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        top_connections = sorted(self.connection_stats.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Calculate average packet size
        avg_packet_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        
        return {
            "packet_count": len(self.packet_history),
            "unique_ips": len(self.ip_stats),
            "unique_ports": len(self.port_stats),
            "top_ips": top_ips,
            "top_ports": top_ports,
            "top_protocols": top_protocols,
            "top_connections": top_connections,
            "avg_packet_size": avg_packet_size
        } 