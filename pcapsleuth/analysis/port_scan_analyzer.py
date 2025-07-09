import logging
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import time

logger = logging.getLogger(__name__)

class PortScanAnalyzer:
    """Analyzer for detecting various port scanning techniques"""
    
    def __init__(self):
        self.name = "PortScanAnalyzer"
        # Track connection attempts per source IP
        self.tcp_syn_attempts = defaultdict(lambda: defaultdict(list))  # src_ip -> {dst_ip: [ports]}
        self.udp_attempts = defaultdict(lambda: defaultdict(list))      # src_ip -> {dst_ip: [ports]}
        self.tcp_connect_attempts = defaultdict(lambda: defaultdict(set))  # src_ip -> {dst_ip: {ports}}
        
        # Track timing for rate-based detection
        self.scan_timestamps = defaultdict(list)  # src_ip -> [timestamps]
        
        # Track different scan types
        self.stealth_scans = defaultdict(lambda: defaultdict(list))  # src_ip -> {scan_type: [targets]}
        
        # Track open ports discovered
        self.open_ports = defaultdict(lambda: defaultdict(set))  # dst_ip -> {protocol: {ports}}
    
    def process_packet(self, packet, state, results, config):
        """Process each packet for port scanning indicators"""
        try:
            # Skip non-IP packets
            if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                return
                
            # Get IP layer (support both IPv4 and IPv6)
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            
            current_time = time.time()
            
            # Analyze TCP packets
            if packet.haslayer(TCP):
                self._analyze_tcp_packet(packet, src_ip, dst_ip, current_time, config)
            
            # Analyze UDP packets
            elif packet.haslayer(UDP):
                self._analyze_udp_packet(packet, src_ip, dst_ip, current_time, config)
                
        except Exception as e:
            logger.debug(f"Error processing packet in PortScanAnalyzer: {e}")
    
    def _analyze_tcp_packet(self, packet, src_ip, dst_ip, current_time, config):
        """Analyze TCP packet for scanning patterns"""
        tcp_layer = packet[TCP]
        dst_port = tcp_layer.dport
        src_port = tcp_layer.sport
        flags = tcp_layer.flags
        
        # Record timestamp for rate analysis
        self.scan_timestamps[src_ip].append(current_time)
        
        # TCP SYN Scan Detection (most common)
        if flags & 0x02 and not (flags & 0x10):  # SYN flag set, ACK not set
            self.tcp_syn_attempts[src_ip][dst_ip].append(dst_port)
        
        # TCP Connect Scan Detection (SYN+ACK response)
        elif flags & 0x12:  # SYN+ACK flags set
            self.tcp_connect_attempts[src_ip][dst_ip].add(dst_port)
            # Mark as potentially open port
            self.open_ports[dst_ip]['tcp'].add(dst_port)
        
        # Stealth Scan Detection
        elif flags & 0x01:  # FIN scan
            self.stealth_scans[src_ip]['FIN'].append((dst_ip, dst_port))
        elif flags == 0:  # NULL scan
            self.stealth_scans[src_ip]['NULL'].append((dst_ip, dst_port))
        elif flags & 0x29:  # XMAS scan (FIN+PSH+URG)
            self.stealth_scans[src_ip]['XMAS'].append((dst_ip, dst_port))
        
        # Track successful connections (open ports)
        if flags & 0x10:  # ACK flag - part of established connection
            self.open_ports[dst_ip]['tcp'].add(dst_port)
    
    def _analyze_udp_packet(self, packet, src_ip, dst_ip, current_time, config):
        """Analyze UDP packet for scanning patterns"""
        udp_layer = packet[UDP]
        dst_port = udp_layer.dport
        
        # Record timestamp for rate analysis
        self.scan_timestamps[src_ip].append(current_time)
        
        # UDP scan detection
        self.udp_attempts[src_ip][dst_ip].append(dst_port)
        
        # Common UDP ports might indicate port scanning
        if dst_port in [53, 161, 123, 500, 1900, 5353]:  # DNS, SNMP, NTP, etc.
            self.open_ports[dst_ip]['udp'].add(dst_port)
    
    def finalize(self, state, results, config):
        """Analyze collected data and populate results"""
        try:
            # Analyze TCP SYN scans
            self._detect_tcp_syn_scans(results, config)
            
            # Analyze UDP scans
            self._detect_udp_scans(results, config)
            
            # Analyze stealth scans
            self._detect_stealth_scans(results, config)
            
            # Analyze scan timing patterns
            self._detect_rapid_scans(results, config)
            
            # Compile open ports summary
            self._compile_open_ports(results)
            
        except Exception as e:
            logger.error(f"Error in PortScanAnalyzer finalization: {e}")
            results.errors.append(f"PortScanAnalyzer finalization error: {str(e)}")
    
    def _detect_tcp_syn_scans(self, results, config):
        """Detect TCP SYN scanning patterns"""
        syn_scan_threshold = getattr(config, 'syn_scan_threshold', 20)
        
        for src_ip, targets in self.tcp_syn_attempts.items():
            for dst_ip, ports in targets.items():
                unique_ports = set(ports)
                
                if len(unique_ports) >= syn_scan_threshold:
                    results.port_scanning.add_tcp_syn_scan(
                        src_ip, dst_ip, len(unique_ports), list(unique_ports)
                    )
    
    def _detect_udp_scans(self, results, config):
        """Detect UDP scanning patterns"""
        udp_scan_threshold = getattr(config, 'udp_scan_threshold', 15)
        
        for src_ip, targets in self.udp_attempts.items():
            for dst_ip, ports in targets.items():
                unique_ports = set(ports)
                
                if len(unique_ports) >= udp_scan_threshold:
                    results.port_scanning.add_udp_scan(
                        src_ip, dst_ip, len(unique_ports), list(unique_ports)
                    )
    
    def _detect_stealth_scans(self, results, config):
        """Detect stealth scanning patterns"""
        stealth_scan_threshold = getattr(config, 'stealth_scan_threshold', 10)
        
        for src_ip, scan_types in self.stealth_scans.items():
            for scan_type, targets in scan_types.items():
                if len(targets) >= stealth_scan_threshold:
                    results.port_scanning.add_stealth_scan(
                        src_ip, scan_type, len(targets), targets
                    )
    
    def _detect_rapid_scans(self, results, config):
        """Detect rapid scanning based on timing"""
        rapid_scan_threshold = getattr(config, 'rapid_scan_threshold', 50)  # packets per second
        time_window = getattr(config, 'rapid_scan_window', 1)  # seconds
        
        for src_ip, timestamps in self.scan_timestamps.items():
            if len(timestamps) < rapid_scan_threshold:
                continue
                
            # Sort timestamps
            timestamps.sort()
            
            # Check for rapid scanning windows
            for i in range(len(timestamps) - rapid_scan_threshold + 1):
                window_start = timestamps[i]
                window_end = timestamps[i + rapid_scan_threshold - 1]
                
                if window_end - window_start <= time_window:
                    packets_per_second = rapid_scan_threshold / time_window
                    results.port_scanning.add_rapid_scan(
                        src_ip, packets_per_second, window_start, window_end
                    )
                    break
    
    def _compile_open_ports(self, results):
        """Compile discovered open ports"""
        for dst_ip, protocols in self.open_ports.items():
            for protocol, ports in protocols.items():
                if ports:  # Only add if there are actual ports
                    results.port_scanning.add_open_ports(
                        dst_ip, protocol, sorted(list(ports))
                    )