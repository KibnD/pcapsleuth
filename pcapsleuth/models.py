from dataclasses import dataclass, field
from collections import Counter
from typing import List, Dict, Tuple, Optional, Any
from datetime import datetime

@dataclass
class Config:
    """Configuration for PcapSleuth analysis"""
    # DNS Analysis Settings
    dns_entropy_threshold: float = 3.5
    dns_max_query_length: int = 100
    dns_txt_query_threshold: int = 50
    
    # ICMP Analysis Settings
    icmp_flood_threshold: int = 100
    icmp_flood_time_window: int = 1  # seconds
    
    # Port Scanning Analysis Settings
    syn_scan_threshold: int = 20  # minimum unique ports to consider SYN scan
    udp_scan_threshold: int = 15  # minimum unique ports to consider UDP scan
    stealth_scan_threshold: int = 10  # minimum attempts to consider stealth scan
    rapid_scan_threshold: int = 50  # packets per second threshold
    rapid_scan_window: int = 1  # time window in seconds
    
    # General Settings
    max_top_talkers: int = 10
    max_dns_queries: int = 10
    batch_size: int = 1000
    show_progress: bool = True

@dataclass
class ProcessingState:
    """Internal state during packet processing"""
    talker_counter: Counter = field(default_factory=Counter)
    protocol_counter: Counter = field(default_factory=Counter)
    dns_counter: Counter = field(default_factory=Counter)
    icmp_timestamps: Dict[str, List[float]] = field(default_factory=dict)
    packet_count: int = 0

@dataclass
class DnsTunnelingResult:
    """Results from DNS tunneling analysis"""
    high_entropy_queries: List[Dict[str, Any]] = field(default_factory=list)
    excessive_txt_queries: Dict[str, int] = field(default_factory=dict)
    total_suspicious_queries: int = 0
    
    def add_suspicious_query(self, query: str, entropy: float, source_ip: str):
        self.high_entropy_queries.append({
            'query': query,
            'entropy': entropy,
            'source_ip': source_ip,
            'timestamp': datetime.now().isoformat()
        })
        self.total_suspicious_queries += 1

@dataclass
class IcmpFloodResult:
    """Results from ICMP flood analysis"""
    potential_floods: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_icmp_packets: int = 0
    
    def add_flood_detection(self, target_ip: str, packet_count: int, timespan: float):
        self.potential_floods[target_ip] = {
            'packet_count': packet_count,
            'timespan_seconds': timespan,
            'packets_per_second': packet_count / timespan if timespan > 0 else 0,
            'detected_at': datetime.now().isoformat()
        }

@dataclass
class PortScanResult:
    """Results from port scanning analysis"""
    tcp_syn_scans: List[Dict[str, Any]] = field(default_factory=list)
    udp_scans: List[Dict[str, Any]] = field(default_factory=list)
    stealth_scans: List[Dict[str, Any]] = field(default_factory=list)
    rapid_scans: List[Dict[str, Any]] = field(default_factory=list)
    open_ports: Dict[str, Dict[str, List[int]]] = field(default_factory=dict)
    total_scan_attempts: int = 0
    
    def add_tcp_syn_scan(self, src_ip: str, dst_ip: str, port_count: int, ports: List[int]):
        self.tcp_syn_scans.append({
            'source_ip': src_ip,
            'target_ip': dst_ip,
            'unique_ports': port_count,
            'ports': ports[:50],  # Limit to first 50 ports for display
            'scan_type': 'TCP SYN',
            'detected_at': datetime.now().isoformat()
        })
        self.total_scan_attempts += 1
    
    def add_udp_scan(self, src_ip: str, dst_ip: str, port_count: int, ports: List[int]):
        self.udp_scans.append({
            'source_ip': src_ip,
            'target_ip': dst_ip,
            'unique_ports': port_count,
            'ports': ports[:50],  # Limit to first 50 ports for display
            'scan_type': 'UDP',
            'detected_at': datetime.now().isoformat()
        })
        self.total_scan_attempts += 1
    
    def add_stealth_scan(self, src_ip: str, scan_type: str, target_count: int, targets: List[Tuple[str, int]]):
        self.stealth_scans.append({
            'source_ip': src_ip,
            'scan_type': scan_type,
            'target_count': target_count,
            'targets': targets[:20],  # Limit targets for display
            'detected_at': datetime.now().isoformat()
        })
        self.total_scan_attempts += 1
    
    def add_rapid_scan(self, src_ip: str, packets_per_second: float, start_time: float, end_time: float):
        self.rapid_scans.append({
            'source_ip': src_ip,
            'packets_per_second': packets_per_second,
            'duration_seconds': end_time - start_time,
            'start_time': datetime.fromtimestamp(start_time).isoformat(),
            'end_time': datetime.fromtimestamp(end_time).isoformat(),
            'detected_at': datetime.now().isoformat()
        })
    
    def add_open_ports(self, dst_ip: str, protocol: str, ports: List[int]):
        if dst_ip not in self.open_ports:
            self.open_ports[dst_ip] = {}
        self.open_ports[dst_ip][protocol] = ports

@dataclass
class AnalysisResult:
    """Final analysis results"""
    # Metadata
    analysis_start_time: datetime = field(default_factory=datetime.now)
    analysis_duration: Optional[float] = None
    pcap_file: str = ""
    
    # Basic Statistics
    packet_count: int = 0
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    dns_queries: List[Tuple[str, int]] = field(default_factory=list)
    
    # Advanced Analysis
    dns_tunneling: DnsTunnelingResult = field(default_factory=DnsTunnelingResult)
    icmp_floods: IcmpFloodResult = field(default_factory=IcmpFloodResult)
    port_scanning: PortScanResult = field(default_factory=PortScanResult)
    
    # Errors
    errors: List[str] = field(default_factory=list)