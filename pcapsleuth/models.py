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
    
    # Errors
    errors: List[str] = field(default_factory=list)