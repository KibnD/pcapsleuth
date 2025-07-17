import logging
from pathlib import Path
from typing import Optional
from scapy.utils import PcapReader
from scapy.error import Scapy_Exception
from tqdm import tqdm
import os
import time
import warnings

from datetime import datetime
from .models import AnalysisResult, ProcessingState, Config
from .analysis.basic_stats import BasicStatsAnalyzer
from .analysis.dns_analyzer import DNSAnalyzer
from .analysis.icmp_analyzer import ICMPAnalyzer
from .analysis.port_scan_analyzer import PortScanAnalyzer
from pcapsleuth.analysis.http_analyzer import HTTPAnalyzer
from pcapsleuth.analysis.tls_analyzer import TLSAnalyzer

logger = logging.getLogger(__name__)

class PcapAnalysisEngine:
    """Main analysis engine with optimizations"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.analyzers = [
            BasicStatsAnalyzer(),
            DNSAnalyzer(),
            ICMPAnalyzer(),
            PortScanAnalyzer(),
        ]
        
        # Only add HTTP/TLS analyzers if enabled
        if getattr(self.config, 'http_analysis_enabled', True):
            self.analyzers.append(HTTPAnalyzer())
            
        if getattr(self.config, 'tls_analysis_enabled', True):
            self.analyzers.append(TLSAnalyzer())
        
        # Suppress scapy TLS warnings about unknown cipher suites
        warnings.filterwarnings('ignore', message='.*Unknown cipher suite.*')
        warnings.filterwarnings('ignore', message='.*more Unknown cipher suite.*')
    
    def _estimate_packet_count(self, filepath: str) -> int:
        """Estimate packet count for progress bar"""
        try:
            file_size = os.path.getsize(filepath)
            # Rough estimate: average packet size in pcap is ~100-200 bytes
            # This is just for progress bar, doesn't need to be exact
            estimated_packets = max(file_size // 150, 1000)
            return estimated_packets
        except:
            return 50000  # Default fallback
    
    def analyze_pcap(self, filepath: str) -> AnalysisResult:
        """Analyze a PCAP file with performance optimizations"""
        logger.info(f"Starting analysis of {filepath}")
        
        # Validate file
        self._validate_pcap_file(filepath)
        
        # Initialize results
        results = AnalysisResult(pcap_file=filepath)
        state = ProcessingState()
        
        # Performance tracking
        start_time = time.time()
        last_progress_update = 0
        packets_processed = 0
        
        try:
            # Setup progress bar with estimated packet count
            estimated_packets = self._estimate_packet_count(filepath)
            progress_bar = None
            
            if self.config.show_progress:
                progress_bar = tqdm(
                    total=estimated_packets,
                    desc="Processing packets",
                    unit="pkt",
                    unit_scale=True,
                    miniters=100,  # Update every 100 packets
                    maxinterval=0.5,  # Update at least every 0.5 seconds
                    bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
                    ncols=70,
                    colour="cyan"
                )
            
            # Process packets with batching
            batch_size = getattr(self.config, 'batch_size', 1000)
            packet_batch = []
            progress_update_interval = 100  # Update progress every 100 packets
            
            with PcapReader(filepath) as pcap_reader:
                for packet in pcap_reader:
                    packet_batch.append(packet)
                    packets_processed += 1
                    
                    # Process in batches for better performance
                    if len(packet_batch) >= batch_size:
                        self._process_packet_batch(packet_batch, state, results)
                        packet_batch = []
                        
                        # Update progress bar based on packet count
                        if progress_bar and packets_processed % progress_update_interval == 0:
                            # If we've processed more than estimated, adjust the total
                            if packets_processed > progress_bar.total:
                                progress_bar.total = packets_processed + estimated_packets // 4
                                progress_bar.refresh()
                            progress_bar.n = packets_processed
                            progress_bar.refresh()
                
                # Process remaining packets
                if packet_batch:
                    self._process_packet_batch(packet_batch, state, results)
                
                # Final progress update
                if progress_bar:
                    progress_bar.n = packets_processed
                    progress_bar.total = packets_processed
                    progress_bar.refresh()
                    progress_bar.close()
            
            # Update final packet count
            state.packet_count = packets_processed
            
            # Finalize results
            self._finalize_results(state, results)
            
            # Calculate total time
            total_time = time.time() - start_time
            results.analysis_duration = total_time
            
            logger.info(f"Analysis completed in {total_time:.2f}s. Processed {results.packet_count:,} packets")
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            results.errors.append(f"Analysis failed: {str(e)}")
            results.packet_count = packets_processed
            return results
    
    def _process_packet_batch(self, packet_batch, state, results):
        """Process a batch of packets"""
        for packet in packet_batch:
            # Process with each analyzer
            for analyzer in self.analyzers:
                try:
                    analyzer.process_packet(packet, state, results, self.config)
                except Exception as e:
                    error_msg = f"{type(analyzer).__name__} error: {str(e)}"
                    logger.warning(error_msg)
                    results.errors.append(error_msg)
                    
                    # Limit error messages to prevent memory issues
                    if len(results.errors) > 1000:
                        results.errors = results.errors[-500:]  # Keep last 500 errors
                        results.errors.append("... (truncated due to too many errors)")
    
    def _validate_pcap_file(self, filepath: str):
        """Validate PCAP file"""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {filepath}")
        if path.stat().st_size == 0:
            raise ValueError(f"PCAP file is empty: {filepath}")
    
    def _finalize_results(self, state: ProcessingState, results: AnalysisResult):
        """Finalize analysis results"""
        # Basic stats
        results.packet_count = state.packet_count
        results.top_talkers = state.talker_counter.most_common(self.config.max_top_talkers)
        results.dns_queries = state.dns_counter.most_common(self.config.max_dns_queries)
        
        # Protocol distribution with readable names
        protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        results.protocol_distribution = {
            protocol_names.get(proto, f'Protocol-{proto}'): count
            for proto, count in state.protocol_counter.items()
        }
        
        # Set analysis start time if not already set
        if not results.analysis_start_time:
            results.analysis_start_time = datetime.now()
        
        # Finalize analyzers
        for analyzer in self.analyzers:
            try:
                analyzer.finalize(state, results, self.config)
            except Exception as e:
                error_msg = f"{type(analyzer).__name__} finalization error: {str(e)}"
                logger.warning(error_msg)
                results.errors.append(error_msg)