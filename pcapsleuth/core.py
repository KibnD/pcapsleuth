import logging
from pathlib import Path
from typing import Optional
from scapy.utils import PcapReader
from scapy.error import Scapy_Exception
from tqdm import tqdm
import os

from datetime import datetime
from .models import AnalysisResult, ProcessingState, Config
from .analysis.basic_stats import BasicStatsAnalyzer
from .analysis.dns_analyzer import DNSAnalyzer
from .analysis.icmp_analyzer import ICMPAnalyzer
from .analysis.port_scan_analyzer import PortScanAnalyzer

logger = logging.getLogger(__name__)

class PcapAnalysisEngine:
    """Main analysis engine"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.analyzers = [
            BasicStatsAnalyzer(),
            DNSAnalyzer(),
            ICMPAnalyzer(),
            PortScanAnalyzer()  # Add the new port scanning analyzer
        ]
        
    def analyze_pcap(self, filepath: str) -> AnalysisResult:
        """Analyze a PCAP file"""
        logger.info(f"Starting analysis of {filepath}")
        
        # Validate file
        self._validate_pcap_file(filepath)
        
        # Initialize results
        results = AnalysisResult(pcap_file=filepath)
        state = ProcessingState()
        
        try:
            # Setup progress bar
            file_size = os.path.getsize(filepath)
            progress_bar = None
            
            if self.config.show_progress:
                progress_bar = tqdm(
                    total=file_size,
                    desc="Processing packets",
                    unit="B",
                    unit_scale=True
                )
            
            # Process packets
            with PcapReader(filepath) as pcap_reader:
                for packet in pcap_reader:
                    state.packet_count += 1
                    
                    # Process with each analyzer
                    for analyzer in self.analyzers:
                        try:
                            analyzer.process_packet(packet, state, results, self.config)
                        except Exception as e:
                            error_msg = f"{type(analyzer).__name__} error: {str(e)}"
                            logger.warning(error_msg)
                            results.errors.append(error_msg)
                    
                    # Update progress
                    if progress_bar and hasattr(pcap_reader, 'f'):
                        try:
                            current_pos = pcap_reader.f.tell()
                            progress_bar.update(current_pos - progress_bar.n)
                        except:
                            pass
                
                if progress_bar:
                    progress_bar.close()
            
            # Finalize results
            self._finalize_results(state, results)
            
            logger.info(f"Analysis completed. Processed {results.packet_count} packets")
            return results
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            results.errors.append(f"Analysis failed: {str(e)}")
            return results
    
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
        
        # Calculate duration
        if results.analysis_start_time:
            results.analysis_duration = (datetime.now() - results.analysis_start_time).total_seconds()
        
        # Finalize analyzers
        for analyzer in self.analyzers:
            try:
                analyzer.finalize(state, results, self.config)
            except Exception as e:
                error_msg = f"{type(analyzer).__name__} finalization error: {str(e)}"
                logger.warning(error_msg)
                results.errors.append(error_msg)