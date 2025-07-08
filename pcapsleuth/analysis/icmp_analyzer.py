from scapy.layers.inet import IP, ICMP
import time
import logging

logger = logging.getLogger(__name__)

class ICMPAnalyzer:
    """ICMP analyzer with flood detection"""
    
    def process_packet(self, packet, state, results, config):
        """Process ICMP packets"""
        if not packet.haslayer(ICMP):
            return
        
        icmp_layer = packet[ICMP]
        
        # Only process echo requests (ping)
        if icmp_layer.type != 8:
            return
        
        if packet.haslayer(IP):
            try:
                dst_ip = packet[IP].dst
                timestamp = time.time()
                
                # Track timestamps per destination
                if dst_ip not in state.icmp_timestamps:
                    state.icmp_timestamps[dst_ip] = []
                
                state.icmp_timestamps[dst_ip].append(timestamp)
                results.icmp_floods.total_icmp_packets += 1
                
            except Exception as e:
                logger.warning(f"ICMP processing error: {e}")
    
    def finalize(self, state, results, config):
        """Finalize ICMP analysis and detect floods"""
        try:
            for dst_ip, timestamps in state.icmp_timestamps.items():
                if len(timestamps) < config.icmp_flood_threshold:
                    continue
                
                # Check for rapid bursts
                timestamps.sort()
                for i in range(len(timestamps) - config.icmp_flood_threshold + 1):
                    window_start = timestamps[i]
                    window_end = timestamps[i + config.icmp_flood_threshold - 1]
                    
                    if window_end - window_start <= config.icmp_flood_time_window:
                        # Found a flood
                        results.icmp_floods.add_flood_detection(
                            dst_ip, 
                            config.icmp_flood_threshold,
                            window_end - window_start
                        )
                        break
            
            logger.debug(f"ICMP analysis complete. {len(results.icmp_floods.potential_floods)} floods detected")
            
        except Exception as e:
            logger.warning(f"ICMP finalization error: {e}")