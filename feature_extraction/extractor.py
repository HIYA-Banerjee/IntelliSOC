import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from collections import defaultdict
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.broker import MessageBroker

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FeatureExtractor")

class FlowExtractor:
    def __init__(self):
        self.broker = MessageBroker()
        
        # Active flows cache: (src_ip, dest_ip, src_port, dest_port, protocol) -> list of packets
        self.active_flows = {}
        self.flow_lock = threading.Lock()
        
        # Connection cache for last 60 seconds to calculate frequency and density
        # List of tuples: (timestamp, src_ip, dest_ip, dest_port)
        self.recent_connections = []
        self.cache_lock = threading.Lock()
        
        # Inactivity timeout (seconds) to seal and publish a flow
        self.flow_timeout = 3.0
        
        self.running = False

    def start(self):
        self.running = True
        logger.info("Starting Flow Feature Extraction Service...")
        
        # Start the flow cleanup and publisher thread
        cleanup_thread = threading.Thread(target=self._flow_cleanup_loop, daemon=True)
        cleanup_thread.start()
        
        # Subscribe to raw traffic stream
        self.broker.subscribe("traffic-stream", self.process_packet, group_id="extractor-group")
        
        # Keep running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        logger.info("Stopping Flow Feature Extraction Service...")

    def process_packet(self, packet_data: dict):
        try:
            # Parse packet timestamp
            ts_str = packet_data.get("timestamp")
            try:
                pkt_time = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                pkt_time = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                
            src_ip = packet_data.get("source_ip")
            dest_ip = packet_data.get("destination_ip")
            src_port = packet_data.get("source_port")
            dest_port = packet_data.get("destination_port")
            protocol = packet_data.get("protocol")
            size = packet_data.get("packet_size", 64)
            flags = packet_data.get("tcp_flags", "")

            # 1. Update the 60-second connection cache
            # Convert port to int if possible
            d_port = int(dest_port) if dest_port is not None else 0
            with self.cache_lock:
                now_epoch = time.time()
                self.recent_connections.append((now_epoch, src_ip, dest_ip, d_port))
                # Purge connections older than 60 seconds
                self.recent_connections = [
                    conn for conn in self.recent_connections if now_epoch - conn[0] <= 60.0
                ]

            # 2. Update active flows
            flow_key = (src_ip, dest_ip, src_port, dest_port, protocol)
            
            with self.flow_lock:
                if flow_key not in self.active_flows:
                    self.active_flows[flow_key] = {
                        "first_seen": pkt_time,
                        "last_seen": pkt_time,
                        "packet_count": 0,
                        "total_size": 0,
                        "tcp_flags": set()
                    }
                
                flow = self.active_flows[flow_key]
                flow["last_seen"] = pkt_time
                flow["packet_count"] += 1
                flow["total_size"] += size
                if flags:
                    # add individual characters as flag indicators
                    for f in flags:
                        if f.strip():
                            flow["tcp_flags"].add(f)
                            
        except Exception as e:
            logger.error(f"Error processing packet in feature extractor: {e}")

    def _flow_cleanup_loop(self):
        """Periodically scans active flows and seals/publishes expired flows."""
        while self.running:
            time.sleep(1.0)
            now = datetime.now()
            expired_flows = []
            
            with self.flow_lock:
                for key, flow in list(self.active_flows.items()):
                    elapsed = (now - flow["last_seen"]).total_seconds()
                    # Seal flow if it timed out or packet count exceeds threshold (to avoid memory blowup)
                    if elapsed >= self.flow_timeout or flow["packet_count"] >= 1000:
                        expired_flows.append((key, self.active_flows.pop(key)))
            
            for key, flow in expired_flows:
                self._seal_and_publish_flow(key, flow)

    def _seal_and_publish_flow(self, key, flow_data):
        try:
            src_ip, dest_ip, src_port, dest_port, protocol = key
            
            first = flow_data["first_seen"]
            last = flow_data["last_seen"]
            duration = max(0.0001, (last - first).total_seconds())
            
            packets = flow_data["packet_count"]
            avg_size = round(flow_data["total_size"] / packets, 2)
            
            # Combine TCP flags
            flags_str = "".join(sorted(list(flow_data["tcp_flags"])))
            
            # Calculate connection frequency and density in the last 60 seconds
            # Frequency: count of packets from src_ip to dest_ip
            # Density: unique destination ports targeted on dest_ip by src_ip
            freq = 0
            dest_ports = set()
            
            with self.cache_lock:
                for _, s_ip, d_ip, d_port in self.recent_connections:
                    if s_ip == src_ip and d_ip == dest_ip:
                        freq += 1
                        dest_ports.add(d_port)
            
            density = float(len(dest_ports))
            
            # Query Database IP blacklisting reputation multiplier (will be double-checked in Threat Detection Service)
            # Default threat reputation score initialized to 0
            reputation_score = 0
            
            flow_features = {
                "timestamp": last.strftime("%Y-%m-%d %H:%M:%S.%f"),
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": protocol,
                "packet_size": avg_size,
                "packet_count": packets,
                "flow_duration": round(duration, 4),
                "tcp_flags": flags_str,
                "connection_frequency": float(freq),
                "connection_density": density,
                "reputation_score": reputation_score
            }
            
            self.broker.publish("flow-stream", flow_features)
            
        except Exception as e:
            logger.error(f"Error sealing flow {key}: {e}")

if __name__ == "__main__":
    extractor = FlowExtractor()
    extractor.start()
