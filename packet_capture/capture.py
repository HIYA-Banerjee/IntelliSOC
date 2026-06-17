import os
import sys
import json
import time
import random
import logging
from datetime import datetime
from dotenv import load_dotenv

# Add project root to path to import broker
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.broker import MessageBroker

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PacketCapture")

SCAPY_AVAILABLE = False
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy is not installed. Packet capture will run in SIMULATION mode.")

class PacketCaptureAgent:
    def __init__(self):
        self.broker = MessageBroker()
        self.simulation_mode = os.getenv("SIMULATION_MODE", "True").lower() == "true"
        self.interface = os.getenv("CAPTURE_INTERFACE", None)
        self.max_packets = int(os.getenv("MAX_PACKETS_TO_CAPTURE", 100000))
        self.packet_count = 0
        self.running = False

    def start(self):
        self.running = True
        logger.info(f"Starting Packet Capture Agent. Mode: {'SIMULATION' if self.simulation_mode or not SCAPY_AVAILABLE else 'LIVE'}")
        
        if self.simulation_mode or not SCAPY_AVAILABLE:
            self.run_simulation()
        else:
            self.run_live_capture()

    def stop(self):
        self.running = False
        logger.info("Stopping Packet Capture Agent...")

    def run_live_capture(self):
        logger.info(f"Sniffing live packets on interface: {self.interface or 'Default'}")
        try:
            # Scapy sniffer loop
            scapy.sniff(
                iface=self.interface,
                prn=self._process_scapy_packet,
                stop_filter=lambda x: not self.running or self.packet_count >= self.max_packets,
                store=False
            )
        except Exception as e:
            logger.error(f"Error sniffing live traffic: {e}. Falling back to simulation mode.")
            self.simulation_mode = True
            self.run_simulation()

    def _process_scapy_packet(self, packet):
        try:
            if not packet.haslayer('IP'):
                return
            
            ip_layer = packet['IP']
            src_ip = ip_layer.src
            dest_ip = ip_layer.dst
            proto_num = ip_layer.proto
            
            # Map protocol number to string
            protocol = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else "ICMP" if proto_num == 1 else "OTHER"
            
            src_port = None
            dest_port = None
            tcp_flags = ""
            
            if packet.haslayer('TCP'):
                src_port = int(packet['TCP'].sport)
                dest_port = int(packet['TCP'].dport)
                # Parse TCP Flags
                flags = packet['TCP'].flags
                tcp_flags = str(flags)
            elif packet.haslayer('UDP'):
                src_port = int(packet['UDP'].sport)
                dest_port = int(packet['UDP'].dport)
            
            packet_size = len(packet)
            
            packet_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": protocol,
                "packet_size": packet_size,
                "tcp_flags": tcp_flags
            }
            
            self.packet_count += 1
            self.broker.publish("traffic-stream", packet_data)
            
            if self.packet_count % 100 == 0:
                logger.info(f"Captured {self.packet_count} live packets.")
                
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")

    def run_simulation(self):
        logger.info("Starting High-Fidelity Network Traffic Simulator...")
        
        # Setup IPs
        internal_ips = [f"192.168.1.{i}" for i in range(10, 80)]
        external_ips = [f"203.0.113.{i}" for i in range(1, 30)]
        malicious_ips = ["198.51.100.42", "203.0.113.195", "192.0.2.89", "45.227.254.3", "185.156.177.5"]
        
        attack_active = False
        attack_type = None
        attack_end_time = 0
        
        while self.running:
            # Check if attack timer expired
            if attack_active and time.time() > attack_end_time:
                logger.info(f"Simulated attack '{attack_type}' ended. Reverting to normal traffic baseline.")
                attack_active = False
                attack_type = None
            
            # Periodically trigger random attacks (e.g. 15% chance if no active attack)
            if not attack_active and random.random() < 0.05:
                attack_active = True
                attack_type = random.choice([
                    "DDoS", "Port Scan", "Brute Force", "SQL Injection", "Botnet Beaconing", "Malware Exfil"
                ])
                duration = random.randint(15, 45) # 15-45 seconds
                attack_end_time = time.time() + duration
                logger.warning(f"Simulating ATTACK: '{attack_type}' started for {duration}s!")
            
            # Define number of packets to generate in this iteration
            num_packets = random.randint(15, 30) if attack_active and attack_type in ["DDoS", "Port Scan"] else random.randint(1, 5)
            
            for _ in range(num_packets):
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                
                # Generate packet according to state
                if attack_active:
                    pkt = self._generate_attack_packet(attack_type, internal_ips, external_ips, malicious_ips, timestamp)
                else:
                    pkt = self._generate_normal_packet(internal_ips, external_ips, timestamp)
                
                if pkt:
                    self.broker.publish("traffic-stream", pkt)
                    self.packet_count += 1
            
            # Control flow rate (sleep 0.1s to 0.5s)
            time.sleep(random.uniform(0.1, 0.4) if attack_active else random.uniform(0.5, 1.5))

    def _generate_normal_packet(self, internal, external, timestamp):
        # Normal HTTP/HTTPS, DNS or SSH packet
        src_ip = random.choice(internal)
        dest_ip = random.choice(external)
        
        # 50/50 outbound vs inbound
        if random.random() > 0.5:
            src_ip, dest_ip = dest_ip, src_ip
            
        proto = random.choice(["TCP", "UDP"])
        if proto == "TCP":
            dest_port = random.choice([80, 443, 22])
            src_port = random.randint(1024, 65535)
            tcp_flags = random.choice(["S", "A", "PA", "FA"])
            packet_size = random.randint(64, 1500)
        else:
            dest_port = 53 # DNS
            src_port = random.randint(1024, 65535)
            tcp_flags = ""
            packet_size = random.randint(50, 150)
            
        return {
            "timestamp": timestamp,
            "source_ip": src_ip,
            "destination_ip": dest_ip,
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": proto,
            "packet_size": packet_size,
            "tcp_flags": tcp_flags
        }

    def _generate_attack_packet(self, attack_type, internal, external, malicious, timestamp):
        # Custom packet generations for various attack categories
        if attack_type == "DDoS":
            # SYN Flood targeting local port 80/443
            src_ip = random.choice(malicious[:2])
            dest_ip = "192.168.1.50"
            dest_port = 80
            src_port = random.randint(1024, 65535)
            return {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": "TCP",
                "packet_size": 64,
                "tcp_flags": "S"
            }
            
        elif attack_type == "Port Scan":
            # Scanning multiple ports on one target server
            src_ip = random.choice(malicious[2:3])
            dest_ip = "192.168.1.10"
            dest_port = random.randint(1, 2000) # Rapidly scanning low ports
            src_port = random.randint(1024, 65535)
            return {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": "TCP",
                "packet_size": 64,
                "tcp_flags": "S"
            }
            
        elif attack_type == "Brute Force":
            # Repeated heavy TCP flags on port 22
            src_ip = random.choice(malicious[1:2])
            dest_ip = "192.168.1.20"
            dest_port = 22
            src_port = random.randint(1024, 65535)
            return {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": "TCP",
                "packet_size": random.randint(128, 256),
                "tcp_flags": "PA"
            }
            
        elif attack_type == "SQL Injection":
            # Large packet size on port 80 containing SQL query vectors
            src_ip = random.choice(external)
            dest_ip = "192.168.1.15"
            dest_port = 80
            src_port = random.randint(1024, 65535)
            return {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": "TCP",
                "packet_size": random.randint(1800, 3500), # Large request size
                "tcp_flags": "PA"
            }
            
        elif attack_type == "Botnet Beaconing":
            # Infected local bot communicating with outside command controller
            src_ip = "192.168.1.99"
            dest_ip = malicious[0] # Mirai server
            dest_port = 8080
            src_port = random.randint(1024, 65535)
            return {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": "TCP",
                "packet_size": random.randint(80, 200),
                "tcp_flags": "PA"
            }
            
        elif attack_type == "Malware Exfil":
            # High volume upload
            src_ip = "192.168.1.100"
            dest_ip = random.choice(malicious[3:5])
            dest_port = 443
            src_port = random.randint(1024, 65535)
            return {
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "protocol": "TCP",
                "packet_size": 1460, # max payload size
                "tcp_flags": "A"
            }
            
        return self._generate_normal_packet(internal, external, timestamp)

if __name__ == "__main__":
    agent = PacketCaptureAgent()
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
