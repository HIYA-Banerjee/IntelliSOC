import os
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def generate_synthetic_data(num_samples=5000, seed=42):
    np.random.seed(seed)
    random.seed(seed)
    
    print(f"Generating {num_samples} synthetic traffic flow records...")
    
    categories = [
        "Normal", "DDoS", "Botnet", "Port Scan", 
        "Brute Force", "SQL Injection", "Malware", "Phishing", "Reconnaissance"
    ]
    
    # Probabilities for each category
    probs = [0.55, 0.12, 0.05, 0.08, 0.06, 0.04, 0.04, 0.03, 0.03]
    
    data = []
    
    # Setup some realistic IPs
    internal_ips = [f"192.168.1.{i}" for i in range(10, 100)]
    external_ips = [f"203.0.113.{i}" for i in range(1, 50)]
    malicious_ips = ["198.51.100.42", "203.0.113.195", "192.0.2.89", "45.227.254.3", "185.156.177.5"]
    
    protocols = ["TCP", "UDP", "ICMP"]
    
    for _ in range(num_samples):
        cat = np.random.choice(categories, p=probs)
        
        # Default features (Normal)
        proto = np.random.choice(protocols, p=[0.7, 0.25, 0.05])
        src_port = random.randint(1024, 65535)
        dest_port = np.random.choice([80, 443, 22, 53, 8080], p=[0.3, 0.5, 0.1, 0.05, 0.05])
        
        packet_count = random.randint(3, 30)
        packet_size = random.randint(64, 1500)
        flow_duration = round(random.uniform(0.01, 10.0), 4)
        tcp_flags = "A" if proto == "TCP" else ""
        
        connection_frequency = float(random.randint(1, 10))
        connection_density = float(random.randint(1, 5))
        reputation_score = random.randint(0, 15)  # low risk
        
        src_ip = np.random.choice(internal_ips)
        dest_ip = np.random.choice(external_ips)
        
        label = 0 if cat == "Normal" else 1
        
        # Inject characteristics based on attack categories
        if cat == "DDoS":
            # High volume, fast duration, small-medium packet size, single destination, many packets
            proto = "TCP"
            src_ip = np.random.choice(malicious_ips[:2])
            dest_ip = "192.168.1.50"  # Target server
            dest_port = 80
            packet_count = random.randint(500, 5000)
            packet_size = random.randint(64, 128)
            flow_duration = round(random.uniform(0.1, 1.5), 4)
            tcp_flags = "S"  # SYN flood
            connection_frequency = float(random.randint(200, 1000))
            connection_density = 1.0  # target single host
            reputation_score = random.randint(85, 100)
            
        elif cat == "Port Scan":
            # Many distinct ports, low packet count, short duration
            proto = "TCP"
            src_ip = np.random.choice(malicious_ips[2:3])
            dest_ip = "192.168.1.10"
            dest_port = random.randint(1, 10000)
            packet_count = random.randint(1, 3)
            packet_size = 64
            flow_duration = round(random.uniform(0.001, 0.1), 4)
            tcp_flags = "S"
            connection_frequency = float(random.randint(50, 500))
            connection_density = float(random.randint(50, 100)) # scanning density
            reputation_score = random.randint(50, 80)
            
        elif cat == "Brute Force":
            # Repeated connection attempts to ports 22 (SSH) or 3389 (RDP)
            proto = "TCP"
            src_ip = np.random.choice(malicious_ips[1:2])
            dest_ip = "192.168.1.20"
            dest_port = np.random.choice([22, 3389])
            packet_count = random.randint(10, 40)
            packet_size = random.randint(128, 256)
            flow_duration = round(random.uniform(1.0, 5.0), 4)
            tcp_flags = "PA"
            connection_frequency = float(random.randint(30, 150))
            connection_density = 1.0
            reputation_score = random.randint(80, 95)
            
        elif cat == "SQL Injection":
            # Normal connection rate, but large packet size representing payloads
            proto = "TCP"
            src_ip = np.random.choice(external_ips)
            dest_ip = "192.168.1.15"  # Web server
            dest_port = 80
            packet_count = random.randint(5, 15)
            packet_size = random.randint(1800, 4500)  # Large payload
            flow_duration = round(random.uniform(0.5, 3.0), 4)
            tcp_flags = "PA"
            connection_frequency = float(random.randint(2, 8))
            connection_density = 1.0
            reputation_score = random.randint(10, 40)
            
        elif cat == "Botnet":
            # Command & Control periodic connections (beaconing)
            proto = "TCP"
            src_ip = "192.168.1.99"  # Infected local host
            dest_ip = np.random.choice(malicious_ips[0:1]) # C2 server
            dest_port = 8080
            packet_count = random.randint(4, 10)
            packet_size = random.randint(100, 300)
            flow_duration = round(random.uniform(0.1, 2.0), 4)
            tcp_flags = "PA"
            connection_frequency = float(random.randint(10, 50))
            connection_density = 1.0
            reputation_score = random.randint(90, 100)
            
        elif cat == "Malware":
            # Downloading payload or data exfiltration
            proto = "TCP"
            src_ip = "192.168.1.100"
            dest_ip = np.random.choice(malicious_ips[3:5])
            dest_port = 443
            packet_count = random.randint(50, 500)
            packet_size = random.randint(1200, 1500) # Big files
            flow_duration = round(random.uniform(5.0, 60.0), 4)
            tcp_flags = "A"
            connection_frequency = float(random.randint(1, 5))
            connection_density = 1.0
            reputation_score = random.randint(85, 99)
            
        elif cat == "Phishing":
            # Redirecting to false domain, small HTTP requests
            proto = "TCP"
            src_ip = np.random.choice(internal_ips)
            dest_ip = "203.0.113.88"
            dest_port = 80
            packet_count = random.randint(5, 15)
            packet_size = random.randint(200, 600)
            flow_duration = round(random.uniform(0.2, 1.5), 4)
            tcp_flags = "PA"
            connection_frequency = float(random.randint(2, 12))
            connection_density = 1.0
            reputation_score = random.randint(60, 80)
            
        elif cat == "Reconnaissance":
            # Ping sweeping, slow scanning
            proto = "ICMP" if random.random() > 0.5 else "UDP"
            src_ip = np.random.choice(malicious_ips[2:3])
            dest_ip = f"192.168.1.{random.randint(1, 254)}"
            dest_port = 0 if proto == "ICMP" else random.randint(1, 1024)
            packet_count = random.randint(1, 2)
            packet_size = 32 if proto == "ICMP" else 64
            flow_duration = round(random.uniform(0.001, 0.05), 4)
            tcp_flags = ""
            connection_frequency = float(random.randint(10, 100))
            connection_density = float(random.randint(10, 50))
            reputation_score = random.randint(40, 75)

        data.append({
            "source_ip": src_ip,
            "destination_ip": dest_ip,
            "source_port": src_port,
            "destination_port": dest_port,
            "protocol": proto,
            "packet_size": packet_size,
            "packet_count": packet_count,
            "flow_duration": flow_duration,
            "tcp_flags": tcp_flags,
            "connection_frequency": connection_frequency,
            "connection_density": connection_density,
            "reputation_score": reputation_score,
            "label": label,
            "attack_category": cat
        })
        
    df = pd.DataFrame(data)
    
    # Create save directory
    os.makedirs("ml_training/data", exist_ok=True)
    df.to_csv("ml_training/data/synthetic_traffic.csv", index=False)
    print("Saved main traffic dataset to ml_training/data/synthetic_traffic.csv")
    
    # 2. Time-series sequence dataset for Forecasting Model (LSTM/GRU)
    # Generate sequential traffic stats representing counts per second
    time_series_data = []
    base_time = datetime.now() - timedelta(hours=24)
    current_attack_prob = 0.05  # low baseline
    
    print("Generating time-series sequence data for forecast modeling...")
    for i in range(1440): # 1440 minutes in 24 hours
        timestamp = base_time + timedelta(minutes=i)
        
        # Inject occasional spikes of attacks (e.g. DDoS/Scans starting)
        hour = timestamp.hour
        # Peak attack hours simulated at night
        if (hour >= 2 and hour <= 4) or (hour >= 14 and hour <= 16):
            # high attack probability
            current_attack_prob = min(0.95, current_attack_prob + 0.1)
        else:
            current_attack_prob = max(0.02, current_attack_prob - 0.05)
            
        # Add random walk noise
        current_attack_prob = np.clip(current_attack_prob + np.random.normal(0, 0.05), 0.0, 1.0)
        
        # Generate counts based on probability
        total_packets = int(np.random.normal(1000, 200) + (current_attack_prob * 10000))
        malicious_packets = int(current_attack_prob * total_packets * np.random.uniform(0.8, 1.0))
        if malicious_packets < 0:
            malicious_packets = 0
            
        # Define current active attacks based on thresholds
        attack_occurred = 1 if current_attack_prob > 0.4 else 0
        
        time_series_data.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "total_packets": total_packets,
            "malicious_packets": malicious_packets,
            "packet_rate": round(total_packets / 60.0, 2),
            "anomaly_score": round(current_attack_prob + np.random.uniform(-0.1, 0.1), 4),
            "attack_occurred": attack_occurred
        })
        
    df_ts = pd.DataFrame(time_series_data)
    df_ts.to_csv("ml_training/data/synthetic_time_series.csv", index=False)
    print("Saved sequence dataset to ml_training/data/synthetic_time_series.csv")
    print("Dataset generation complete!")

if __name__ == "__main__":
    generate_synthetic_data()
