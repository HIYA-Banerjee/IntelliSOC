import os
import sys
import joblib
import pandas as pd
import numpy as np
import time
import logging
import threading
from datetime import datetime
from dotenv import load_dotenv

# PyTorch imports for forecasting
try:
    import torch
except ImportError:
    pass

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.broker import MessageBroker
from threat_intelligence.threat_intel import ThreatIntelEngine
from threat_detection.explain import ExplainerModule
from threat_forecasting.forecaster_model import ThreatForecasterLSTM

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatDetector")

class ThreatDetectionService:
    def __init__(self):
        self.broker = MessageBroker()
        self.intel_engine = ThreatIntelEngine()
        self.explainer = ExplainerModule()
        
        # Load pipelines
        self.binary_ids = self._load_model("ml_training/models/binary_ids_pipeline.joblib")
        self.classifier = self._load_model("ml_training/models/threat_classifier_pipeline.joblib")
        self.severity = self._load_model("ml_training/models/threat_severity_pipeline.joblib")
        self.anomaly_detector = self._load_model("ml_training/models/anomaly_detector_pipeline.joblib")
        
        # LSTM Forecaster setup
        self.device = "cpu"
        self.lstm_model = None
        self.lstm_scaler = None
        self._load_forecaster()
        
        # Sequence buffer for forecasting (maintains last 10 intervals of traffic logs)
        self.sequence_lock = threading.Lock()
        self.sequence_history = []
        self.seq_length = 10
        self._init_sequence_history()
        
        # Keep track of statistics
        self.stats = {
            "total_packets": 0,
            "malicious_packets": 0,
            "anomaly_sum": 0.0,
            "counts_lock": threading.Lock()
        }
        
        # Periodically aggregate stats and run forecasting
        self.running = False
        
    def _load_model(self, path):
        if os.path.exists(path):
            try:
                model = joblib.load(path)
                logger.info(f"Loaded ML model from {path}")
                return model
            except Exception as e:
                logger.error(f"Error loading model {path}: {e}")
        else:
            logger.warning(f"ML Model path {path} not found. Standalone prediction fallback will be active.")
        return None

    def _load_forecaster(self):
        weights_path = "ml_training/models/forecaster_lstm.pth"
        scaler_path = "ml_training/models/forecaster_scaler.joblib"
        
        if os.path.exists(weights_path) and os.path.exists(scaler_path):
            try:
                self.lstm_scaler = joblib.load(scaler_path)
                self.lstm_model = ThreatForecasterLSTM(input_dim=4, hidden_dim=32, num_layers=2, output_dim=3)
                self.lstm_model.load_state_dict(torch.load(weights_path, map_location=torch.device('cpu')))
                self.lstm_model.eval()
                logger.info("Loaded LSTM threat forecasting weights and scaler.")
            except Exception as e:
                logger.error(f"Error loading LSTM forecasting model: {e}")
        else:
            logger.warning("Forecasting models not found. Running prediction fallback.")

    def _init_sequence_history(self):
        # Initialize with baseline stats
        for _ in range(self.seq_length):
            self.sequence_history.append([50.0, 0.0, 1.0, 5.0]) # normal counts

    def start(self):
        self.running = True
        logger.info("Threat Detection Analytical Service Started.")
        
        # Launch forecasting polling thread
        forecast_thread = threading.Thread(target=self._forecasting_loop, daemon=True)
        forecast_thread.start()
        
        # Subscribe to active flows
        self.broker.subscribe("flow-stream", self.process_flow, group_id="detector-group")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        logger.info("Stopping Threat Detection Service...")

    def process_flow(self, flow_data: dict):
        try:
            # 1. Threat Intel Reputation Lookup
            src_ip = flow_data["source_ip"]
            dest_ip = flow_data["destination_ip"]
            
            intel_res = self.intel_engine.lookup_ip(src_ip)
            # update reputation features
            flow_data["reputation_score"] = intel_res["reputation"]
            
            # Map features to a single-row DataFrame
            feature_cols = [
                "source_port", "destination_port", "protocol", "packet_size", 
                "packet_count", "flow_duration", "tcp_flags", 
                "connection_frequency", "connection_density", "reputation_score"
            ]
            row_dict = {col: flow_data.get(col, 0.0) for col in feature_cols}
            row_dict["protocol"] = flow_data.get("protocol", "TCP")
            row_dict["tcp_flags"] = flow_data.get("tcp_flags", "")
            
            df_inst = pd.DataFrame([row_dict])
            
            # 2. Anomaly Detection (Unsupervised Isolation Forest)
            anomaly_score = 0.0
            if self.anomaly_detector:
                try:
                    # Anomaly detector is a pipeline
                    scores = self.anomaly_detector.named_steps['anomaly_detector'].decision_function(
                        self.anomaly_detector.named_steps['preprocessor'].transform(df_inst)
                    )
                    anomaly_score = float(np.clip((0.5 - scores[0]) * 100, 0, 100))
                except Exception as e:
                    logger.debug(f"Error predicting anomaly: {e}")
                    anomaly_score = 10.0 + (50.0 if intel_res["reputation"] > 50 else 0)
            
            # 3. Binary IDS Detection (Ensemble)
            attack_detected = False
            confidence = 0.0
            
            if self.binary_ids:
                try:
                    pred = self.binary_ids.predict(df_inst)[0]
                    prob = self.binary_ids.predict_proba(df_inst)[0][1] # Probability of malicious (class 1)
                    
                    attack_detected = bool(pred == 1)
                    confidence = float(prob * 100)
                except Exception as e:
                    logger.error(f"Binary prediction error: {e}")
            else:
                # Rule-based fallback
                if intel_res["reputation"] > 50 or anomaly_score > 60:
                    attack_detected = True
                    confidence = max(55.0, float(intel_res["reputation"]))
                    
            # 4. Threat Classification & Severity (if attack is detected)
            threat_type = "Normal"
            risk_score = 0.0
            severity_level = "Low"
            shap_output = {}
            remediation = "No threat mitigation necessary. Traffic is within expected baseline."
            
            if attack_detected:
                # Classify attack
                if self.classifier:
                    try:
                        classes = self.classifier["classes"]
                        pipeline = self.classifier["pipeline"]
                        pred_idx = pipeline.predict(df_inst)[0]
                        threat_type = classes[pred_idx]
                    except Exception as e:
                        logger.error(f"Classification error: {e}")
                        threat_type = "Reconnaissance Attack" if anomaly_score < 50 else "DDoS"
                else:
                    # Fallback rules
                    if flow_data["connection_frequency"] > 300:
                        threat_type = "DDoS"
                    elif flow_data["connection_density"] > 30:
                        threat_type = "Port Scan"
                    elif flow_data["destination_port"] == 22:
                        threat_type = "Brute Force"
                    elif flow_data["packet_size"] > 1500:
                        threat_type = "SQL Injection"
                    else:
                        threat_type = "Malware"

                # Severity Risk Score
                # Add classification column since severity depends on it
                df_inst_sev = df_inst.copy()
                df_inst_sev["attack_category"] = threat_type
                
                if self.severity:
                    try:
                        risk_score = float(self.severity.predict(df_inst_sev)[0])
                        # Map to label
                        if risk_score < 25.0:
                            severity_level = "Low"
                        elif risk_score < 50.0:
                            severity_level = "Medium"
                        elif risk_score < 75.0:
                            severity_level = "High"
                        else:
                            severity_level = "Critical"
                    except Exception as e:
                        logger.error(f"Severity calculation error: {e}")
                else:
                    # Fallback scoring
                    risk_score = min(100.0, confidence + (20.0 if severity_level == "Critical" else 0.0))
                    
                # Force categories if score matches
                if risk_score < 25.0: severity_level = "Low"
                elif risk_score < 50.0: severity_level = "Medium"
                elif risk_score < 75.0: severity_level = "High"
                else: severity_level = "Critical"
                
                # Explainable AI Attributions (SHAP)
                shap_output = self.explainer.explain_flow(flow_data)
                
                # Mitigation steps compile
                remediation = self._get_remediation_steps(threat_type, src_ip, dest_ip, flow_data["destination_port"])
                
            # Update stats
            with self.stats["counts_lock"]:
                self.stats["total_packets"] += flow_data["packet_count"]
                if attack_detected:
                    self.stats["malicious_packets"] += flow_data["packet_count"]
                self.stats["anomaly_sum"] += anomaly_score
                
            # Compile final prediction output
            enriched_payload = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": flow_data["source_port"],
                "destination_port": flow_data["destination_port"],
                "protocol": flow_data["protocol"],
                "packet_size": flow_data["packet_size"],
                "packet_count": flow_data["packet_count"],
                "flow_duration": flow_data["flow_duration"],
                "tcp_flags": flow_data["tcp_flags"],
                "connection_frequency": flow_data["connection_frequency"],
                "connection_density": flow_data["connection_density"],
                "attack_detected": "Yes" if attack_detected else "No",
                "confidence_score": round(confidence, 2),
                "threat_type": threat_type,
                "anomaly_score": round(anomaly_score, 2),
                "risk_score": round(risk_score, 2),
                "severity_level": severity_level,
                "shap_explanations": shap_output,
                "remediation_steps": remediation
            }
            
            # Post prediction to broker
            self.broker.publish("prediction-stream", enriched_payload)
            
        except Exception as e:
            logger.error(f"Error processing flow in detector: {e}")

    def _get_remediation_steps(self, threat_type: str, src_ip: str, dest_ip: str, dest_port: int) -> str:
        mitigations = {
            "DDoS": f"1. Rate-limit incoming TCP traffic using firewall iptables. 2. Enable SYN cookies in network settings. 3. Deploy external DDoS protection reverse-proxy. 4. Block malicious traffic originating from attacker IP: {src_ip}.",
            "Botnet": f"1. Isolate the infected internal host: {src_ip} immediately. 2. Audit corporate DNS queries for domain indicators. 3. Block Command & Control IP: {dest_ip} on all interfaces. 4. Perform an antivirus audit on infected systems.",
            "Port Scan": f"1. Block host {src_ip} on firewall rules. 2. Close unnecessary services and configure ports as stealth/filtered. 3. Deploy port-knocking protocols for secure SSH management.",
            "Brute Force": f"1. Block attacker IP {src_ip} on SSH/RDP ports. 2. Install Fail2Ban to block multiple failed login attempts automatically. 3. Enforce multi-factor authentication (MFA) and SSH key-only access.",
            "SQL Injection": f"1. Deploy Web Application Firewall (WAF) rule sets to inspect payloads. 2. Patch database input parameters using prepared statements. 3. Sanitize URL requests containing SQL keywords.",
            "Malware": f"1. Stop host {src_ip} from establishing connections. 2. Restrict internal ports and check endpoint indicators. 3. Terminate active sessions to the command center {dest_ip}.",
            "Phishing": f"1. Add phishing redirect domain IP {dest_ip} to DNS blocklists. 2. Enforce email SPF, DKIM, and DMARC checking. 3. Trigger immediate credential resets for affected user sessions.",
            "Reconnaissance": f"1. Block scan IP {src_ip} on perimeter filters. 2. Deactivate ICMP ping response on servers. 3. Run audit on leaked system banners."
        }
        return mitigations.get(threat_type, "Configure standard firewall block rules for source host.")

    def _forecasting_loop(self):
        """Runs in background, aggregate traffic statistics and makes predictions using the PyTorch LSTM model."""
        interval = 2.0  # run forecasting predictions every 2 seconds
        while self.running:
            time.sleep(interval)
            
            # Aggregate stats from buffer
            with self.stats["counts_lock"]:
                total = self.stats["total_packets"]
                malicious = self.stats["malicious_packets"]
                anom_sum = self.stats["anomaly_sum"]
                
                # Reset counters
                self.stats["total_packets"] = 0
                self.stats["malicious_packets"] = 0
                self.stats["anomaly_sum"] = 0.0
                
            rate = round(total / interval, 2)
            avg_anomaly = round(anom_sum / max(1.0, total), 2)
            
            # Add to sliding window history
            new_log = [float(total), float(malicious), float(rate), float(avg_anomaly)]
            
            with self.sequence_lock:
                self.sequence_history.append(new_log)
                if len(self.sequence_history) > self.seq_length:
                    self.sequence_history.pop(0)
                
                # Prepare forecasting tensor
                seq_data = np.array(self.sequence_history) # shape (10, 4)
                
            # Perform LSTM forecasting
            forecast_probabilities = [0.0, 0.0, 0.0]
            if self.lstm_model and self.lstm_scaler:
                try:
                    # Scale inputs
                    # scaler fits on columns: total_packets, malicious_packets, packet_rate, anomaly_score
                    scaled_seq = self.lstm_scaler.transform(seq_data)
                    input_tensor = torch.tensor(scaled_seq, dtype=torch.float32).unsqueeze(0) # shape (1, 10, 4)
                    
                    with torch.no_grad():
                        out = self.lstm_model(input_tensor)
                        probs = out[0].numpy()
                        forecast_probabilities = [float(probs[0]), float(probs[1]), float(probs[2])]
                except Exception as e:
                    logger.debug(f"Forecasting error: {e}")
                    forecast_probabilities = self._get_fallback_forecast(new_log)
            else:
                forecast_probabilities = self._get_fallback_forecast(new_log)
                
            # Package prediction
            forecast_payload = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "forecast_1m": round(forecast_probabilities[0], 4),
                "forecast_5m": round(forecast_probabilities[1], 4),
                "forecast_15m": round(forecast_probabilities[2], 4),
                "attack_probability": round(max(forecast_probabilities), 4),
                "forecast_model": "LSTM"
            }
            
            self.broker.publish("predictions", forecast_payload)

    def _get_fallback_forecast(self, current_stats):
        # Fallback math based on malicious packet ratio
        malicious_ratio = current_stats[1] / max(1.0, current_stats[0])
        prob_1m = max(0.01, min(0.99, malicious_ratio * 1.2))
        prob_5m = max(0.02, min(0.99, malicious_ratio * 1.5 + 0.05))
        prob_15m = max(0.05, min(0.99, malicious_ratio * 1.8 + 0.10))
        return [prob_1m, prob_5m, prob_15m]

if __name__ == "__main__":
    service = ThreatDetectionService()
    service.start()
