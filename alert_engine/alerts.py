import os
import sys
import json
import smtplib
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.broker import MessageBroker
from api.supabase_client import get_supabase_client

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AlertEngine")

class AlertEngine:
    def __init__(self, supabase_client=None):
        self.broker = MessageBroker()
        self.supabase = supabase_client or get_supabase_client()
        
        # Load configs
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_from = os.getenv("SMTP_FROM", "soc-alert@intellisoc.local")
        self.smtp_to = os.getenv("SMTP_TO", "")
        
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        
        self.running = False

    def start(self):
        self.running = True
        logger.info("Alert Engine listening for threats on prediction-stream...")
        
        # Subscribe to predictions
        self.broker.subscribe("prediction-stream", self.process_prediction, group_id="alert-engine-group")
        
        # Keep running
        try:
            while self.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        logger.info("Stopping Alert Engine...")

    def process_prediction(self, data: dict):
        try:
            # We only generate alerts for detected attacks
            if data.get("attack_detected") != "Yes":
                # Still store benign logs in Supabase traffic_logs for statistics
                self._save_traffic_log(data)
                return
            
            logger.warning(f"CRITICAL THREAT DETECTED: {data['threat_type']} from IP {data['source_ip']} -> {data['destination_ip']} (Risk: {data['risk_score']}, Severity: {data['severity_level']})")
            
            # 1. Save traffic and threat log to Supabase
            traffic_id = self._save_traffic_log(data)
            threat_id = self._save_threat_log(data, traffic_id)
            alert_id = self._save_alert(data, threat_id)
            
            # Publish alert update for real-time dashboard listeners
            alert_payload = {
                "alert_id": alert_id,
                "threat_log_id": threat_id,
                "timestamp": data["timestamp"],
                "threat_type": data["threat_type"],
                "risk_level": data["severity_level"],
                "risk_score": data["risk_score"],
                "source_ip": data["source_ip"],
                "destination_ip": data["destination_ip"],
                "confidence_score": data["confidence_score"]
            }
            self.broker.publish("alert-stream", alert_payload)

            # 2. Trigger Email Alert
            self._send_email_alert(data)
            
            # 3. Trigger Telegram Alert
            self._send_telegram_alert(data)
            
        except Exception as e:
            logger.error(f"Error processing prediction in AlertEngine: {e}")

    def _save_traffic_log(self, data: dict) -> str:
        """Saves raw traffic parameters to Supabase."""
        log_id = f"sim-{datetime.now().microsecond}"
        if not self.supabase:
            return log_id
            
        try:
            res = self.supabase.table("traffic_logs").insert({
                "source_ip": data["source_ip"],
                "destination_ip": data["destination_ip"],
                "source_port": data["source_port"],
                "destination_port": data["destination_port"],
                "protocol": data["protocol"],
                "packet_size": int(data["packet_size"]),
                "packet_count": int(data["packet_count"]),
                "flow_duration": float(data["flow_duration"]),
                "tcp_flags": data["tcp_flags"],
                "connection_frequency": float(data["connection_frequency"])
            }).execute()
            if res.data:
                return res.data[0]["id"]
        except Exception as e:
            logger.error(f"Failed to save traffic log to Supabase: {e}")
        return log_id

    def _save_threat_log(self, data: dict, traffic_id: str) -> str:
        """Saves enriched threat analytics to Supabase."""
        log_id = f"threat-{datetime.now().microsecond}"
        if not self.supabase:
            return log_id
            
        try:
            insert_data = {
                "source_ip": data["source_ip"],
                "destination_ip": data["destination_ip"],
                "threat_type": data["threat_type"],
                "attack_detected": True,
                "confidence_score": float(data["confidence_score"]),
                "severity_score": float(data["risk_score"]),
                "severity_level": data["severity_level"],
                "anomaly_score": float(data["anomaly_score"]),
                "shap_explanations": data["shap_explanations"],
                "remediation_steps": data["remediation_steps"]
            }
            # Link traffic record if we got an actual UUID from Supabase
            if len(traffic_id) > 15:
                insert_data["traffic_log_id"] = traffic_id
                
            res = self.supabase.table("threat_logs").insert(insert_data).execute()
            if res.data:
                return res.data[0]["id"]
        except Exception as e:
            logger.error(f"Failed to save threat log to Supabase: {e}")
        return log_id

    def _save_alert(self, data: dict, threat_id: str) -> str:
        """Saves alert log to Supabase."""
        alert_id = f"alert-{datetime.now().microsecond}"
        if not self.supabase:
            return alert_id
            
        try:
            insert_data = {
                "threat_type": data["threat_type"],
                "risk_level": data["severity_level"],
                "source_ip": data["source_ip"],
                "destination_ip": data["destination_ip"],
                "confidence_score": float(data["confidence_score"]),
                "status": "unread"
            }
            if len(threat_id) > 15:
                insert_data["threat_log_id"] = threat_id
                
            res = self.supabase.table("alerts").insert(insert_data).execute()
            if res.data:
                return res.data[0]["id"]
        except Exception as e:
            logger.error(f"Failed to save alert to Supabase: {e}")
        return alert_id

    def _send_email_alert(self, data: dict):
        if not self.smtp_user or not self.smtp_to:
            logger.debug("Email alerts bypassed. SMTP credentials or recipient not configured in .env.")
            return
            
        try:
            subject = f"[IntelliSOC Alert] {data['severity_level']} Risk: {data['threat_type']} Detected!"
            
            body = f"""
            ======================================================================
            INTELLISOC SECURITY Operations Center - REALTIME THREAT ALERT
            ======================================================================
            
            Timestamp:          {data['timestamp']}
            Threat Category:    {data['threat_type']}
            Risk Severity:      {data['severity_level']} (Score: {data['risk_score']}/100)
            Source Attacker:    {data['source_ip']} (Port: {data['source_port']})
            Destination Target: {data['destination_ip']} (Port: {data['destination_port']})
            IDS Confidence:     {data['confidence_score']}%
            Anomaly Deviation:  {data['anomaly_score']}%
            
            ======================================================================
            EXPLAINABLE AI INSIGHTS (SHAP)
            ======================================================================
            {data['shap_explanations'].get('text_summary', 'Explainability metrics loading...')}
            
            ======================================================================
            RECOMMENDED INCIDENT MITIGATION
            ======================================================================
            {data['remediation_steps']}
            
            This is an automated message. Please review the SOC Dashboard immediately.
            """
            
            msg = MIMEMultipart()
            msg['From'] = self.smtp_from
            msg['To'] = self.smtp_to
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))
            
            # Connection
            server = smtplib.SMTP(self.smtp_host, self.smtp_port)
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.sendmail(self.smtp_from, self.smtp_to, msg.as_string())
            server.quit()
            logger.info(f"Email alert dispatched successfully to {self.smtp_to}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def _send_telegram_alert(self, data: dict):
        if not self.telegram_token or not self.telegram_chat_id:
            logger.debug("Telegram alert bypassed. Bot token or Chat ID not configured in .env.")
            return
            
        try:
            emoji = "🚨" if data["severity_level"] == "Critical" else "⚠️" if data["severity_level"] == "High" else "ℹ️"
            message = (
                f"{emoji} *IntelliSOC Threat Alert* {emoji}\n\n"
                f"*Type:* `{data['threat_type']}`\n"
                f"*Risk Severity:* `{data['severity_level']}` (Score: {data['risk_score']}/100)\n"
                f"*Confidence:* `{data['confidence_score']}%`\n"
                f"*Source IP:* `{data['source_ip']}`\n"
                f"*Destination IP:* `{data['destination_ip']}`\n"
                f"*Target Port:* `{data['destination_port']}`\n"
                f"*Time:* `{data['timestamp']}`\n\n"
                f"*Mitigation Plan:*\n{data['remediation_steps']}"
            )
            
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                logger.info("Telegram alert dispatched successfully.")
            else:
                logger.error(f"Telegram API responded with error status: {res.status_code}")
        except Exception as e:
            logger.error(f"Failed to dispatch Telegram alert: {e}")

if __name__ == "__main__":
    engine = AlertEngine()
    engine.start()
