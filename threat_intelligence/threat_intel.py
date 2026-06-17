import os
import sys
import logging
from dotenv import load_dotenv

# Path setups
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.supabase_client import get_supabase_client

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ThreatIntelligence")

class ThreatIntelEngine:
    def __init__(self, supabase_client=None):
        self.supabase = supabase_client or get_supabase_client()
        
        # Local fallback blacklist
        self.local_blacklist = {
            "198.51.100.42": {"reputation": 95, "classification": "Malicious", "desc": "Known Mirai Botnet command and control server."},
            "203.0.113.195": {"reputation": 85, "classification": "Malicious", "desc": "Identified brute force host targeting SSH ports."},
            "192.0.2.89": {"reputation": 55, "classification": "Suspicious", "desc": "Port scanning activities detected on cloud servers."},
            "45.227.254.3": {"reputation": 98, "classification": "Malicious", "desc": "Associated with Cobalt Strike beacon activities."},
            "185.156.177.5": {"reputation": 92, "classification": "Malicious", "desc": "Malware distribution site IP address."},
            "103.86.99.99": {"reputation": 40, "classification": "Suspicious", "desc": "Tor exit node with high volume of encrypted payloads."}
        }
        self.sync_with_db()

    def sync_with_db(self):
        """Attempts to load blacklisted IPs from Supabase if connection is available."""
        if not self.supabase:
            logger.info("Using local pre-cached Threat Intelligence blacklist.")
            return
            
        try:
            # Query from supabase
            res = self.supabase.table("blacklisted_ips").select("*").execute()
            if res.data:
                db_blacklist = {}
                for row in res.data:
                    db_blacklist[row["ip_address"]] = {
                        "reputation": row["reputation_score"],
                        "classification": row["classification"],
                        "desc": row["description"]
                    }
                self.local_blacklist = db_blacklist
                logger.info(f"Synchronized {len(self.local_blacklist)} Threat Intelligence IPs from Supabase.")
        except Exception as e:
            logger.warning(f"Could not load blacklisted IPs from Supabase: {e}. Using local fallback cache.")

    def lookup_ip(self, ip_address: str) -> dict:
        """
        Looks up an IP address and returns its threat profile.
        """
        if ip_address in self.local_blacklist:
            return self.local_blacklist[ip_address]
            
        # Check if internal IP
        if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("127."):
            return {
                "reputation": 0,
                "classification": "Trusted",
                "desc": "Internal private subnet IP address."
            }
            
        # Normal external IP (default safe)
        return {
            "reputation": 5,
            "classification": "Trusted",
            "desc": "External public IP address, no known malicious history."
        }

    def add_to_blacklist(self, ip: str, score: int, classification: str, desc: str):
        """Adds a newly discovered malicious IP to the blacklist."""
        self.local_blacklist[ip] = {
            "reputation": score,
            "classification": classification,
            "desc": desc
        }
        
        # Write to Supabase if active
        if self.supabase:
            try:
                self.supabase.table("blacklisted_ips").upsert({
                    "ip_address": ip,
                    "reputation_score": score,
                    "classification": classification,
                    "description": desc
                }, on_conflict="ip_address").execute()
                logger.info(f"Pushed {ip} to blacklisted_ips table in Supabase.")
            except Exception as e:
                logger.error(f"Failed to push blacklisted IP to Supabase: {e}")
                
if __name__ == "__main__":
    engine = ThreatIntelEngine()
    print("Lookup 198.51.100.42:", engine.lookup_ip("198.51.100.42"))
    print("Lookup 192.168.1.100:", engine.lookup_ip("192.168.1.100"))
    print("Lookup 8.8.8.8:", engine.lookup_ip("8.8.8.8"))
