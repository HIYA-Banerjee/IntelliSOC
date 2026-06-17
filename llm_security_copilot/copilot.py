import os
import sys
import logging
from dotenv import load_dotenv

# Path setup
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SecurityCopilot")

GEMINI_AVAILABLE = False
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    logger.warning("google-generativeai package not found. AI Copilot will run in rule-based fallback mode.")

class SecurityCopilot:
    def __init__(self, supabase_client=None):
        self.supabase = supabase_client
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.use_gemini = GEMINI_AVAILABLE and len(self.api_key.strip()) > 0
        
        if self.use_gemini:
            try:
                genai.configure(api_key=self.api_key)
                # Using gemini-1.5-flash for fast, efficient cybersecurity queries
                self.model = genai.GenerativeModel('gemini-1.5-flash')
                logger.info("Gemini AI Copilot initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to configure Gemini API: {e}. Falling back to rule-based engine.")
                self.use_gemini = False
        else:
            logger.info("Initializing rule-based Security Copilot fallback engine.")

    def query(self, question: str, context: dict = None) -> str:
        """
        Queries the copilot.
        - question: the user's natural language query.
        - context: optional system context (recent alerts, stats) to inform the response.
        """
        if not context:
            context = self._fetch_recent_threat_context()
            
        if self.use_gemini:
            return self._query_gemini(question, context)
        else:
            return self._query_rule_based(question, context)

    def _fetch_recent_threat_context(self) -> dict:
        """Helper to collect database statistics for the prompt context."""
        context = {
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_risk_ips": [],
            "recent_incidents": []
        }
        
        if not self.supabase:
            # InMemory mock context
            context["total_alerts"] = 2
            context["critical_alerts"] = 1
            context["high_risk_ips"] = ["198.51.100.42"]
            context["recent_incidents"] = [
                {"timestamp": "2026-06-14 13:00:00", "source_ip": "198.51.100.42", "type": "DDoS", "severity": "Critical"},
                {"timestamp": "2026-06-14 13:05:00", "source_ip": "203.0.113.195", "type": "Brute Force", "severity": "High"}
            ]
            return context
            
        try:
            # Total counts
            res_total = self.supabase.table("alerts").select("id", count="exact").execute()
            if res_total.count is not None:
                context["total_alerts"] = res_total.count
                
            # Critical counts
            res_crit = self.supabase.table("alerts").select("id", count="exact").eq("risk_level", "Critical").execute()
            if res_crit.count is not None:
                context["critical_alerts"] = res_crit.count
                
            # Fetch recent threat logs
            res_logs = self.supabase.table("threat_logs").select("timestamp, source_ip, threat_type, severity_level").order("timestamp", desc=True).limit(5).execute()
            if res_logs.data:
                context["recent_incidents"] = res_logs.data
                high_risk = list(set(r["source_ip"] for r in res_logs.data if r["severity_level"] in ["Critical", "High"]))
                context["high_risk_ips"] = high_risk
        except Exception as e:
            logger.debug(f"Failed to load context database records: {e}")
            
        return context

    def _query_gemini(self, question: str, context: dict) -> str:
        prompt = f"""
        You are Antigravity SOC Copilot, a senior cybersecurity incident responder and threat analyst. 
        You are assisting a security analyst in a Security Operations Center (SOC).
        
        Recent Database Threat Context:
        - Total security alerts active: {context['total_alerts']}
        - Critical level alerts: {context['critical_alerts']}
        - High-risk attacker IPs in play: {', '.join(context['high_risk_ips']) if context['high_risk_ips'] else 'None'}
        - Recent threats logged: {context['recent_incidents']}
        
        Analyst Question: "{question}"
        
        Provide a concise, professional, and highly actionable response. 
        Explain technical aspects clearly and provide terminal firewall block commands (e.g., iptables, UFW, or Cisco CLI) or remediation recommendations where applicable. Format outputs in Markdown.
        """
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}. Falling back to rule engine.")
            return self._query_rule_based(question, context)

    def _query_rule_based(self, question: str, context: dict) -> str:
        q = question.lower()
        
        # 1. Summarize requests
        if any(w in q for w in ["summarize", "summary", "today", "report", "status"]):
            summary = (
                f"### SOC Daily Incident Summary\n\n"
                f"Currently, the platform is tracking **{context['total_alerts']}** security alerts in the database, "
                f"with **{context['critical_alerts']}** flagged as **Critical** threat level.\n\n"
                f"**Top High-Risk Attacker IPs:**\n"
            )
            for ip in context["high_risk_ips"]:
                summary += f"- `{ip}` (Categorized in Threat Intelligence as Malicious)\n"
            if not context["high_risk_ips"]:
                summary += "- No high-risk attacker IPs logged in this window.\n"
                
            summary += "\n**Recent Incidents Timeline:**\n"
            for inc in context["recent_incidents"]:
                time_str = inc.get("timestamp", "")[:19]
                summary += f"- `[{time_str}]` **{inc.get('threat_type', inc.get('type'))}** from `{inc.get('source_ip')}` -> Severity: `{inc.get('severity_level', inc.get('severity'))}`\n"
                
            summary += "\n**Recommended Action:** Apply firewall filters to block the high-risk IPs immediately."
            return summary
            
        # 2. DDoS mitigation
        if "ddos" in q or "dos" in q or "syn flood" in q:
            return (
                "### Incident Playbook: Mitigating DDoS Attacks\n\n"
                "A Distributed Denial of Service (DDoS) SYN flood exhausts system sockets by sending rapid SYN packets without ACK responses.\n\n"
                "**Mitigation Steps:**\n"
                "1. **IP Blocking:** Drop traffic from the attacking host instantly:\n"
                "   ```bash\n"
                "   # Block attacker IP via iptables\n"
                "   sudo iptables -A INPUT -s <attacker_ip> -j DROP\n"
                "   ```\n"
                "2. **Enable TCP SYN Cookies:** Helps defend against socket exhaustion:\n"
                "   ```bash\n"
                "   sudo sysctl -w net.ipv4.tcp_syncookies=1\n"
                "   ```\n"
                "3. **Rate Limiting:** Limit connections per minute per IP:\n"
                "   ```bash\n"
                "   sudo iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT\n"
                "   ```\n"
                "4. **Upstream Mitigation:** Configure a CDN (like Cloudflare) or external scrubbers to filter traffic before it hits your server."
            )
            
        # 3. Brute force mitigation
        if "brute force" in q or "ssh" in q or "login" in q or "password" in q:
            return (
                "### Incident Playbook: Mitigating SSH / RDP Brute Force Attacks\n\n"
                "Brute force attacks attempt rapid passwords to gain unauthorized terminal login access.\n\n"
                "**Mitigation Steps:**\n"
                "1. **Fail2Ban Installation:** Automatically monitor logs and ban brute-forcers:\n"
                "   ```bash\n"
                "   sudo apt install fail2ban -y\n"
                "   # Standard configuration jail.local blocks IP after 5 failures\n"
                "   ```\n"
                "2. **Block Attacker IP:**\n"
                "   ```bash\n"
                "   sudo ufw deny from <attacker_ip> to any port 22\n"
                "   ```\n"
                "3. **Disable Password Auth:** Rely strictly on SSH keys by editing `/etc/ssh/sshd_config`:\n"
                "   ```text\n"
                "   PasswordAuthentication no\n"
                "   PubkeyAuthentication yes\n"
                "   ```\n"
                "   Then restart service: `sudo systemctl restart ssh`"
            )
            
        # 4. SQL Injection mitigation
        if "sql" in q or "sqli" in q or "injection" in q:
            return (
                "### Incident Playbook: Mitigating SQL Injection Vulnerabilities\n\n"
                "SQL Injection (SQLi) attacks occur when unsanitized inputs are executed as raw SQL commands against backend databases.\n\n"
                "**Mitigation Steps:**\n"
                "1. **Input Parametrization:** Never concatenate user input into queries. Use prepared statement bounds:\n"
                "   ```python\n"
                "   # SECURE: Using database query bindings\n"
                "   cursor.execute(\"SELECT * FROM users WHERE username = %s\", (user_input,))\n"
                "   ```\n"
                "2. **Web Application Firewall (WAF):** Set up Nginx ModSecurity or cloud rules to inspect payloads.\n"
                "3. **Database Privileges:** Restrict the web application's DB user account to have minimal permissions (e.g. read/write to specific tables only, disabling `DROP/ALTER` access)."
            )
            
        # 5. Port Scan mitigation
        if "port scan" in q or "scan" in q or "nmap" in q:
            return (
                "### Incident Playbook: Mitigating Network Port Scans\n\n"
                "Reconnaissance scans target host ports to identify operating systems and open services for exploits.\n\n"
                "**Mitigation Steps:**\n"
                "1. **Block Scanning Node:**\n"
                "   ```bash\n"
                "   sudo iptables -A INPUT -s <scanning_ip> -j DROP\n"
                "   ```\n"
                "2. **Implement Port Knocking:** Hides ports until a specific sequence of packets is sent.\n"
                "3. **Configure Stealth Mode:** Set firewall defaults to drop packets instead of rejecting with RST packets, preventing scanner map creation."
            )
            
        # 6. Dangerous IPs query
        if "dangerous" in q or "worst" in q or "attacker" in q or "ip" in q:
            ips = context["high_risk_ips"]
            if not ips:
                return "No high-risk malicious IPs have been logged in the threat database in this current window."
            res = "The following IP addresses represent active attackers or blacklisted threats in our logs:\n\n"
            for ip in ips:
                res += f"- **IP:** `{ip}` | Mapped category: **Malicious C2 / Probe Host**\n"
            res += "\nAction: Run `sudo iptables -A INPUT -s <IP> -j DROP` to shield the host."
            return res

        # Default Response
        return (
            "### Antigravity SOC Copilot Assistant\n\n"
            "I can assist you with explaining predictions, summarising daily incidents, or drafting security playbooks.\n\n"
            "**Example prompts you can try:**\n"
            "- *Summarize today's threats.*\n"
            "- *How can I mitigate this DDoS attack?*\n"
            "- *What are the most dangerous IPs in our logs?*\n"
            "- *Explain how to secure SSH from brute force attacks.*"
        )
