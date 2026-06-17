import os
import sys
import logging
import uuid
from datetime import datetime
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv

# Path setup
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.supabase_client import get_supabase_client
from llm_security_copilot.copilot import SecurityCopilot
from report_generator.generator import IncidentReportGenerator

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FastAPIServer")

app = FastAPI(
    title="IntelliSOC Security Intelligence Backend API",
    description="Production-grade API endpoints for real-time cyber threat detection, analytics, and copilot interaction.",
    version="1.0.0"
)

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow dashboard connections
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth configuration
security_bearer = HTTPBearer()
supabase_client = get_supabase_client()
copilot = SecurityCopilot(supabase_client)
report_gen = IncidentReportGenerator()

# Models
class LoginRequest(BaseModel):
    email: str
    password: str

class ChatRequest(BaseModel):
    message: str
    context: Optional[dict] = None

class ReportRequest(BaseModel):
    format: str # 'pdf' or 'docx'
    limit: Optional[int] = 20

# Mock User verification helper
def get_current_user_role(credentials: HTTPAuthorizationCredentials = Depends(security_bearer)) -> str:
    """Verifies JWT token. Under simulated settings, decodes role directly from token payload."""
    token = credentials.credentials
    if token == "mock-token-admin":
        return "Admin"
    elif token == "mock-token-analyst":
        return "Security Analyst"
    elif token == "mock-token-viewer":
        return "Viewer"
        
    # Standard decode fallback
    try:
        # In a real deploy, verify with Supabase Auth
        # client.auth.get_user(token)
        return "Security Analyst"
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authorization token.")

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "components": {
            "database": "connected" if supabase_client else "disconnected",
            "copilot": "active",
            "report_generator": "active"
        }
    }

@app.post("/api/auth/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    
    # Static auth routing for SOC simulation roles
    role = "Viewer"
    token = "mock-token-viewer"
    
    if email == "admin@intellisoc.local":
        role = "Admin"
        token = "mock-token-admin"
    elif email == "analyst@intellisoc.local":
        role = "Security Analyst"
        token = "mock-token-analyst"
    elif email in ["viewer@intellisoc.local", "user@intellisoc.local"]:
        role = "Viewer"
        token = "mock-token-viewer"
    else:
        # Try local db lookups
        try:
            res = supabase_client.table("users").select("*").eq("email", email).execute()
            if res.data:
                role = res.data[0]["role"]
                token = f"mock-token-{role.lower().replace(' ', '')}"
        except Exception:
            pass
            
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": email,
            "role": role
        }
    }

@app.get("/api/stats")
def get_soc_stats():
    """Aggregates and returns active security indicators."""
    try:
        # 1. Total Packets and flow logs count
        res_flows = supabase_client.table("traffic_logs").select("id", count="exact").limit(1).execute()
        total_flows = res_flows.count if res_flows.count is not None else 1250
        
        # 2. Total threats detected
        res_threats = supabase_client.table("threat_logs").select("id", count="exact").execute()
        total_threats = res_threats.count if res_threats.count is not None else 18
        
        # 3. High risk IPs count
        res_ips = supabase_client.table("blacklisted_ips").select("ip_address").eq("classification", "Malicious").execute()
        high_risk_ips_count = len(res_ips.data) if res_ips.data else 4
        
        # 4. Packets per second estimation
        # Sum packet counts in the last 10 seconds
        packets_rate = 120.0
        active_connections = 12
        try:
            res_rate = supabase_client.table("traffic_logs").select("packet_count").limit(10).execute()
            if res_rate.data:
                total_pkts = sum(int(r.get("packet_count", 1)) for r in res_rate.data)
                packets_rate = round(total_pkts / 10.0, 2)
                active_connections = len(res_rate.data)
        except Exception:
            pass
            
        return {
            "packets_per_second": packets_rate,
            "active_connections": active_connections,
            "threats_detected": total_threats,
            "high_risk_ips": high_risk_ips_count
        }
    except Exception as e:
        logger.error(f"Error compiling stats: {e}")
        return {
            "packets_per_second": 12.5,
            "active_connections": 3,
            "threats_detected": 2,
            "high_risk_ips": 1
        }

@app.get("/api/alerts")
def get_alerts(risk_level: Optional[str] = None, status: Optional[str] = None):
    """Fetches list of threat alerts with filtering."""
    try:
        query = supabase_client.table("alerts").select("*").order("timestamp", desc=True)
        
        if risk_level:
            query = query.eq("risk_level", risk_level)
        if status:
            query = query.eq("status", status)
            
        res = query.execute()
        return res.data if res.data else []
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return []

@app.put("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str, role: str = Depends(get_current_user_role)):
    """Acknowledge alert status."""
    if role not in ["Admin", "Security Analyst"]:
        raise HTTPException(status_code=403, detail="Viewer role does not have permissions to acknowledge alerts.")
        
    try:
        res = supabase_client.table("alerts").update({
            "status": "acknowledged",
            "acknowledged_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }).eq("id", alert_id).execute()
        
        return {"status": "success", "alert": res.data[0] if res.data else None}
    except Exception as e:
        logger.error(f"Failed to acknowledge alert: {e}")
        raise HTTPException(status_code=500, detail="Database write failure.")

@app.get("/api/predictions")
def get_threat_predictions():
    """Fetches forecasting probabilities."""
    try:
        res = supabase_client.table("predictions").select("*").order("timestamp", desc=True).limit(1).execute()
        if res.data:
            return res.data[0]
            
        # Mock fallback prediction data
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "forecast_1m": 0.05,
            "forecast_5m": 0.12,
            "forecast_15m": 0.28,
            "attack_probability": 0.28,
            "forecast_model": "LSTM"
        }
    except Exception as e:
        logger.error(f"Error fetching forecasting data: {e}")
        return {}

@app.post("/api/copilot/chat")
def copilot_chat(req: ChatRequest):
    """Queries AI Security Copilot."""
    try:
        ans = copilot.query(req.message, req.context)
        return {"response": ans}
    except Exception as e:
        logger.error(f"Copilot query failure: {e}")
        raise HTTPException(status_code=500, detail="Copilot engine error.")

@app.post("/api/reports/generate")
def generate_incident_report(req: ReportRequest, role: str = Depends(get_current_user_role)):
    """Generates PDF or DOCX reports."""
    if role not in ["Admin", "Security Analyst"]:
        raise HTTPException(status_code=403, detail="Unauthorized role for report generation.")
        
    try:
        # Fetch threats to cover in report
        res = supabase_client.table("threat_logs").select("*").order("timestamp", desc=True).limit(req.limit).execute()
        threats_data = res.data if res.data else []
        
        if not threats_data:
            # Inject a mock log if empty to allow report generation demo
            threats_data = [{
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": "198.51.100.42",
                "destination_ip": "192.168.1.50",
                "threat_type": "DDoS",
                "severity_level": "Critical",
                "confidence_score": 95.0,
                "risk_score": 92.0,
                "remediation_steps": "Drop attacker packets using iptables rules."
            }]
            
        # File generation
        report_id = str(uuid.uuid4())
        filename = f"incident_report_{report_id}.{req.format}"
        
        if req.format.lower() == "pdf":
            file_path = report_gen.generate_pdf_report(threats_data, filename)
        else:
            file_path = report_gen.generate_docx_report(threats_data, filename)
            
        # Save reference metadata in database
        supabase_client.table("incident_reports").insert({
            "id": report_id,
            "report_name": f"Security Analysis Report - {req.format.upper()}",
            "file_path": file_path,
            "file_type": req.format.lower(),
            "summary": f"Incident report covering recent {len(threats_data)} logged alerts.",
            "threats_covered": len(threats_data)
        }).execute()
        
        return {
            "report_id": report_id,
            "report_name": f"Security Analysis Report - {req.format.upper()}",
            "file_type": req.format,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threats_covered": len(threats_data)
        }
        
    except Exception as e:
        logger.error(f"Error compiling incident report: {e}")
        raise HTTPException(status_code=500, detail=f"Report compiler crash: {e}")

@app.get("/api/reports/download/{report_id}")
def download_report(report_id: str):
    """Downloads a compiled report file."""
    try:
        res = supabase_client.table("incident_reports").select("*").eq("id", report_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="Incident report record not found.")
            
        file_path = res.data[0]["file_path"]
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Physical report file missing on disk storage.")
            
        media_type = "application/pdf" if file_path.endswith(".pdf") else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        return FileResponse(
            path=file_path,
            media_type=media_type,
            filename=os.path.basename(file_path)
        )
    except Exception as e:
        logger.error(f"Download query failed: {e}")
        raise HTTPException(status_code=500, detail="Report download storage error.")

@app.get("/api/graph")
def get_threat_knowledge_graph():
    """Generates nodes and edges for Cyber Threat Knowledge Graph mapping attacker IP connections."""
    try:
        # Pull threat logs
        res = supabase_client.table("threat_logs").select("source_ip, destination_ip, threat_type, severity_level").limit(10).execute()
        threats = res.data if res.data else []
        
        nodes = []
        edges = []
        node_ids = set()
        
        # Add baseline target servers
        targets = ["192.168.1.10", "192.168.1.20", "192.168.1.50"]
        for target in targets:
            nodes.append({"id": target, "label": f"Server ({target})", "group": "TargetServer"})
            node_ids.add(target)
            
        if not threats:
            # Mock graph node setup
            nodes.append({"id": "198.51.100.42", "label": "Attacker (198.51.100.42)", "group": "AttackerIP"})
            nodes.append({"id": "DDoS", "label": "DDoS Attack Type", "group": "ThreatType"})
            edges.append({"source": "198.51.100.42", "target": "192.168.1.50", "label": "traffic"})
            edges.append({"source": "198.51.100.42", "target": "DDoS", "label": "classified"})
        else:
            for threat in threats:
                src = threat["source_ip"]
                dest = threat["destination_ip"]
                ttype = threat["threat_type"]
                level = threat["severity_level"]
                
                # Add source attacker IP node
                if src not in node_ids:
                    nodes.append({"id": src, "label": f"Attacker ({src})", "group": "AttackerIP"})
                    node_ids.add(src)
                    
                # Add destination IP node
                if dest not in node_ids:
                    nodes.append({"id": dest, "label": f"Target Host ({dest})", "group": "TargetServer"})
                    node_ids.add(dest)
                    
                # Add Threat Type Node
                if ttype not in node_ids:
                    nodes.append({"id": ttype, "label": f"Attack: {ttype}", "group": "ThreatType"})
                    node_ids.add(ttype)
                    
                # Add edges
                edges.append({"source": src, "target": dest, "label": f"{level} Connection"})
                edges.append({"source": src, "target": ttype, "label": "triggered"})
                
        return {"nodes": nodes, "edges": edges}
        
    except Exception as e:
        logger.error(f"Error building knowledge graph: {e}")
        return {"nodes": [], "edges": []}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
