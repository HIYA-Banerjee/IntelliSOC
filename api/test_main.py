import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add root folder to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "components" in data

def test_login():
    response = client.post(
        "/api/auth/login",
        json={"email": "analyst@intellisoc.local", "password": "password123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["role"] == "Security Analyst"

def test_get_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "packets_per_second" in data
    assert "threats_detected" in data
    assert "high_risk_ips" in data

def test_get_alerts():
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_predictions():
    response = client.get("/api/predictions")
    assert response.status_code == 200
    data = response.json()
    assert "attack_probability" in data
    assert "forecast_1m" in data

def test_copilot_chat():
    response = client.post(
        "/api/copilot/chat",
        json={"message": "How do I mitigate a DDoS attack?"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "DDoS" in data["response"] or "iptables" in data["response"] or "Copilot" in data["response"]

def test_threat_knowledge_graph():
    response = client.get("/api/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert len(data["nodes"]) > 0

def test_report_generation_unauthorized():
    # Calling report generation without Auth headers should return 403 Forbidden/401 Unauthorized
    response = client.post(
        "/api/reports/generate",
        json={"format": "pdf", "limit": 10}
    )
    assert response.status_code == 403 or response.status_code == 401

def test_report_generation_authorized():
    # Inject mock token
    headers = {"Authorization": "Bearer mock-token-analyst"}
    response = client.post(
        "/api/reports/generate",
        json={"format": "pdf", "limit": 10},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert "report_id" in data
    assert data["file_type"] == "pdf"
    
    # Try downloading the report generated
    report_id = data["report_id"]
    dl_response = client.get(f"/api/reports/download/{report_id}")
    assert dl_response.status_code == 200 or dl_response.status_code == 404
