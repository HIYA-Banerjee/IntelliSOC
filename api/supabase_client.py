import os
import logging
from typing import Dict, List, Any
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SupabaseClientSetup")

# Try to import real supabase client
SUPABASE_INSTALLED = False
try:
    from supabase import create_client, Client
    SUPABASE_INSTALLED = True
except ImportError:
    pass

class MockResponse:
    def __init__(self, data, count=None):
        self.data = data
        self.count = count

class TableQueryMock:
    """
    Mock class matching Supabase Client query builder syntax:
    client.table("name").select("*").eq("col", "val").execute()
    """
    def __init__(self, table_name: str, db_store: dict):
        self.table_name = table_name
        self.db_store = db_store
        self.filters = []
        self.limit_val = None
        self.order_col = None
        self.order_desc = False

    def select(self, columns: str = "*", count: str = None):
        return self

    def insert(self, data: Any):
        if not isinstance(data, list):
            data = [data]
        self._insert_data = data
        return self

    def update(self, data: dict):
        self._update_data = data
        return self

    def upsert(self, data: dict, on_conflict: str = ""):
        # Simple mock upsert
        ip = data.get("ip_address")
        if ip:
            # Check if exists
            idx = -1
            for i, r in enumerate(self.db_store[self.table_name]):
                if r.get("ip_address") == ip:
                    idx = i
                    break
            if idx != -1:
                self.db_store[self.table_name][idx].update(data)
            else:
                data["id"] = str(datetime.now().microsecond)
                self.db_store[self.table_name].append(data)
        return MockResponse([data])

    def eq(self, column: str, value: Any):
        self.filters.append(lambda r: str(r.get(column)) == str(value))
        return self

    def order(self, column: str, desc: bool = False):
        self.order_col = column
        self.order_desc = desc
        return self

    def limit(self, value: int):
        self.limit_val = value
        return self

    def execute(self) -> MockResponse:
        # 1. If this is an insert query, perform insertion immediately and return
        if hasattr(self, "_insert_data"):
            rows_inserted = []
            for row in self._insert_data:
                new_row = row.copy()
                if "id" not in new_row:
                    import uuid
                    new_row["id"] = str(uuid.uuid4())
                if "timestamp" not in new_row and "created_at" not in new_row:
                    new_row["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                self.db_store[self.table_name].append(new_row)
                rows_inserted.append(new_row)
            # Clear insert memory
            del self._insert_data
            return MockResponse(rows_inserted)

        # 2. Otherwise perform read/update query logic
        data = self.db_store.get(self.table_name, [])
        
        # Apply filters
        filtered_data = []
        for row in data:
            match = True
            for filt in self.filters:
                if not filt(row):
                    match = False
                    break
            if match:
                filtered_data.append(row)
                
        # Apply order
        if self.order_col:
            try:
                filtered_data = sorted(
                    filtered_data, 
                    key=lambda x: x.get(self.order_col, ""), 
                    reverse=self.order_desc
                )
            except Exception:
                pass
                
        # Apply limit
        if self.limit_val:
            filtered_data = filtered_data[:self.limit_val]
            
        # If this was an update query, perform update on filtered rows
        if hasattr(self, "_update_data"):
            for row in filtered_data:
                row.update(self._update_data)
                
        return MockResponse(filtered_data, count=len(filtered_data))

class SupabaseInMemoryClient:
    """Thread-safe in-memory Supabase Mock Client."""
    def __init__(self):
        self.db = {
            "users": [
                {"id": "usr-admin-uuid", "email": "admin@intellisoc.local", "role": "Admin"},
                {"id": "usr-analyst-uuid", "email": "analyst@intellisoc.local", "role": "Security Analyst"},
                {"id": "usr-viewer-uuid", "email": "viewer@intellisoc.local", "role": "Viewer"}
            ],
            "traffic_logs": [],
            "threat_logs": [],
            "alerts": [],
            "predictions": [],
            "incident_reports": [],
            "blacklisted_ips": [
                {"ip_address": "198.51.100.42", "reputation_score": 95, "classification": "Malicious", "description": "Known Mirai Botnet command and control server."},
                {"ip_address": "203.0.113.195", "reputation_score": 85, "classification": "Malicious", "description": "Identified brute force host targeting SSH ports."},
                {"ip_address": "192.0.2.89", "reputation_score": 55, "classification": "Suspicious", "description": "Port scanning activities detected on cloud servers."},
                {"ip_address": "45.227.254.3", "reputation_score": 98, "classification": "Malicious", "description": "Associated with Cobalt Strike beacon activities."},
                {"ip_address": "185.156.177.5", "reputation_score": 92, "classification": "Malicious", "description": "Malware distribution site IP address."},
                {"ip_address": "103.86.99.99", "reputation_score": 40, "classification": "Suspicious", "description": "Tor exit node with high volume of encrypted payloads."}
            ]
        }

    def table(self, table_name: str) -> TableQueryMock:
        if table_name not in self.db:
            self.db[table_name] = []
        return TableQueryMock(table_name, self.db)

def get_supabase_client():
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")
    
    # Check if we should use actual Supabase
    if (SUPABASE_INSTALLED and 
            url and 
            key and 
            "your-supabase-project" not in url and 
            "your-supabase-anon" not in key):
        try:
            logger.info(f"Connecting to live remote Supabase: {url}")
            client: Client = create_client(url, key)
            return client
        except Exception as e:
            logger.error(f"Failed to connect to remote Supabase: {e}. Defaulting to InMemory Mock client.")
    else:
        logger.info("Using SupabaseInMemoryClient (Local Simulation Mode).")
        
    return SupabaseInMemoryClient()
