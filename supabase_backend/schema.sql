-- Supabase PostgreSQL Database Schema for IntelliSOC Platform

-- Enable UUID extension if not enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users table (linked with Supabase Auth auth.users)
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'Viewer' CHECK (role IN ('Admin', 'Security Analyst', 'Viewer')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Enable RLS on users
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read access to users profiles" 
ON public.users FOR SELECT USING (true);

CREATE POLICY "Allow users to update their own profile"
ON public.users FOR UPDATE USING (auth.uid() = id);

-- 2. Traffic Logs table (Real-time packet captures)
CREATE TABLE IF NOT EXISTS public.traffic_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(10) NOT NULL,
    packet_size INTEGER NOT NULL,
    packet_count INTEGER DEFAULT 1,
    flow_duration FLOAT DEFAULT 0.0,
    tcp_flags VARCHAR(50) DEFAULT '',
    connection_frequency FLOAT DEFAULT 1.0
);

CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON public.traffic_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_ips ON public.traffic_logs (source_ip, destination_ip);

-- 3. Threat Logs table (Classified cyber attacks & explainable metrics)
CREATE TABLE IF NOT EXISTS public.threat_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    traffic_log_id UUID REFERENCES public.traffic_logs(id) ON DELETE SET NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    attack_detected BOOLEAN NOT NULL DEFAULT TRUE,
    confidence_score FLOAT NOT NULL,
    severity_score FLOAT NOT NULL,
    severity_level VARCHAR(20) NOT NULL CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical')),
    anomaly_score FLOAT DEFAULT 0.0,
    shap_explanations JSONB DEFAULT '{}'::jsonb,
    remediation_steps TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON public.threat_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_threats_level ON public.threat_logs (severity_level);

-- 4. Alerts table (Real-time notification engine triggers)
CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    threat_log_id UUID REFERENCES public.threat_logs(id) ON DELETE CASCADE,
    threat_type VARCHAR(100) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    confidence_score FLOAT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'acknowledged', 'resolved')),
    acknowledged_by UUID REFERENCES public.users(id),
    acknowledged_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON public.alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON public.alerts (timestamp DESC);

-- 5. Threat Predictions table (Attack forecasting probabilities)
CREATE TABLE IF NOT EXISTS public.predictions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    forecast_1m FLOAT NOT NULL,
    forecast_5m FLOAT NOT NULL,
    forecast_15m FLOAT NOT NULL,
    attack_probability FLOAT NOT NULL,
    forecast_model VARCHAR(50) DEFAULT 'LSTM'
);

CREATE INDEX IF NOT EXISTS idx_predictions_timestamp ON public.predictions (timestamp DESC);

-- 6. Incident Reports table (PDF & DOCX report logs)
CREATE TABLE IF NOT EXISTS public.incident_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    report_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_type VARCHAR(10) NOT NULL CHECK (file_type IN ('pdf', 'docx')),
    summary TEXT,
    threats_covered INTEGER DEFAULT 0,
    created_by UUID REFERENCES public.users(id)
);

-- 7. Blacklisted IPs table (Threat intelligence IP reputations)
CREATE TABLE IF NOT EXISTS public.blacklisted_ips (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reputation_score INTEGER DEFAULT 0 CHECK (reputation_score BETWEEN 0 AND 100),
    classification VARCHAR(20) NOT NULL DEFAULT 'Trusted' CHECK (classification IN ('Trusted', 'Suspicious', 'Malicious')),
    description TEXT,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON public.blacklisted_ips (ip_address);

-- Insert initial Threat Intel dataset
INSERT INTO public.blacklisted_ips (ip_address, reputation_score, classification, description) VALUES
('198.51.100.42', 95, 'Malicious', 'Known Mirai Botnet command and control server.'),
('203.0.113.195', 85, 'Malicious', 'Identified brute force host targeting SSH ports.'),
('192.0.2.89', 55, 'Suspicious', 'Port scanning activities detected on cloud servers.'),
('45.227.254.3', 98, 'Malicious', 'Associated with Cobalt Strike beacon activities.'),
('185.156.177.5', 92, 'Malicious', 'Malware distribution site IP address.'),
('103.86.99.99', 40, 'Suspicious', 'Tor exit node with high volume of encrypted payloads.')
ON CONFLICT (ip_address) DO NOTHING;

-- Realtime Setup
-- Enable Supabase Realtime for specific tables (enables web socket listening on Streamlit)
alter publication supabase_realtime add table public.alerts;
alter publication supabase_realtime add table public.threat_logs;
alter publication supabase_realtime add table public.traffic_logs;
alter publication supabase_realtime add table public.predictions;
alter publication supabase_realtime add table public.blacklisted_ips;
