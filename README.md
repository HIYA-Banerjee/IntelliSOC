# 🛡️ IntelliSOC: AI-Powered Security Operations Center Platform

IntelliSOC is a production-grade, end-to-end cyber security intelligence platform. It processes raw network traffic packets in real-time, extracts logical connection flows, performs multi-stage Machine Learning (ML) threat analysis, dispatches automated alerts, and offers an interactive Security Analyst Dashboard alongside an AI Security Copilot powered by Google Gemini.

---

## 🏗️ Architecture & Component Flow

The platform relies on a streaming event architecture utilizing **Apache Kafka** (with an in-memory queue fallback for lightweight local deployment).

```
[Packet Capture Agent] (scapy / high-fidelity simulator)
       │
       ▼ (topic: "traffic-stream")
[Flow Feature Extractor] (groups packets into flows, calculates connection rates)
       │
       ▼ (topic: "flow-stream")
[Threat Detection Service] (Machine Learning & Explainable AI Pipeline)
       ├─► Anomaly Detector (Isolation Forest - Unsupervised)
       ├─► Binary Intrusion Detection (XGBoost/LightGBM/CatBoost Ensemble)
       ├─► Multi-class Threat Classifier (XGBoost Multi-class)
       ├─► Severity Regressor (Random Forest Regressor)
       ├─► Explainable AI (SHAP attributions)
       ├─► Forecasting Engine (PyTorch LSTM time-series forecaster)
       │
       ▼ (topics: "prediction-stream", "predictions")
[Alert & Storage Engine] (saves to Supabase, generates incident reports)
       ├─► Real-time DB Writes (Supabase client/mock)
       ├─► PDF/Word Report Generator (ReportLab & python-docx)
       ├─► Notification Dispatches (SMTP Email & Telegram Bot API)
       │
       ▼ (topic: "alert-stream")
[Analyst Dashboard UI] (Streamlit frontend) & [AI Security Copilot] (Gemini API)
```

---

## 📂 Project Structure

```text
├── alert_engine/           # Automated notification dispatch (Email, Telegram)
├── api/                    # FastAPI backend endpoints, JWT auth, and mock/live Supabase client
├── dashboard/              # Streamlit analyst UI & visualization console
├── docker/                 # Nginx proxy and Docker multi-container configurations
├── feature_extraction/     # Stateful packet-to-flow feature assembler
├── llm_security_copilot/   # LLM security copilot module (Google Gemini API integration)
├── ml_training/            # Synthetic data generation and ML pipelines (Isolation Forest, XGBoost, PyTorch)
├── packet_capture/         # Live network sniffing (Scapy) and high-fidelity attack simulator
├── report_generator/       # Automated PDF/Word incident reporting engine
├── supabase_backend/       # Database SQL schema, indices, and realtime publication setup
├── threat_detection/       # Core ML analytical detection pipeline
├── threat_forecasting/     # PyTorch LSTM deep learning threat forecaster
├── threat_intelligence/    # IP threat reputation and blacklisting module
├── .env.example            # Environment configurations template
├── vercel.json             # Vercel serverless build and routing configurations
└── render.yaml             # Render Multi-Service blueprint file
```

---

## ⚙️ Setup & Configuration

1. Clone the repository and configure the environment:
   ```bash
   cp .env.example .env
   ```

2. Open `.env` and fill out your variables:
   * **Supabase Configuration**: Provide your remote `SUPABASE_URL` and `SUPABASE_KEY` (otherwise the application falls back to a thread-safe local in-memory simulation).
   * **AI Copilot**: Add your `GEMINI_API_KEY` to enable Gemini AI copilot interactions.
   * **Alerts**: Configure SMTP details for email alerts or a Telegram Bot token/Chat ID to receive active attack alerts.
   * **SIMULATION_MODE**: Set to `True` (default) to run the high-fidelity mock stream generator instead of opening raw network socket sniffers (which require root/administrative execution).

---

## 🏃 Run the Platform Locally

You can run the full multi-service architecture using Docker or execute services individually.

### Option A: Run via Docker Compose

Build and spin up the complete microservice stack:
```bash
docker-compose -f docker/docker-compose.yml up --build
```
This runs the FastAPI API backend, the Streamlit analyst dashboard, the Nginx reverse-proxy, and streaming simulation containers in concert.

### Option B: Run Services Individually (Development Mode)

If you are developing or editing components, run them in separate terminal windows:

1. **Start the FastAPI Backend**:
   ```bash
   # Install dependencies
   pip install -r api/requirements.txt
   # Run local server
   python api/main.py
   ```
   *The backend will be available at `http://localhost:8000`.*

2. **Start the Streamlit Dashboard**:
   ```bash
   pip install -r dashboard/requirements.txt
   streamlit run dashboard/app.py --server.port 8501
   ```
   *Open your browser to `http://localhost:8501` to view the UI.*

3. **Start the Background SOC Simulation Services**:
   Ensure you run these in order to populate the data streams:
   ```bash
   # 1. Start packet capture agent
   python packet_capture/capture.py
   
   # 2. Start flow feature extraction
   python feature_extraction/extractor.py
   
   # 3. Start threat detection analytics
   python threat_detection/detector.py
   
   # 4. Start alert engine dispatcher
   python alert_engine/alerts.py
   ```

---

## 🤖 Machine Learning Model Training

The project comes with pre-trained models in `ml_training/models/`. If you want to modify features, simulate custom traffic, or retrain the algorithms:

1. **Generate Training Datasets**:
   ```bash
   python ml_training/generate_data.py
   ```
   Creates `synthetic_traffic.csv` (for classification/severity) and `synthetic_time_series.csv` (for forecasting).

2. **Train Unsupervised Anomaly Detector**:
   ```bash
   python ml_training/train_anomaly.py
   ```
   Establishes standard baseline profiling using an **Isolation Forest**.

3. **Train Intrusion Detection (IDS) Ensemble**:
   ```bash
   python ml_training/train_ids.py
   ```
   Trains an ensemble voting classifier (XGBoost, LightGBM, CatBoost) to detect malicious vs. benign traffic.

4. **Train Multi-Class Threat Classifier**:
   ```bash
   python ml_training/train_classifier.py
   ```
   Trains a multi-class **XGBoost Classifier** to map threats to specific categories (e.g., DDoS, SQL Injection, Brute Force).

5. **Train Threat Severity Regressor**:
   ```bash
   python ml_training/train_severity.py
   ```
   Trains a **Random Forest Regressor** to calculate dynamic risk scores from 0-100.

6. **Train Threat Forecaster**:
   ```bash
   python ml_training/train_forecaster.py
   ```
   Trains a **PyTorch LSTM model** to predict attack probabilities at 1, 5, and 15-minute intervals.

---

## ☁️ Production Deployment

### Vercel (FastAPI Backend API)
Vercel is optimized for hosting serverless Python endpoints.
1. Connect your repository to **Vercel**.
2. Vercel automatically detects the root `vercel.json` routing configuration.
3. Configure your Environment Variables (`SUPABASE_URL`, `SUPABASE_KEY`, `GEMINI_API_KEY`, etc.) in the Vercel dashboard.
4. Deploy. The backend will compile using the lightweight `api/requirements.txt` to stay within serverless bundle size limits.

### Render (Streamlit Dashboard & Full Stack)
You can deploy the Streamlit Dashboard on Render or deploy the entire API + Dashboard stack.
* **Streamlit Web Service on Render**:
  * Build Command: `pip install -r dashboard/requirements.txt`
  * Start Command: `streamlit run dashboard/app.py --server.port $PORT --server.address 0.0.0.0`
  * Environment Variables: `BACKEND_API_URL` (set to your Vercel API url).
* **Blueprint Deployment**: Connect your repo to Render's **Blueprints** to automatically deploy the multi-service `render.yaml` layout.
