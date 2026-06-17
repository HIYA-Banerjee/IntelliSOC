import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error, r2_score

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainSeverity")

def calculate_synthetic_risk_score(row):
    # Base risk score by attack category
    base_risk = {
        "Normal": 2.0,
        "Reconnaissance": 25.0,
        "Phishing": 40.0,
        "Port Scan": 55.0,
        "SQL Injection": 65.0,
        "Brute Force": 70.0,
        "Malware": 80.0,
        "Botnet": 85.0,
        "DDoS": 92.0
    }
    
    cat = row["attack_category"]
    score = base_risk.get(cat, 5.0)
    
    # Modify based on features
    # Reputation modifier: high reputation score means high maliciousness
    rep_mod = (row["reputation_score"] / 100.0) * 15.0
    
    # Frequency modifier
    freq = row["connection_frequency"]
    freq_mod = min(10.0, np.log1p(freq) * 1.5)
    
    # Volume modifier (packets * size)
    vol = row["packet_count"] * row["packet_size"]
    vol_mod = min(10.0, np.log1p(vol) * 0.8)
    
    # Connection density modifier
    density = row["connection_density"]
    density_mod = min(8.0, density * 0.5)
    
    final_score = score + rep_mod + freq_mod + vol_mod + density_mod
    
    # Clip to 0-100
    final_score = np.clip(final_score, 0.0, 100.0)
    
    # Add minor noise
    final_score += np.random.normal(0, 1.5)
    return np.clip(final_score, 0.0, 100.0)

def get_severity_category(score):
    if score < 25.0:
        return "Low"
    elif score < 50.0:
        return "Medium"
    elif score < 75.0:
        return "High"
    else:
        return "Critical"

def train_severity_model():
    data_path = "ml_training/data/synthetic_traffic.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please run generate_data.py first.")
        
    df = pd.read_csv(data_path)
    
    # Compute Target Risk Score
    logger.info("Computing engineered target risk scores for severity training...")
    df["risk_score"] = df.apply(calculate_synthetic_risk_score, axis=1)
    
    # Target and features
    y = df["risk_score"]
    
    # We include attack_category as a feature here because severity depends heavily on classification output!
    X = df.drop(columns=["label", "risk_score", "source_ip", "destination_ip"])
    
    # Feature columns
    cat_cols = ["protocol", "tcp_flags", "attack_category"]
    num_cols = [
        "source_port", "destination_port", "packet_size", "packet_count", 
        "flow_duration", "connection_frequency", "connection_density", "reputation_score"
    ]
    
    # Preprocessor
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), num_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
        ]
    )
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Fit preprocessor
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)
    
    # Train Random Forest Regressor
    logger.info("Training Random Forest Regressor for threat severity score...")
    model = RandomForestRegressor(n_estimators=100, max_depth=12, random_state=42)
    model.fit(X_train_processed, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_processed)
    mae = mean_absolute_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)
    
    print("\n=========================================")
    print("SEVERITY REGRESSOR EVALUATION METRICS")
    print("=========================================")
    print(f"Mean Absolute Error: {mae:.4f}")
    print(f"R-squared Score:     {r2:.4f}")
    print("=========================================\n")
    
    # Save Pipeline
    os.makedirs("ml_training/models", exist_ok=True)
    
    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('regressor', model)
    ])
    
    model_path = "ml_training/models/threat_severity_pipeline.joblib"
    joblib.dump(pipeline, model_path)
    logger.info(f"Threat Severity Pipeline successfully saved to {model_path}")

if __name__ == "__main__":
    train_severity_model()
