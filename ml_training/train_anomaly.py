import os
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainAnomaly")

def train_anomaly_detector():
    data_path = "ml_training/data/synthetic_traffic.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please run generate_data.py first.")
        
    df = pd.read_csv(data_path)
    
    # Unsupervised: Train ONLY on normal data to establish a baseline
    normal_df = df[df["label"] == 0]
    
    # We drop labels and identity columns
    X_normal = normal_df.drop(columns=["label", "attack_category", "source_ip", "destination_ip"])
    
    # Feature columns
    cat_cols = ["protocol", "tcp_flags"]
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
    
    # Fit preprocessor on normal data
    X_normal_processed = preprocessor.fit_transform(X_normal)
    
    # Train Isolation Forest
    logger.info("Training Unsupervised Isolation Forest Anomaly Detector...")
    # contamination represents expected proportion of anomalies in training data (even though we filtered for normal, we set minor rate)
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
    model.fit(X_normal_processed)
    
    # Test on full dataset (normal + attacks) to see anomaly scores
    X_full = df.drop(columns=["label", "attack_category", "source_ip", "destination_ip"])
    X_full_processed = preprocessor.transform(X_full)
    
    # isolation forest outputs -1 for anomaly, 1 for normal
    preds = model.predict(X_full_processed)
    # decision_function outputs anomaly score (lower is more anomalous)
    scores = model.decision_function(X_full_processed)
    
    # Convert scores to a 0-1 range where 1 is highly anomalous
    # Decision function values are typically between -0.5 and 0.5. 
    # Let's map it so that it's easy to interpret as an Anomaly Score (0 to 100%)
    anomaly_scores = (0.5 - scores) * 100
    anomaly_scores = np.clip(anomaly_scores, 0, 100)
    
    df["anomaly_score"] = anomaly_scores
    
    # Evaluate separation
    mean_normal_anomaly = df[df["label"] == 0]["anomaly_score"].mean()
    mean_attack_anomaly = df[df["label"] == 1]["anomaly_score"].mean()
    
    print("\n=========================================")
    print("ANOMALY DETECTOR EVALUATION")
    print("=========================================")
    print(f"Mean Anomaly Score (Normal): {mean_normal_anomaly:.2f}%")
    print(f"Mean Anomaly Score (Attack): {mean_attack_anomaly:.2f}%")
    print("=========================================\n")
    
    # Save Pipeline
    os.makedirs("ml_training/models", exist_ok=True)
    
    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('anomaly_detector', model)
    ])
    
    model_path = "ml_training/models/anomaly_detector_pipeline.joblib"
    joblib.dump(pipeline, model_path)
    logger.info(f"Anomaly Detector Pipeline successfully saved to {model_path}")

if __name__ == "__main__":
    train_anomaly_detector()
