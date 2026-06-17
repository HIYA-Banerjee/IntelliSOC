import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
import xgboost as xgb

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainClassifier")

def train_threat_classifier():
    data_path = "ml_training/data/synthetic_traffic.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please run generate_data.py first.")
        
    df = pd.read_csv(data_path)
    
    # Target and features
    y_str = df["attack_category"]
    X = df.drop(columns=["label", "attack_category", "source_ip", "destination_ip"])
    
    # Label encode targets
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_str)
    
    # Feature columns
    cat_cols = ["protocol", "tcp_flags"]
    num_cols = [
        "source_port", "destination_port", "packet_size", "packet_count", 
        "flow_duration", "connection_frequency", "connection_density", "reputation_score"
    ]
    
    # Handle missing values
    X[cat_cols] = X[cat_cols].fillna("")
    X[num_cols] = X[num_cols].fillna(0)
    
    # Preprocessor
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), num_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), cat_cols)
        ]
    )
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Fit preprocessor
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)
    
    # Train multi-class XGBoost
    logger.info("Training Multi-Class XGBoost Classifier...")
    model = xgb.XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.1,
        objective='multi:softprob',
        num_class=len(label_encoder.classes_),
        random_state=42,
        eval_metric='mlogloss'
    )
    
    model.fit(X_train_processed, y_train)
    
    # Predictions
    y_pred = model.predict(X_test_processed)
    
    acc = accuracy_score(y_test, y_pred)
    
    print("\n=========================================")
    print("THREAT CLASSIFIER EVALUATION REPORT")
    print("=========================================")
    print(f"Overall Accuracy: {acc:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    print("=========================================\n")
    
    # Save Pipeline
    os.makedirs("ml_training/models", exist_ok=True)
    
    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', model)
    ])
    
    # Wrap label encoder mapping along with pipeline
    model_data = {
        "pipeline": pipeline,
        "classes": label_encoder.classes_.tolist()
    }
    
    model_path = "ml_training/models/threat_classifier_pipeline.joblib"
    joblib.dump(model_data, model_path)
    logger.info(f"Threat Classifier Pipeline and class labels saved to {model_path}")

if __name__ == "__main__":
    train_threat_classifier()
