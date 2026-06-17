import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.ensemble import VotingClassifier, RandomForestClassifier, GradientBoostingClassifier
import xgboost as xgb

# Set up logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TrainIDS")

def train_binary_ids():
    data_path = "ml_training/data/synthetic_traffic.csv"
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please run generate_data.py first.")
        
    df = pd.read_csv(data_path)
    
    # Target and features
    y = df["label"]
    X = df.drop(columns=["label", "attack_category", "source_ip", "destination_ip"])
    
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
    
    # Models to ensemble
    estimators = []
    
    # 1. XGBoost
    logger.info("Initializing XGBoost classifier...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric='logloss'
    )
    estimators.append(('xgb', xgb_model))
    
    # 2. LightGBM
    try:
        import lightgbm as lgb
        logger.info("Initializing LightGBM classifier...")
        lgb_model = lgb.LGBMClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            verbose=-1
        )
        estimators.append(('lgb', lgb_model))
    except ImportError:
        logger.warning("LightGBM package not installed. Using RandomForestClassifier as ensemble fallback.")
        rf_model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        estimators.append(('rf', rf_model))
        
    # 3. CatBoost
    try:
        from catboost import CatBoostClassifier
        logger.info("Initializing CatBoost classifier...")
        cat_model = CatBoostClassifier(
            iterations=100,
            depth=6,
            learning_rate=0.1,
            random_state=42,
            verbose=0
        )
        estimators.append(('cat', cat_model))
    except ImportError:
        logger.warning("CatBoost package not installed. Using GradientBoostingClassifier as ensemble fallback.")
        gb_model = GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42)
        estimators.append(('gb', gb_model))
        
    # Create Voting Classifier
    logger.info("Creating Voting Classifier Ensemble (Soft Voting)...")
    ensemble = VotingClassifier(
        estimators=estimators,
        voting='soft'
    )
    
    # Fit model
    ensemble.fit(X_train_processed, y_train)
    
    # Predict and evaluate
    y_pred = ensemble.predict(X_test_processed)
    y_pred_proba = ensemble.predict_proba(X_test_processed)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print("\n=========================================")
    print("IDS BINARY ENSEMBLE EVALUATION METRICS")
    print("=========================================")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"ROC-AUC:   {auc:.4f}")
    print("=========================================\n")
    
    # Save Pipeline (preprocessor + model)
    os.makedirs("ml_training/models", exist_ok=True)
    
    pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', ensemble)
    ])
    
    model_path = "ml_training/models/binary_ids_pipeline.joblib"
    joblib.dump(pipeline, model_path)
    logger.info(f"Binary IDS Pipeline successfully saved to {model_path}")
    
    # Save XGBoost standalone for SHAP tree explanations (as SHAP works best directly on single tree models)
    xgb_pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', xgb_model.fit(X_train_processed, y_train))
    ])
    joblib.dump(xgb_pipeline, "ml_training/models/shap_ids_pipeline.joblib")
    logger.info("SHAP reference model pipeline saved to ml_training/models/shap_ids_pipeline.joblib")

if __name__ == "__main__":
    train_binary_ids()
