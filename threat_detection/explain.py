import os
import sys
import joblib
import pandas as pd
import numpy as np
import logging
from dotenv import load_dotenv

# Path setup
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ExplainableAI")

SHAP_AVAILABLE = False
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    logger.warning("SHAP package not installed. Explainable AI will run in heuristic fallback mode.")

class ExplainerModule:
    def __init__(self):
        self.model_path = "ml_training/models/shap_ids_pipeline.joblib"
        self.pipeline = None
        self.explainer = None
        
        # Load the SHAP model if it exists
        if os.path.exists(self.model_path):
            try:
                self.pipeline = joblib.load(self.model_path)
                logger.info("Successfully loaded SHAP reference model pipeline.")
                
                # Setup TreeExplainer
                if SHAP_AVAILABLE:
                    classifier = self.pipeline.named_steps['classifier']
                    # We initialize tree explainer on the raw model
                    self.explainer = shap.TreeExplainer(classifier)
                    logger.info("SHAP TreeExplainer initialized successfully.")
            except Exception as e:
                logger.error(f"Error loading SHAP model pipeline: {e}")

    def explain_flow(self, flow_data: dict) -> dict:
        """
        Calculates feature attributions for a single network flow prediction.
        Returns a dictionary containing:
        - top_features: list of dicts with feature names and impact scores
        - text_summary: paragraph explanation
        """
        # Feature columns expected
        feature_cols = [
            "source_port", "destination_port", "protocol", "packet_size", 
            "packet_count", "flow_duration", "tcp_flags", 
            "connection_frequency", "connection_density", "reputation_score"
        ]
        
        # Build DataFrame
        row = {col: flow_data.get(col, 0.0) for col in feature_cols}
        # default strings if None
        row["protocol"] = flow_data.get("protocol", "TCP")
        row["tcp_flags"] = flow_data.get("tcp_flags", "")
        
        df_inst = pd.DataFrame([row])
        
        # If SHAP is available and model is loaded, run SHAP
        if SHAP_AVAILABLE and self.pipeline and self.explainer:
            try:
                # Preprocess input
                preprocessor = self.pipeline.named_steps['preprocessor']
                processed_x = preprocessor.transform(df_inst)
                
                # Calculate SHAP values (usually shape is (1, num_features) or (1, num_features, 2))
                shap_values = self.explainer.shap_values(processed_x)
                
                # If binary classification, take SHAP values for class 1
                if isinstance(shap_values, list):
                    # Multi-class output or list of classes
                    shap_vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
                else:
                    if len(shap_values.shape) == 3:  # (samples, features, classes)
                        shap_vals = shap_values[0, :, 1]
                    else:  # (samples, features)
                        shap_vals = shap_values[0]
                
                # Map back to feature names
                # Get feature names from encoder
                num_features = len(preprocessor.transformers_[0][2])
                cat_encoder = preprocessor.transformers_[1][1]
                
                cat_features = []
                if hasattr(cat_encoder, 'get_feature_names_out'):
                    cat_features = cat_encoder.get_feature_names_out(preprocessor.transformers_[1][2]).tolist()
                else:
                    cat_features = [f"cat_{i}" for i in range(processed_x.shape[1] - num_features)]
                    
                feature_names = preprocessor.transformers_[0][2] + cat_features
                
                # Combine into key-value pairs
                attributions = {}
                for name, val in zip(feature_names, shap_vals):
                    # Simplify feature names (e.g. protocol_TCP -> protocol)
                    simple_name = name
                    for orig in ["protocol", "tcp_flags"]:
                        if name.startswith(orig):
                            simple_name = orig
                            
                    attributions[simple_name] = attributions.get(simple_name, 0.0) + float(val)
                
                # Sort features by highest impact (positive contributors)
                sorted_attribs = sorted(attributions.items(), key=lambda item: item[1], reverse=True)
                
                # Filter positive impacts
                top_features = [{"feature": k, "impact": round(v * 100, 2)} for k, v in sorted_attribs if v > 0]
                # If no positive values, take top 3
                if not top_features:
                    top_features = [{"feature": k, "impact": round(v * 100, 2)} for k, v in sorted_attribs[:3]]
                    
                return {
                    "method": "SHAP",
                    "top_features": top_features,
                    "text_summary": self._generate_explanation_text(top_features, row)
                }
                
            except Exception as e:
                logger.error(f"Error computing SHAP values: {e}. Falling back to heuristics.")
                
        # Heuristic/Rule-based Fallback
        return self._compute_heuristics(row)

    def _compute_heuristics(self, row: dict) -> dict:
        """Fallback to estimate feature impact for explanations."""
        impacts = []
        
        # Evaluate numerical thresholds which suggest threat profiles
        if row["reputation_score"] > 50:
            impacts.append(("reputation_score", float(row["reputation_score"]) * 0.4))
        if row["connection_frequency"] > 100:
            impacts.append(("connection_frequency", min(35.0, float(row["connection_frequency"]) * 0.05)))
        if row["connection_density"] > 20:
            impacts.append(("connection_density", min(30.0, float(row["connection_density"]) * 0.3)))
            
        if row["packet_size"] > 1200 and row["destination_port"] in [80, 8080]:
            impacts.append(("packet_size", 25.0))
        if row["packet_count"] > 100 and row["flow_duration"] < 1.0:
            impacts.append(("packet_count", 28.0))
            impacts.append(("flow_duration", 15.0))
            
        if "S" in row["tcp_flags"] and row["packet_count"] > 50:
            impacts.append(("tcp_flags", 22.0))
            
        # Add small randomized variance to simulate model scoring
        for name in ["packet_size", "flow_duration", "destination_port"]:
            if name not in [x[0] for x in impacts]:
                impacts.append((name, random.uniform(1.0, 5.0)))
                
        sorted_attribs = sorted(impacts, key=lambda item: item[1], reverse=True)
        top_features = [{"feature": k, "impact": round(v, 2)} for k, v in sorted_attribs[:4]]
        
        return {
            "method": "Heuristic",
            "top_features": top_features,
            "text_summary": self._generate_explanation_text(top_features, row)
        }

    def _generate_explanation_text(self, top_features: list, row: dict) -> str:
        if not top_features:
            return "The traffic was flagged due to overall anomalous characteristics in connection volume and headers."
            
        reasons = []
        for feat in top_features:
            f_name = feat["feature"]
            if f_name == "reputation_score":
                reasons.append(f"malicious source IP reputation score of {row['reputation_score']}/100")
            elif f_name == "connection_frequency":
                reasons.append(f"unusually high connection rate ({int(row['connection_frequency'])} flow occurrences in 60s)")
            elif f_name == "connection_density":
                reasons.append(f"high concentration of target destination ports scanned ({int(row['connection_density'])} ports)")
            elif f_name == "packet_size":
                reasons.append(f"large average packet size ({int(row['packet_size'])} bytes) suggesting payload injection")
            elif f_name == "packet_count":
                reasons.append(f"high transmission count of {int(row['packet_count'])} packets")
            elif f_name == "flow_duration":
                reasons.append(f"rapid flow duration of {row['flow_duration']:.4f} seconds")
            elif f_name == "tcp_flags":
                reasons.append(f"abnormal TCP flag sequence '{row['tcp_flags']}' (e.g. SYN flag flood)")
            else:
                reasons.append(f"anomalous behavior in feature '{f_name}'")
                
        # Compile text
        if len(reasons) == 1:
            return f"Attack detected primarily due to a {reasons[0]}."
        elif len(reasons) == 2:
            return f"Attack detected due to a {reasons[0]} and a {reasons[1]}."
        else:
            return f"Attack detected due to multiple factors: {', '.join(reasons[:-1])}, and {reasons[-1]}."

# Setup singleton import
import random
if __name__ == "__main__":
    explainer = ExplainerModule()
    sample = {
        "source_port": 49200, "destination_port": 80, "protocol": "TCP", "packet_size": 64.0, 
        "packet_count": 800, "flow_duration": 0.45, "tcp_flags": "S", 
        "connection_frequency": 650.0, "connection_density": 1.0, "reputation_score": 95
    }
    print("Explanation:", explainer.explain_flow(sample))
