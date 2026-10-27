# tier1_ml/calibrator.py
# ---------------------------------------
# CyberGuard AI – Isotonic Calibration Utility
# (MLOps Maintenance Script - Not used during live inference)
# ---------------------------------------

import pickle
import numpy as np
from sklearn.calibration import CalibratedClassifierCV

def recalibrate_model(raw_model_path: str, X_val: np.ndarray, y_val: np.ndarray, output_path: str = 'phishing_model_v3.pkl'):
    """
    Takes an existing (potentially drifting) model and recalibrates its 
    probability outputs using Isotonic Regression against a fresh validation dataset.
    
    This ensures T_SAFE (0.05) and T_MALICIOUS (0.85) remain mathematically 
    accurate as real-world phishing tactics evolve.
    """
    print(f"🔧 Loading raw model from {raw_model_path}...")
    try:
        with open(raw_model_path, 'rb') as f:
            base_model = pickle.load(f)
    except Exception as e:
        print(f"❌ Failed to load model: {e}")
        return False

    print("📊 Applying Isotonic Regression (Pre-fit mode)...")
    # cv='prefit' tells sklearn NOT to retrain the XGBoost model, 
    # but only to learn the probability mapping from X_val and y_val.
    calibrated_clf = CalibratedClassifierCV(base_model, method='isotonic', cv='prefit')
    
    calibrated_clf.fit(X_val, y_val)
    
    print(f"💾 Saving newly calibrated production model to {output_path}...")
    with open(output_path, 'wb') as f:
        pickle.dump(calibrated_clf, f)
        
    print("✅ Recalibration complete. Model is ready for deployment.")
    return True

if __name__ == "__main__":
    # Example Usage (You would load your fresh CSV data here)
    print("This is an MLOps utility script. Import recalibrate_model() to use.")