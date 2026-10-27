import pickle

# Global model variable
_model = None

def load_model(model_path: str = 'phishing_model_v3.pkl'):
    """Loads the model into memory. Call this once at startup."""
    global _model
    if _model is None:
        try:
            with open(model_path, 'rb') as f:
                _model = pickle.load(f)
            print("✅ XGBoost Model loaded successfully.")
        except Exception as e:
            print(f"❌ Failed to load model: {e}")
            raise e
    return _model

def get_model():
    """Retrieves the loaded model instance."""
    global _model
    if _model is None:
        load_model()
    return _model