import os
import firebase_admin
from firebase_admin import credentials, firestore

# Global DB instance
_db = None

def init_firebase():
    """
    Initializes the Firebase Admin SDK using credentials from the environment.
    Fails safely if credentials are not found (useful for local ML testing).
    """
    global _db
    
    # Check if already initialized to prevent app crashes on reload
    if firebase_admin._apps:
        _db = firestore.client()
        return _db
        
    # In production, set this environment variable to your firebase-adminsdk.json path
    cred_path = os.environ.get("FIREBASE_CREDS", "firebase-credentials.json")
    
    if not os.path.exists(cred_path):
        print("⚠️ [Database] Firebase credentials not found. Cloud logging disabled.")
        return None
        
    try:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        _db = firestore.client()
        print("✅ [Database] Firebase Firestore initialized successfully.")
        return _db
    except Exception as e:
        print(f"❌ [Database] Failed to initialize Firebase: {e}")
        return None

def get_db():
    """Returns the active Firestore client instance."""
    global _db
    if _db is None:
        return init_firebase()
    return _db