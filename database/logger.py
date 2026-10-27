# backend/database/logger.py

import threading
from datetime import datetime, timezone
from .firebase_client import get_db

def _async_log_to_firestore(uid: str, document_data: dict):
    """Background task to push data to the user's specific Firestore path."""
    db = get_db()
    if not db:
        return
        
    try:
        # Path: users -> [user_id] -> scans-> [auto_generated_doc_id]
        db.collection('users').document(uid).collection('scans').add(document_data)
        print(f"📝 [Database] Scan saved to profile of user: {uid}")
    except Exception as e:
        print(f"❌ [Database] Failed to log scan to Firestore: {e}")

def log_scan_result(uid: str, payload: dict):
    """
    Formats the scan result and dispatches it to the background logger.
    """
    log_data = payload.copy()
    log_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    thread = threading.Thread(
        target=_async_log_to_firestore, 
        args=(uid, log_data),
        daemon=True
    )
    thread.start()