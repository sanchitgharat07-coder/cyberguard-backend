import os

class Config:
    # --- MODEL THRESHOLDS (Locked from Phase 1) ---
    T_SAFE = 0.05
    T_MALICIOUS = 0.85
    
    # --- ML OVERRIDES ---
    SUSPICIOUS_TLDS = {'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'club', 'work', 'cn', 'su'}
    PROTECTED_BRANDS = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook', 'chase', 'netflix', 'wellsfargo', 'bankofamerica']

    # --- INFRASTRUCTURE ---
    # REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    # FIREBASE_CREDENTIALS = os.environ.get("FIREBASE_CREDS", "path/to/creds.json")
    
    # --- TIMEOUTS ---
    TIER3_FETCH_TIMEOUT = 2.0
    RDAP_TIMEOUT = 0.8