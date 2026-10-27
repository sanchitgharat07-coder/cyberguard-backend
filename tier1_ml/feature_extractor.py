# tier1_ml/feature_extractor.py
# ---------------------------------------
# CyberGuard AI – URL Feature Extraction
# (Tier 1: 17-Dimensional Lexical & Semantic Analysis)
# ---------------------------------------

import re
import math
from collections import Counter
from urllib.parse import urlparse

# Import global configuration
from config import Config

def max_consecutive_consonants(s):
    """
    Detects Domain Generation Algorithms (DGA) by counting
    unnaturally long strings of consecutive consonants.
    """
    matches = re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+', s)
    if not matches: return 0
    return max(len(match) for match in matches)

def shannon_entropy(data):
    """
    Calculates the Shannon Entropy of a string.
    High entropy indicates random character generation or heavy obfuscation.
    """
    if not data: 
        return 0
    entropy = 0
    for x in [float(c) / len(data) for c in dict(Counter(data)).values()]:
        entropy += - x * math.log(x, 2)
    return entropy

def generate_data_set(url):
    """
    Transforms a raw URL string into a 17-dimensional numerical vector.
    CRITICAL: The order MUST perfectly match the XGBoost training pipeline.
    Returns a 2D array [[f1, f2, ... f17]] for sklearn/xgboost compatibility.
    """
    features = []
    
    # --- Lexical Core (Features 1-8) ---
    features.append(len(url))                      # 1. Total Length
    features.append(url.count('.'))                # 2. Dot Count
    features.append(url.count('-'))                # 3. Hyphen Count
    features.append(url.count('@'))                # 4. At-Symbol Count
    features.append(url.count('?'))                # 5. Question Mark Count
    features.append(url.count('&'))                # 6. Ampersand Count
    
    # 7. Has IP Address (Bypassing DNS)
    has_ip = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0
    features.append(has_ip)
    
    # 8. Total Digit Count
    features.append(sum(c.isdigit() for c in url))
    
    # --- Structural Depth & TLD (Features 9-11) ---
    parse_target = url if url.startswith(('http://', 'https://')) else 'http://' + url
    try:
        parsed = urlparse(parse_target)
        features.append(parsed.path.count('/'))    # 9. URL Depth
        features.append(parsed.netloc.count('.'))  # 10. Subdomain count
        
        # 11. Suspicious TLD Check using Config
        tld = parsed.netloc.split('.')[-1].lower()
        features.append(1 if tld in Config.SUSPICIOUS_TLDS else 0)
    except Exception:
        features.extend([0, 0, 0])
        parsed = urlparse('http://error.com') # Failsafe
        
    # --- Advanced Heuristics (Features 12-14) ---
    features.append(shannon_entropy(url))          # 12. Shannon Entropy
    
    suspicious_words = [
        'login', 'secure', 'account', 'update', 'banking', 
        'verify', 'webscr', 'password', 'credential', 'support'
    ]
    features.append(sum(1 for word in suspicious_words if word in url.lower())) # 13. Suspicious Words
    
    try:
        features.append(max_consecutive_consonants(parsed.netloc)) # 14. DGA Detection
    except Exception:
        features.append(0)

    # --- NEW: Semantic Features (Features 15-17) ---
    
    # 15. Brand Token in Path using Config
    brand_in_path = 1 if any(b in parsed.path.lower() for b in Config.PROTECTED_BRANDS) else 0
    features.append(brand_in_path)
    
    # 16. Domain-Brand Mismatch using Config
    netloc_lower = parsed.netloc.lower()
    brand_in_netloc = any(b in netloc_lower for b in Config.PROTECTED_BRANDS)
    
    parts = netloc_lower.split('.')
    domain_stem = parts[-2] if len(parts) > 1 else netloc_lower
    domain_is_brand = any(b == domain_stem for b in Config.PROTECTED_BRANDS)
    
    mismatch_flag = 1 if (brand_in_path or brand_in_netloc) and not domain_is_brand else 0
    features.append(mismatch_flag)
    
    # 17. Longest Token Length
    tokens = re.split(r'[\.\/\-\_\?\=\&]', url)
    longest_token = max((len(t) for t in tokens if t), default=0)
    features.append(longest_token)
    
    return [features]

# --- QUICK TEST BLOCK ---
if __name__ == "__main__":
    # Test a URL that should trigger the Domain-Brand mismatch and Suspicious TLD
    test_url = "http://secure-update.paypal.com.random-gibberish-asdfghjkl.xyz/login"
    print(f"Extracting features for: {test_url}")
    vector = generate_data_set(test_url)
    print(f"Feature Vector (Dimension d={len(vector[0])}):")
    print(vector[0])