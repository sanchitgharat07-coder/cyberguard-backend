import pandas as pd
import numpy as np
import pickle
import re
import math
from collections import Counter
from urllib.parse import urlparse
from xgboost import XGBClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, roc_auc_score)

# ── Constants ────────────────────────────────────────────────────
PROTECTED_BRANDS = [
    'paypal','microsoft','apple','google','amazon',
    'facebook','chase','netflix','wellsfargo','bankofamerica'
]
SUSPICIOUS_TLDS = {
    'xyz','top','tk','ml','ga','cf','gq','pw',
    'cc','club','work','cn','su'
}

# ── Helpers ──────────────────────────────────────────────────────
def max_consecutive_consonants(s):
    matches = re.findall(
        r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+', s)
    return max((len(m) for m in matches), default=0)

def shannon_entropy(data):
    if not data: return 0
    entropy = 0
    for x in [float(c)/len(data)
               for c in dict(Counter(data)).values()]:
        entropy += -x * math.log(x, 2)
    return entropy

def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('&'))
    features.append(
        1 if re.search(
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url
        ) else 0)
    features.append(sum(c.isdigit() for c in url))

    parse_target = url if url.startswith(
        ('http://','https://')) else 'http://'+url
    try:
        parsed = urlparse(parse_target)
        features.append(parsed.path.count('/'))
        features.append(parsed.netloc.count('.'))
        tld = parsed.netloc.split('.')[-1].lower()
        features.append(1 if tld in SUSPICIOUS_TLDS else 0)
    except:
        features.extend([0, 0, 0])
        parsed = urlparse('http://error.com')

    features.append(shannon_entropy(url))

    suspicious_words = [
        'login','secure','account','update','banking',
        'verify','webscr','password','credential','support'
    ]
    features.append(
        sum(1 for w in suspicious_words if w in url.lower()))

    try:
        features.append(
            max_consecutive_consonants(parsed.netloc))
    except:
        features.append(0)

    brand_in_path = 1 if any(
        b in parsed.path.lower()
        for b in PROTECTED_BRANDS) else 0
    features.append(brand_in_path)

    netloc_lower  = parsed.netloc.lower()
    brand_in_netloc = any(b in netloc_lower for b in PROTECTED_BRANDS)
    parts = netloc_lower.split('.')
    domain_stem   = parts[-2] if len(parts) > 1 else netloc_lower
    domain_is_brand = any(b == domain_stem for b in PROTECTED_BRANDS)
    mismatch = 1 if (brand_in_path or brand_in_netloc) \
                    and not domain_is_brand else 0
    features.append(mismatch)

    tokens = re.split(r'[\.\/\-\_\?\=\&]', url)
    features.append(max((len(t) for t in tokens if t), default=0))
    return features

def clean_labels(row):
    trusted = {
        'google.com','microsoft.com','apple.com','amazon.com',
        'facebook.com','youtube.com','wikipedia.org',
        'twitter.com','linkedin.com','instagram.com'
    }
    try:
        domain = urlparse(row['url']).netloc.replace('www.','')
        if domain in trusted:
            return 0
    except:
        pass
    return row['label']

# ── Load Pre-Split Files ─────────────────────────────────────────
print("Loading pre-split dataset files...")
train_df = pd.read_csv('train_dataset.csv')
test_df  = pd.read_csv('test_dataset.csv')

print("Cleaning labels...")
train_df['label'] = train_df.apply(clean_labels, axis=1)
test_df['label']  = test_df.apply(clean_labels, axis=1)

print(f"Train: {len(train_df):,} URLs | "
      f"Phishing: {train_df['label'].sum():,}")
print(f"Test : {len(test_df):,}  URLs | "
      f"Phishing: {test_df['label'].sum():,}")

# ── Feature Extraction ───────────────────────────────────────────
print("\nExtracting features from training set...")
X_train = np.array(train_df['url'].apply(extract_features).tolist())
y_train = train_df['label'].values

print("Extracting features from test set...")
X_test  = np.array(test_df['url'].apply(extract_features).tolist())
y_test  = test_df['label'].values

# ── Class Weight ─────────────────────────────────────────────────
neg   = (y_train == 0).sum()
pos   = (y_train == 1).sum()
ratio = neg / pos
print(f"\nClass weight ratio (scale_pos_weight): {ratio:.4f}")

# ── Train ────────────────────────────────────────────────────────
print("Training XGBoost with Isotonic Regression calibration...")
xgb_base = XGBClassifier(
    n_estimators=200,
    learning_rate=0.1,
    max_depth=7,
    scale_pos_weight=ratio,
    eval_metric='logloss',
    random_state=42,
    device="cuda",
    tree_method='hist',
)
model = CalibratedClassifierCV(xgb_base, method='isotonic', cv=5)
model.fit(X_train, y_train)

# ── Evaluate on CLEAN TEST SET ───────────────────────────────────
print("\nEvaluating on clean test set (no training contamination)...")
y_proba_raw = model.predict_proba(X_test)[:, 1]

# Deterministic override
susp_tld_flag    = X_test[:, 10] == 1
brand_mis_flag   = X_test[:, 15] == 1
y_proba = np.where(
    susp_tld_flag | brand_mis_flag,
    np.maximum(y_proba_raw, 0.50),
    y_proba_raw
)

# Thresholds
T_SAFE      = 0.05
T_MALICIOUS = 0.85

# Hard-threshold standalone metrics
y_pred = (y_proba >= 0.5).astype(int)
print("\n" + "="*60)
print("TIER-1 STANDALONE METRICS (hard threshold = 0.5)")
print("="*60)
print(f"Accuracy  : {accuracy_score(y_test, y_pred)*100:.2f}%")
print(f"Precision : {precision_score(y_test, y_pred)*100:.2f}%")
print(f"Recall    : {recall_score(y_test, y_pred)*100:.2f}%")
print(f"F1 Score  : {f1_score(y_test, y_pred)*100:.2f}%")
print(f"AUC-ROC   : {roc_auc_score(y_test, y_proba):.4f}")

# Routing zones
total        = len(y_test)
total_phish  = (y_test == 1).sum()
total_legit  = (y_test == 0).sum()

safe_mask    = y_proba < T_SAFE
esc_mask     = (y_proba >= T_SAFE) & (y_proba <= T_MALICIOUS)
high_mask    = y_proba > T_MALICIOUS

safe_legit   = ((y_test==0) & safe_mask).sum()
safe_phish   = ((y_test==1) & safe_mask).sum()
esc_total    = esc_mask.sum()
esc_phish    = ((y_test==1) & esc_mask).sum()
esc_legit    = ((y_test==0) & esc_mask).sum()
high_phish   = ((y_test==1) & high_mask).sum()
high_legit   = ((y_test==0) & high_mask).sum()

print("\n" + "="*60)
print(f"ROUTING BREAKDOWN  (T_safe={T_SAFE}, T_mal={T_MALICIOUS})")
print("="*60)
print(f"Total test  : {total:,}")
print(f"Phishing    : {total_phish:,}")
print(f"Legitimate  : {total_legit:,}")

print(f"\nSAFE zone (p < {T_SAFE})")
print(f"  Legit cleared : {safe_legit:,}"
      f"  ({safe_legit/total_legit*100:.2f}% of legit)")
print(f"  Fatal bypasses: {safe_phish:,}"
      f"  ({safe_phish/total_phish*100:.2f}% of phishing)")

print(f"\nESCALATION zone ({T_SAFE} <= p <= {T_MALICIOUS})")
print(f"  Total         : {esc_total:,}"
      f"  ({esc_total/total*100:.2f}%)")
print(f"  Phishing      : {esc_phish:,}"
      f"  ({esc_phish/total_phish*100:.2f}% of all phishing)")
print(f"  Legit         : {esc_legit:,}"
      f"  ({esc_legit/total_legit*100:.2f}% of all legit)")

print(f"\nHIGH-CONF zone (p > {T_MALICIOUS})")
print(f"  Phishing      : {high_phish:,}"
      f"  ({high_phish/total_phish*100:.2f}% of all phishing)")
print(f"  Legit FP      : {high_legit:,}"
      f"  ({high_legit/total_legit*100:.2f}% of all legit)")

if high_phish + high_legit > 0:
    t1_prec = high_phish/(high_phish+high_legit)*100
    print(f"  Precision     : {t1_prec:.2f}%")

print("\n" + "="*60)
print("PROJECTED CASCADE RECALL")
print("="*60)
for oracle in [0.80, 0.85, 0.90, 0.95]:
    esc_rescued  = int(esc_phish  * oracle)
    high_rescued = int(high_phish * oracle)
    proj = (esc_rescued + high_rescued) / total_phish * 100
    print(f"  Oracle {oracle:.0%} -> "
          f"Projected Recall = {proj:.2f}%")

# ── Save Clean Model ─────────────────────────────────────────────
print("\nSaving clean model to phishing_model_v3.pkl...")
with open('phishing_model_v3.pkl', 'wb') as f:
    pickle.dump(model, f)

print("\nDone. Paste full output back.")