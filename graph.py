import pickle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import re, math
from collections import Counter
from urllib.parse import urlparse
from sklearn.metrics import roc_curve, auc

matplotlib.rcParams['font.family'] = 'serif'
matplotlib.rcParams['font.size'] = 10

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
        features.append(max_consecutive_consonants(parsed.netloc))
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

# ── Load test set only ───────────────────────────────────────────
print("Loading test set...")
test_df = pd.read_csv('test_dataset.csv')
test_df['label'] = test_df.apply(clean_labels, axis=1)

print(f"Test set: {len(test_df):,} URLs")

print("Extracting features...")
X_test = np.array(test_df['url'].apply(extract_features).tolist())
y_test = test_df['label'].values

# ── Load model ───────────────────────────────────────────────────
print("Loading model...")
with open('phishing_model_v3.pkl', 'rb') as f:
    model = pickle.load(f)

# ── Predict ──────────────────────────────────────────────────────
print("Running inference...")
y_proba_raw = model.predict_proba(X_test)[:, 1]

susp_tld  = X_test[:, 10] == 1
brand_mis = X_test[:, 15] == 1
y_proba   = np.where(
    susp_tld | brand_mis,
    np.maximum(y_proba_raw, 0.50),
    y_proba_raw
)

# ── ROC ──────────────────────────────────────────────────────────
print("Computing ROC curve...")
fpr, tpr, thresholds = roc_curve(y_test, y_proba)
roc_auc = auc(fpr, tpr)

# Operating point at T_safe = 0.05
T_SAFE = 0.05
idx    = np.argmin(np.abs(thresholds - T_SAFE))
op_fpr = fpr[idx]
op_tpr = tpr[idx]

print(f"\nAUC-ROC     : {roc_auc:.4f}")
print(f"T_safe=0.05 : TPR={op_tpr:.4f}  FPR={op_fpr:.4f}")

# ── Plot ─────────────────────────────────────────────────────────
# ── Plot ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(3.5, 3.0))

ax.plot(fpr, tpr, color='#1a1a2e', lw=1.8,
        label=f'Tier-1 Classifier (AUC = {roc_auc:.4f})')
ax.plot([0, 1], [0, 1], color='grey', lw=0.8,
        linestyle='--', label='Random Classifier')
ax.scatter(op_fpr, op_tpr, color='#e94560', s=40, zorder=5, # Reduced scatter size slightly to match
           label=f'$T_{{\\mathrm{{safe}}}}=0.05$ '
                 f'(TPR={op_tpr:.2f}, FPR={op_fpr:.2f})')

ax.set_xlim([0.0, 1.0])
ax.set_ylim([0.0, 1.02])

# Reduced axis labeling sizes to 7.5
ax.set_xlabel('False Positive Rate', fontsize=7.5)
ax.set_ylabel('True Positive Rate', fontsize=7.5)
ax.set_title('ROC Curve --- Tier-1 Calibrated XGBoost', fontsize=8)

# Reduced tick label sizes (0.0, 0.2, etc.) to 7
ax.tick_params(axis='both', which='major', labelsize=7)

# Reduced index box (legend) font size to 6 and tightened internal padding
ax.legend(loc='lower right', fontsize=6, labelspacing=0.3, handletextpad=0.4, borderaxespad=0.4)
ax.grid(True, alpha=0.3, linewidth=0.5)

plt.tight_layout()
plt.savefig('roc_curve.pdf', dpi=300, bbox_inches='tight')
plt.savefig('roc_curve.png', dpi=300, bbox_inches='tight')
print("\nSaved roc_curve.pdf and roc_curve.png")
