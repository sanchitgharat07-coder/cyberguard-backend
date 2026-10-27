import pandas as pd
import numpy as np
import pickle
from sklearn.metrics import recall_score

# Import your actual feature extraction logic
# (Make sure your file is named feature_extraction.py)
from tier1_ml.feature_extractor import generate_data_set

# --- 1. LOAD MODEL & DATA ---
print("Loading Model and Data...")
with open('phishing_model_v3.pkl', 'rb') as f:
    model = pickle.load(f)

df = pd.read_csv('test_dataset.csv')
y_true = df['label'].values

# --- 2. EXTRACT FEATURES & PREDICT ---
print(f"Extracting features for {len(df)} URLs... (Please wait, this may take a few minutes)")

# generate_data_set returns [[f1, f2, ... f14]], so we grab [0] to flatten it for the dataframe
X_features = df['url'].apply(lambda x: generate_data_set(x)[0]).tolist()

print("Running ML predictions...")
y_pred_proba = model.predict_proba(X_features)[:, 1]

# --- 3. DEFINE SYSTEM CONSTANTS ---
T_SAFE = 0.07
T_MALICIOUS = 0.85
ORACLE_HIT_RATE = 0.90 # Simulating that Tier 2 catches 90% of historical threats

print("\n" + "="*60)
print("🔬 PART 1: DETERMINISTIC OFFLINE CASCADE EVALUATION")
print("="*60)

# --- 4. BASELINE EVALUATION (Standard ML at 0.5) ---
y_pred_baseline = (y_pred_proba >= 0.5).astype(int)
baseline_recall = recall_score(y_true, y_pred_baseline)
total_phishing = np.sum(y_true == 1)

print(f"Baseline ML Recall (Threshold 0.5): {baseline_recall * 100:.2f}%")

# --- 5. CASCADE ARCHITECTURE EVALUATION ---
# Isolate the Grey Zone
grey_mask = (y_pred_proba >= T_SAFE) & (y_pred_proba <= T_MALICIOUS)
escalation_rate = (np.sum(grey_mask) / len(y_pred_proba)) * 100

# Calculate Fatal Bypasses (The absolute blind spots)
fatal_mask = (y_true == 1) & (y_pred_proba < T_SAFE)
fatal_bypasses = np.sum(fatal_mask)

# Calculate Grey Zone Phishing (Threats successfully routed to the Oracle)
grey_phishing_mask = (y_true == 1) & grey_mask
grey_phishing_count = np.sum(grey_phishing_mask)

# Simulate the Oracle (Tier 2) rescuing the Grey Zone threats
oracle_rescues = int(grey_phishing_count * ORACLE_HIT_RATE)

# Calculate Final Cascade Recall
tier_1_caught = np.sum((y_true == 1) & (y_pred_proba > T_MALICIOUS))
final_cascade_caught = tier_1_caught + oracle_rescues
final_cascade_recall = final_cascade_caught / total_phishing

print("-" * 60)
print(f"System Escalation Rate:             {escalation_rate:.2f}%")
print(f"Total Phishing Samples:             {total_phishing}")
print(f"Threats Routed to Oracle:           {grey_phishing_count}")
print(f"Expected Oracle Rescues (at {ORACLE_HIT_RATE*100}%): {oracle_rescues}")
print(f"Fatal Bypasses (P < {T_SAFE}):        {fatal_bypasses}")
print("-" * 60)
print(f"🔥 FINAL SYSTEM RECALL (Simulated): {final_cascade_recall * 100:.2f}%")
print("="*60 + "\n")

# import pandas as pd

# train_df = pd.read_csv('train_dataset.csv')
# test_df  = pd.read_csv('test_dataset.csv')

# print("=== FULL DATASET STATISTICS ===")
# print(f"Total URLs        : {len(train_df)+len(test_df):,}")
# print(f"Train set         : {len(train_df):,}")
# print(f"Test set          : {len(test_df):,}")
# print(f"\nTrain - Phishing  : {train_df['label'].sum():,}")
# print(f"Train - Legit     : {(train_df['label']==0).sum():,}")
# print(f"\nTest  - Phishing  : {test_df['label'].sum():,}")
# print(f"Test  - Legit     : {(test_df['label']==0).sum():,}")
# print(f"\nTotal Phishing    : {train_df['label'].sum()+test_df['label'].sum():,}")
# print(f"Total Legit       : {(train_df['label']==0).sum()+(test_df['label']==0).sum():,}")
# print(f"\nClass ratio       : 1:{((train_df['label']==0).sum()+(test_df['label']==0).sum())/(train_df['label'].sum()+test_df['label'].sum()):.2f}")