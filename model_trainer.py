import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import pickle
import re
from urllib.parse import urlparse

print("Script starting...")

# 1. Load and Combine the Larger Datasets
print("Loading and combining datasets...")
try:
    train_df = pd.read_csv('train_dataset.csv')
    test_df = pd.read_csv('test_dataset.csv')
    df = pd.concat([train_df, test_df], ignore_index=True)
except FileNotFoundError:
    print("Error: Make sure 'train_dataset.csv' and 'test_dataset.csv' are in the 'backend' folder.")
    exit()

print(f"Total dataset size: {len(df)} samples.")

# 2. Data Cleaning with Whitelist
print("Cleaning data using domain whitelist...")
trusted_domains = {
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'youtube.com', 'wikipedia.org', 'twitter.com', 'linkedin.com', 'instagram.com'
}

def clean_labels(row):
    try:
        domain = urlparse(row['url']).netloc.replace('www.', '')
        if domain in trusted_domains:
            return 0
    except Exception:
        pass
    return row['label']

df['label'] = df.apply(clean_labels, axis=1)
print("Data cleaning complete.")

# 3. Final 8-Feature Extraction
def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('&'))
    # The unreliable '//' feature is removed
    features.append(1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0)
    features.append(sum(c.isdigit() for c in url))
    return features

print("Generating features from URLs...")
X = df['url'].apply(extract_features).tolist()
y = df['label']

# 4. Split Data for Training and Evaluation
print("Splitting data into training and testing sets...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Train the Model
print("Training the XGBoost model...")
xgb = XGBClassifier(n_estimators=100, learning_rate=0.1, eval_metric='logloss')
xgb.fit(X_train, y_train)
print("Model training complete.")

# 6. Evaluate and Print Accuracy
print("Evaluating model...")
y_pred = xgb.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# 7. Save the Trained Model
print("Saving the model to 'phishing_model.pkl'...")
with open('phishing_model.pkl', 'wb') as f:
    pickle.dump(xgb, f)

print("Model saved successfully. Script finished.")