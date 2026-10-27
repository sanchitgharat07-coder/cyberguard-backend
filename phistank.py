import requests
import pandas as pd

print("Downloading OpenPhish feed...")

# OpenPhish free feed — plain text, one URL per line, no auth needed
response = requests.get(
    "https://openphish.com/feed.txt",
    headers={"User-Agent": "Mozilla/5.0"},
    timeout=30
)

urls = [
    line.strip()
    for line in response.text.splitlines()
    if line.strip().startswith("http")
]

print(f"Total live phishing URLs: {len(urls)}")

df = pd.DataFrame({"url": urls})
df.to_csv("phishtank_live.csv", index=False)

# Sample 200
sample = df.sample(n=min(200, len(df)), random_state=42)
sample.to_csv("phishtank_sample_200.csv", index=False)

print(f"Saved {len(sample)} URLs to phishtank_sample_200.csv")
print(sample.head(10))