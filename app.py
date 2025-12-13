from flask import Flask, request, jsonify
import pickle
import re
import numpy as np
import os
import requests
import base64
import time
from dotenv import load_dotenv

import whois 
from datetime import datetime
import socket
import ssl
import certifi 
from urllib.parse import urlparse 

from bs4 import BeautifulSoup

import feedparser # <--- NEW IMPORT

load_dotenv()
app = Flask(__name__)

# --- 1. FALLBACK MODEL ---
print("Loading local ML model as fallback...")
try:
    with open('phishing_model.pkl', 'rb') as f:
        local_model = pickle.load(f)
except FileNotFoundError:
    print("⚠️ Warning: phishing_model.pkl not found. Local model features disabled.")
    local_model = None

def extract_features(url):
    features = []
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('@'))
    features.append(url.count('?'))
    features.append(url.count('&'))
    features.append(1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else 0)
    features.append(sum(c.isdigit() for c in url))
    return features

def predict_with_local_model(url):
    if not local_model: return 'Unknown'
    print("Fallback: Using local model...")
    features = np.array(extract_features(url)).reshape(1, -1)
    prediction = local_model.predict(features)
    return 'Malicious' if prediction[0] == 1 else 'Safe'

RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews", # The Hacker News (Top Tier)
    "https://www.bleepingcomputer.com/feed/",      # BleepingComputer (Breaking News)
    "https://www.darkreading.com/rss.xml"          # Dark Reading (Enterprise)
]

def get_cyber_news():
    news_items = []
    
    print("📡 Fetching latest cyber intelligence...")
    
    for feed_url in RSS_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
            for entry in feed.entries[:5]: # Take top 5 from each source
                
                # 1. Try to find an image
                image_url = None
                if 'media_content' in entry:
                    image_url = entry.media_content[0]['url']
                elif 'links' in entry:
                    for link in entry.links:
                        if link['type'].startswith('image'):
                            image_url = link['href']
                            break
                
                # 2. Clean up Summary (Remove HTML tags)
                summary_text = entry.summary if 'summary' in entry else entry.title
                clean_summary = BeautifulSoup(summary_text, "html.parser").get_text()[:150] + "..."

                # 3. Determine Type (Simple keyword check)
                title_lower = entry.title.lower()
                news_type = 'INFO'
                if 'malware' in title_lower or 'virus' in title_lower or 'ransomware' in title_lower:
                    news_type = 'MALWARE'
                elif 'breach' in title_lower or 'leak' in title_lower or 'hack' in title_lower:
                    news_type = 'BREACH'
                elif 'update' in title_lower or 'patch' in title_lower or 'zero-day' in title_lower:
                    news_type = 'PATCH'
                elif 'alert' in title_lower or 'warning' in title_lower:
                    news_type = 'ALERT'

                news_items.append({
                    'title': entry.title,
                    'summary': clean_summary,
                    'url': entry.link,
                    'source': feed.feed.title if 'title' in feed.feed else "CyberWire",
                    'timestamp': entry.published_parsed if 'published_parsed' in entry else datetime.now().timetuple(),
                    'imageUrl': image_url,
                    'type': news_type
                })
        except Exception as e:
            print(f"Error fetching feed {feed_url}: {e}")

    # Sort by date (Newest first) and take top 10
    news_items.sort(key=lambda x: x['timestamp'], reverse=True)
    return news_items[:10]

@app.route('/news', methods=['GET'])
def news_endpoint():
    try:
        articles = get_cyber_news()
        return jsonify(articles)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- 2. VIRUSTOTAL API LOGIC ---
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VT_API_URL = 'https://www.virustotal.com/api/v3/urls/'
MALICIOUS_THRESHOLD = 3 

def predict_with_virustotal(url):
    print("Primary: Checking VirusTotal...")
    if not VT_API_KEY:
        print("Warning: VIRUSTOTAL_API_KEY not set. Using fallback.")
        return None 

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {'x-apikey': VT_API_KEY}
        response = requests.get(VT_API_URL + url_id, headers=headers)

        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            total_flags = stats['malicious'] + stats['suspicious']
            
            if total_flags >= MALICIOUS_THRESHOLD:
                print(f"VirusTotal: Malicious (Flags: {total_flags})")
                return 'Malicious'
            else:
                print(f"VirusTotal: Safe (Flags: {total_flags})")
                return 'Safe'
        elif response.status_code == 404:
            print("VirusTotal: URL unknown. Using fallback.")
            return None 
        else:
            print(f"VirusTotal Error: {response.status_code}. Using fallback.")
            return None 
    except Exception as e:
        print(f"Exception during VT call: {e}. Using fallback.")
        return None

# --- 3. FORENSICS MODULE (UPDATED) ---
def get_domain_forensics(url):
    forensics = {
        "domain_age_days": None,
        "registrar": "Unknown",
        "ssl_issuer": "None",
        "is_suspicious_age": False,
        "is_suspicious_issuer": False 
    }
    
    try:
        if not url.startswith(('http://', 'https://')):
            parse_url = 'http://' + url
        else:
            parse_url = url
            
        domain = urlparse(parse_url).netloc
        if not domain: return forensics

        # A. WHOIS (Domain Age)
        try:
            print(f"Forensics: Checking WHOIS for {domain}...")
            w = whois.whois(domain)
            creation_date = w.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                if isinstance(creation_date, str):
                      try:
                         creation_date = datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
                      except:
                         pass 

                if isinstance(creation_date, datetime):
                    if creation_date.tzinfo is not None:
                        creation_date = creation_date.replace(tzinfo=None)
                    
                    age = (datetime.now() - creation_date).days
                    forensics['domain_age_days'] = age
                    forensics['registrar'] = w.registrar
                    
                    # --- NEW: Extract Abuse Email ---
                    emails = w.emails
                    abuse_email = None
                    
                    if isinstance(emails, list):
                        # 1. Try to find an email with 'abuse' in it
                        for email in emails:
                            if 'abuse' in email.lower():
                                abuse_email = email
                                break
                        # 2. If no 'abuse' email, just take the first one
                        if not abuse_email and len(emails) > 0:
                            abuse_email = emails[0]
                    elif isinstance(emails, str):
                        abuse_email = emails
                        
                    forensics['abuse_email'] = abuse_email
                    
                    if age < 30:
                        forensics['is_suspicious_age'] = True
        except Exception as e:
            print(f"Whois Error: {e}")

        # B. SSL CERTIFICATE CHECK
        try:
            print(f"Forensics: Checking SSL for {domain}...")
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(cafile=certifi.where())

            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3.0) 
                s.connect((domain, 443))
                cert = s.getpeercert()
                
                issuer = dict(x[0] for x in cert['issuer'])
                organization = issuer.get('organizationName', 'Unknown')
                common_name = issuer.get('commonName', 'Unknown')
                
                if organization != 'Unknown':
                    forensics['ssl_issuer'] = organization
                else:
                    forensics['ssl_issuer'] = common_name
                
                # --- FIX: REMOVED THE "LET'S ENCRYPT" PENALTY ---
                # We now trust Let's Encrypt because major sites use it.
                # Only flag if it's explicitly explicitly untrusted or self-signed.
                
        except ssl.SSLCertVerificationError:
            print("Forensics: SSL Invalid/Expired")
            forensics['ssl_issuer'] = "❌ Invalid / Expired"
            forensics['is_suspicious_issuer'] = True 
            
        except socket.timeout:
            print("Forensics: SSL Timeout")
            forensics['ssl_issuer'] = "⚠️ Timeout (Blocked?)"
            # A timeout is annoying, but not necessarily malicious (could be firewall)
            
        except Exception as e:
             print(f"SSL Error: {e}")
             forensics['ssl_issuer'] = "Unknown / No SSL"
             # If SSL fails entirely, we flag it
             forensics['is_suspicious_issuer'] = True
        
    except Exception as e:
        print(f"Forensics General Error: {e}")
    
    return forensics

def get_page_content_forensics(url):
    evidence = {
        "has_password_field": False,
        "has_login_form": False,
        "page_title": "Unknown",
        "suspicious_keywords": [],
        "is_suspicious_content": False
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        print(f"🕵️‍♂️ Scanning Content: {url}")
        # Reduced timeout to 4s to speed up scans
        response = requests.get(url, headers=headers, timeout=4)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            if soup.title:
                evidence['page_title'] = soup.title.string.strip()
            
            password_inputs = soup.find_all('input', {'type': 'password'})
            if password_inputs:
                print("⚠️ FOUND PASSWORD INPUT FIELD")
                evidence['has_password_field'] = True
                evidence['is_suspicious_content'] = True
            
            text_content = soup.get_text().lower()
            risk_words = ['verify your account', 'update payment', 'confirm identity', 'urgent action', 'login', 'signin', 'password']
            found_risks = [word for word in risk_words if word in text_content]
            evidence['suspicious_keywords'] = list(set(found_risks)) # Unique list
            
            if len(found_risks) > 0:
                evidence['is_suspicious_content'] = True

    except Exception as e:
        print(f"Content Scan Error: {e}")
    
    return evidence

# --- 4. NEW: SCORING ENGINE ---
def calculate_safety_score(vt_result, domain_data, content_data, url):
    score = 10.0
    reasons = []

    # 1. VIRUSTOTAL (The Hammer)
    if vt_result == 'Malicious':
        score -= 10
        reasons.append("Flagged by VirusTotal security vendors")
    
    # 2. SSL/TLS CERTIFICATE (The Shield)
    if url.startswith("http://"):
        score -= 4
        reasons.append("Insecure Connection (HTTP only - No SSL)")
    elif domain_data.get('is_suspicious_issuer'):
        score -= 3
        reasons.append("Suspicious or Self-Signed SSL Certificate")
    
    # 3. CONTENT FORENSICS (The Trap)
    # Penalty: Password field on insecure HTTP
    if content_data.get('has_password_field'):
        if url.startswith("http://"):
            score -= 5 
            reasons.append("CRITICAL: Password field detected on insecure connection")
        else:
            # Password field on HTTPS is acceptable, but we note it
            pass 
            
    if content_data.get('is_suspicious_content') and not content_data.get('has_password_field'):
        # Only deduct for keywords if no major password risk was already found to avoid double counting
        score -= 1
        reasons.append("Suspicious keywords found in page content")

    # 4. DOMAIN AGE (The History)
    days_alive = domain_data.get('domain_age_days')
    if days_alive is not None and days_alive < 30:
        score -= 2
        reasons.append(f"Domain is extremely new ({days_alive} days old)")

    # Clamp score between 0 and 10
    final_score = max(0, min(10, score))
    
    # Determine Label
    if final_score >= 8:
        label = "Safe"
    elif final_score >= 5:
        label = "Suspicious"
    else:
        label = "Malicious" # 0-4 is dangerous

    return final_score, label, reasons

# --- 5. MAIN ENDPOINT ---
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json(force=True)
        url_to_check = data.get('url')
        if not url_to_check: return jsonify({'error': 'No URL provided'}), 400

        print(f"\n🔎 ANALYZING: {url_to_check}")

        # 1. Gather Evidence (Run all scans)
        vt_prediction = predict_with_virustotal(url_to_check)
        domain_forensics = get_domain_forensics(url_to_check)
        content_forensics = get_page_content_forensics(url_to_check)

        # 2. Calculate Score
        score, prediction, reasons = calculate_safety_score(
            vt_prediction, 
            domain_forensics, 
            content_forensics, 
            url_to_check
        )

        print(f"📊 FINAL SCORE: {score}/10 ({prediction})")
        
        # 3. Merge Data for Frontend
        full_report = {
            **domain_forensics, 
            **content_forensics,
            "risk_reasons": reasons
        }

        return jsonify({
            'url': url_to_check,
            'prediction': prediction,
            'score': score, 
            'source': 'CyberGuard AI Scoring Engine',
            'forensics': full_report
        })
    except Exception as e:
        print(f"Server Error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)