import os
from flask import Flask, jsonify
from flask_cors import CORS
import os
import re
import time
import calendar
import threading
import requests

import feedparser

# --- Import Architecture Modules ---
from config import Config
from database.firebase_client import init_firebase
from tier1_ml.model_loader import load_model
from tier2_intel.blacklist_loader import load_local_lists
from tier2_intel.blacklist_sync import start_background_sync
from sockets.socket_handler import init_websockets
from workers.task_queue import init_queue

# --- Initialize Flask Application ---
app = Flask(__name__)
app.config.from_object(Config)

# Enable CORS for standard HTTP routes (if needed later)
CORS(app)
HTTP_SESSION = requests.Session()
TAG_RE = re.compile(r"<[^>]+>")
NEWS_CACHE_TTL_SECONDS = int(os.getenv("NEWS_CACHE_TTL_SECONDS", "600"))
NEWS_CACHE = {"expires_at": 0.0, "data": []}
def strip_html(text):
    if not text:
        return ""
    return TAG_RE.sub("", text)

def parse_entry_timestamp(entry):
    published = getattr(entry, "published_parsed", None)
    if published:
        try:
            return float(calendar.timegm(published))
        except Exception:
            pass
    return time.time()
@app.route("/news", methods=["GET"])
def news():
    try:
        now = time.time()
        if NEWS_CACHE["expires_at"] > now and NEWS_CACHE["data"]:
            return jsonify(NEWS_CACHE["data"])

        news_items = []
        RSS_FEEDS = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://www.bleepingcomputer.com/feed/",
            "https://krebsonsecurity.com/feed/",
            "https://www.darkreading.com/rss.xml"
        ]
        for feed_url in RSS_FEEDS:
            try:
                feed = feedparser.parse(feed_url)
                for entry in feed.entries[:5]:
                    image_url = entry.media_content[0].get("url") if "media_content" in entry else None
                    raw_summary = getattr(entry, "summary", None) or entry.title
                    summary = strip_html(raw_summary)
                    
                    news_items.append({
                        "title": entry.title,
                        "summary": summary[:150] + "...",
                        "url": entry.link,
                        "source": feed.feed.title if "title" in feed.feed else "Cyber News",
                        "timestamp": parse_entry_timestamp(entry),
                        "imageUrl": image_url,
                        "type": "INFO"
                    })
            except Exception:
                continue
        
        news_items.sort(key=lambda x: x["timestamp"], reverse=True)
        trimmed = news_items[:10]
        NEWS_CACHE["data"] = trimmed
        NEWS_CACHE["expires_at"] = now + NEWS_CACHE_TTL_SECONDS
        return jsonify(trimmed)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


print("\n" + "="*50)
print("🛡️  CYBERGUARD AI BACKEND INITIALIZING...")
print("="*50)

# --- 1. Initialize Persistence Layer ---
print("\n[1/5] Connecting to Database...")
init_firebase()

# --- 2. Initialize Tier 1 (Machine Learning) ---
print("[2/5] Loading Tier-1 Lexical ML Engine...")
load_model('tier1_ml/phishing_model_v2.pkl')

# --- 3. Initialize Tier 2 (Threat Intelligence) ---
print("[3/5] Loading Tier-2 Threat Intelligence...")
load_local_lists()
# Kick off the background thread to fetch the latest zero-days every 60 minutes
start_background_sync(interval_minutes=60)

# --- 4. Initialize Real-Time WebSockets & Task Queue ---
print("[4/5] Establishing Event-Driven WebSocket Layer...")
socketio = init_websockets(app)
init_queue(socketio)

# --- 5. Register WebSocket Events ---
print("[5/5] Registering Mobile Client Event Listeners...")
# We import events here so the @socketio.on decorators attach to the initialized instance
import sockets.events

print("\n" + "="*50)
print("✅ SYSTEM ONLINE. READY FOR MOBILE CONNECTIONS.")
print("="*50 + "\n")

# --- Standard HTTP Health Check Route ---
@app.route('/health', methods=['GET'])
def health_check():
    """Simple HTTP endpoint to verify the server is running."""
    return jsonify({
        "status": "healthy",
        "service": "CyberGuard AI Cascaded Backend",
        "tiers_active": [1, 2, 3]
    }), 200

if __name__ == '__main__':
    # Use SocketIO's run method (which wraps Eventlet/Gevent) instead of standard app.run()
    # Host '0.0.0.0' allows your mobile phone on the same Wi-Fi to connect
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)