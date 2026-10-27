"""
blacklist_sync.py — Firebase ↔ RAM blacklist synchronization.

Responsibilities:
  • On startup: full fetch from Firebase into RAM
  • Real-time: on_snapshot listener fires instantly on any Firebase change
  • Fallback: poll loop every N minutes in case listener drops
  • Write-back: report_malicious() writes Tier-3 verdicts back to Firebase
               so they are instantly picked up by all running instances
               via the real-time listener
"""

import threading
import time
from database.firebase_client import get_db
from .blacklist_loader import add_to_blacklist

_listener_handle = None
_listener_lock   = threading.Lock()


# ── Read: Firebase → RAM ───────────────────────────────────────────────────────

def fetch_firebase_intel():
    """Full fetch from Firestore into RAM. Called on startup and by poll loop."""
    print("🔄 [Tier-2 Sync] Fetching Threat Intel from Firebase...")

    db = get_db()
    if not db:
        print("⚠️ [Tier-2 Sync] Firebase not initialized. Skipping sync.")
        return

    try:
        docs = db.collection("blacklisted_domains").stream()
        malicious_domains = set()

        for doc in docs:
            data = doc.to_dict()
            domain_string = data.get("domain")
            if domain_string:
                malicious_domains.add(domain_string.lower().strip())

        if malicious_domains:
            add_to_blacklist(malicious_domains)
            print(f"✅ [Tier-2 Sync] Loaded {len(malicious_domains)} domains into RAM.")
        else:
            print("ℹ️ [Tier-2 Sync] Firebase blacklist is empty.")

    except Exception as e:
        print(f"❌ [Tier-2 Sync] Firebase fetch error: {e}")


# ── Write: Tier-3 verdict → Firebase → RAM (via listener) ─────────────────────

def report_malicious(url: str, signals: list = None):
    """
    Called by the worker when Tier-3 flags a URL as malicious.

    Writes the domain to Firebase 'blacklisted_domains' collection.
    The real-time on_snapshot listener picks it up instantly and syncs
    all running instances — no manual RAM update needed here.

    Document structure mirrors existing Firebase schema:
      { domain, source, signals, flagged_at }
    """
    from urllib.parse import urlparse
    from datetime import datetime, timezone

    try:
        netloc = urlparse(url).netloc.lower().split(":")[0]
        if not netloc:
            return

        db = get_db()
        if not db:
            # Firebase unavailable — update local RAM directly as fallback
            add_to_blacklist({netloc})
            print(f"⚠️ [Tier-2 Write] Firebase unavailable. Added '{netloc}' to local RAM only.")
            return

        # Use netloc as document ID to prevent duplicates naturally
        doc_ref = db.collection("blacklisted_domains").document(netloc)
        doc_ref.set({
            "domain":     netloc,
            "source":     "tier3_auto",
            "signals":    signals or [],
            "flagged_at": datetime.now(timezone.utc).isoformat(),
        })

        print(f"🚨 [Tier-2 Write] '{netloc}' written to Firebase — listener will sync all instances.")

    except Exception as e:
        print(f"❌ [Tier-2 Write] Failed to report malicious domain: {e}")
        # Fallback: at minimum keep local RAM updated
        try:
            add_to_blacklist({netloc})
        except Exception:
            pass


# ── Real-time listener: Firebase → RAM instantly ───────────────────────────────

def _on_snapshot(col_snapshot, changes, read_time):
    """
    Firestore calls this on its own background thread whenever any document
    in 'blacklisted_domains' is added, modified, or deleted.
    Rebuilds full set from snapshot for consistency.
    """
    try:
        malicious_domains = set()
        for doc in col_snapshot:
            data = doc.to_dict()
            domain_string = data.get("domain")
            if domain_string:
                malicious_domains.add(domain_string.lower().strip())

        add_to_blacklist(malicious_domains)
        print(
            f"⚡ [Tier-2 Live] Firestore change detected — "
            f"resynced {len(malicious_domains)} domains into RAM."
        )
    except Exception as e:
        print(f"❌ [Tier-2 Live] Snapshot error: {e}")


def _start_realtime_listener() -> bool:
    """
    Attaches on_snapshot listener to 'blacklisted_domains'.
    Returns True if successful, False if Firebase unavailable.
    """
    global _listener_handle

    db = get_db()
    if not db:
        return False

    try:
        with _listener_lock:
            if _listener_handle:
                _listener_handle.unsubscribe()
            col_ref = db.collection("blacklisted_domains")
            _listener_handle = col_ref.on_snapshot(_on_snapshot)

        print("🔌 [Tier-2 Live] Real-time Firestore listener attached.")
        return True

    except Exception as e:
        print(f"⚠️ [Tier-2 Live] Could not attach listener: {e}. Poll-only mode.")
        return False


def stop_realtime_listener():
    """Cleanly detach listener on app shutdown to avoid resource leaks."""
    global _listener_handle
    with _listener_lock:
        if _listener_handle:
            try:
                _listener_handle.unsubscribe()
                print("🔌 [Tier-2 Live] Listener detached.")
            except Exception as e:
                print(f"⚠️ [Tier-2 Live] Error detaching listener: {e}")
            finally:
                _listener_handle = None


# ── Poll loop: safety net if listener drops ────────────────────────────────────

def start_background_sync(interval_minutes: int = 60):
    """
    Starts the full Tier-2 sync system:
      1. Immediate full fetch on startup
      2. Real-time listener for instant change propagation
      3. Background poll loop as safety net if listener drops
    """
    fetch_firebase_intel()
    _start_realtime_listener()

    def sync_loop():
        while True:
            time.sleep(interval_minutes * 60)
            fetch_firebase_intel()

            # Re-check listener health every poll cycle and re-attach if lost
            with _listener_lock:
                listener_alive = _listener_handle is not None
            if not listener_alive:
                print("⚠️ [Tier-2 Sync] Listener not active — re-attaching...")
                _start_realtime_listener()

    thread = threading.Thread(target=sync_loop, daemon=True)
    thread.start()
    print(f"⏱️  [Tier-2 Sync] Poll loop started (every {interval_minutes} min as safety net).")