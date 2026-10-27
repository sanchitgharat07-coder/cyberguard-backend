"""
blacklist_loader.py — Pure O(1) RAM blacklist lookup.

Tier-2 has exactly ONE job:
  "Is this URL/domain in our known-malicious database?"

  YES → return 'malicious' (skip Tier-3, save resources)
  NO  → return 'unknown'   (pass to Tier-3 for analysis)

No whitelist. No TLD checks. No risk scoring. No analysis.
All thinking is done by Tier-1 and Tier-3.
"""

# In-memory O(1) lookup — populated by blacklist_sync.py on startup
_malicious_domains: set = set()


def load_local_lists():
    """
    Called once on server startup.
    No static lists to load — Firebase sync populates _malicious_domains
    via add_to_blacklist() called from blacklist_sync.py.
    """
    print("✅ Tier-2 Intel: Blacklist engine ready (Firebase sync will populate).")


def check_tier2_intel(variations: list) -> str:
    """
    Checks all domain variations against the in-memory blacklist.
    Returns 'malicious' if any variation is found, 'unknown' otherwise.
    Never returns 'safe' or 'suspicious' — those are not Tier-2 decisions.
    """
    for var in variations:
        if var in _malicious_domains:
            return 'malicious'
    return 'unknown'


def add_to_blacklist(domains: set):
    """Updates the live blacklist in RAM. Called by blacklist_sync.py."""
    global _malicious_domains
    _malicious_domains.update(domains)
    print(f"✅ Tier-2 Intel: Blacklist updated — {len(_malicious_domains)} domains in RAM.")