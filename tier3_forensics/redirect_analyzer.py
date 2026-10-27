import re
from typing import List
from urllib.parse import urlparse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False  # graceful fallback to netloc split

from .schemas import RedirectSignals

# ── Tuning ─────────────────────────────────────────────────────────────────────

_EXCESSIVE_REDIRECT_THRESHOLD = 3   # > this many hops → flag (mirrors original)

# Known URL-shortener / redirect-as-a-service domains
# These are legitimate services but heavily abused to hide phishing destinations.
_SHORTENER_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "rebrand.ly", "short.io", "cutt.ly", "is.gd", "v.gd", "bl.ink",
    "tiny.cc", "shorte.st", "adf.ly", "linktr.ee", "lnkd.in",
})

# ── Helpers ────────────────────────────────────────────────────────────────────

def _etld1(url: str) -> str:
    """
    Return the eTLD+1 (e.g. 'paypal.com') from any URL.
    Uses tldextract when available, falls back to parts[-2].parts[-1].
    """
    try:
        netloc = urlparse(url).netloc.lower().split(":")[0]
        if not netloc:
            return ""
        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(netloc)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            return netloc
        parts = netloc.split(".")
        return f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else netloc
    except Exception:
        return ""


def _scheme(url: str) -> str:
    try:
        return urlparse(url).scheme.lower()
    except Exception:
        return ""


# ── Public API ─────────────────────────────────────────────────────────────────

def analyze_redirects(redirect_chain: List[str]) -> RedirectSignals:
    """
    Analyzes the HTTP redirect chain for evasion tactics.

    New signals vs v1:
      • domain_changes       — counts how many times eTLD+1 changed across hops
      • cross_domain_redirect — True if any domain change occurred
      • shortener_detected   — True if any hop passes through a URL shortener
      • http_to_http_bypass  — True if chain starts HTTPS then drops to HTTP
                               (original only caught HTTP→HTTPS→HTTP bounce)
    """
    signals = RedirectSignals()

    if not redirect_chain:
        return signals

    signals.redirect_count = len(redirect_chain)

    # ── Rule 1: Excessive hops (original) ─────────────────────────────────────
    if signals.redirect_count > _EXCESSIVE_REDIRECT_THRESHOLD:
        signals.excessive_redirect_flag = True

    # ── Rule 2: Protocol sequence analysis (original + extended) ──────────────
    protocols = [_scheme(url) for url in redirect_chain]

    if len(protocols) >= 2:
        # Original: HTTP → HTTPS → HTTP bounce (protocol ping-pong)
        if (protocols[0] == "http"
                and "https" in protocols
                and protocols[-1] == "http"):
            signals.suspicious_routing = True

        # New: HTTPS → HTTP downgrade at any point (strips TLS protection)
        for i in range(len(protocols) - 1):
            if protocols[i] == "https" and protocols[i + 1] == "http":
                signals.suspicious_routing = True
                break

    # ── Rule 3: Cross-domain redirect counting ────────────────────────────────
    # Each time the eTLD+1 changes across a hop we count it.
    # A single domain change is normal (e.g. HTTP→HTTPS canonical redirect).
    # Multiple domain changes is a strong evasion signal.
    domains = [_etld1(url) for url in redirect_chain]
    domain_changes = sum(
        1 for i in range(len(domains) - 1)
        if domains[i] and domains[i + 1] and domains[i] != domains[i + 1]
    )
    signals.domain_changes        = domain_changes
    signals.cross_domain_redirect = domain_changes > 0

    # ── Rule 4: URL shortener in the chain ────────────────────────────────────
    # Shorteners are commonly used as a first hop to hide the final phishing
    # domain from link-preview scanners and email filters.
    for url in redirect_chain:
        if _etld1(url) in _SHORTENER_DOMAINS:
            signals.shortener_detected = True
            break

    return signals