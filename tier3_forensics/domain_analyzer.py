import re
import threading
import time
import urllib.parse
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False  # graceful fallback to old heuristic

from .schemas import DomainSignals

# ── Tuning ─────────────────────────────────────────────────────────────────────

_YOUNG_DOMAIN_DAYS       = 30
_RDAP_TIMEOUT            = (0.4, 0.8)   # (connect_timeout, read_timeout)
_CACHE_TTL_SECONDS       = 900          # 15 min — mirrors original forensics.py
_CACHE_MAX_SIZE          = 1024

# ── Expanded suspicious TLD list (APWG eCrime + Spamhaus DBL data) ─────────────

SUSPICIOUS_TLDS = {
    # Free / donated — highest phishing volume
    'tk', 'ml', 'ga', 'cf', 'gq',
    # Generic high-abuse
    'xyz', 'top', 'pw', 'cc', 'club', 'work', 'su',
    # ccTLD abuse
    'cn', 'ru',
    # New gTLDs with disproportionate phishing rates
    'icu', 'shop', 'online', 'site', 'space', 'website', 'fun', 'world',
    # Near-zero legitimate use
    'loan', 'date', 'racing', 'review', 'stream',
    'download', 'cricket', 'win', 'accountant', 'bid', 'trade',
}

# ── Shared RDAP session (connection-pooled, no cookies needed) ─────────────────

def _build_rdap_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"Accept": "application/rdap+json, application/json"})
    adapter = HTTPAdapter(
        max_retries=Retry(total=0),  # no retries — we have our own fallback
        pool_connections=5,
        pool_maxsize=10,
    )
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session

_RDAP_SESSION = _build_rdap_session()

# ── TTL cache — ported directly from original forensics.py ─────────────────────

_CACHE: dict         = {}
_CACHE_LOCK          = threading.Lock()


def _cache_get(domain: str):
    now = time.time()
    with _CACHE_LOCK:
        entry = _CACHE.get(domain)
        if not entry:
            return None
        if entry["expires_at"] <= now:
            _CACHE.pop(domain, None)
            return None
        return dict(entry["data"])


def _cache_set(domain: str, data: dict) -> None:
    now = time.time()
    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX_SIZE:
            _CACHE.pop(next(iter(_CACHE)))  # evict oldest (insertion order)
        _CACHE[domain] = {
            "expires_at": now + _CACHE_TTL_SECONDS,
            "data":       dict(data),
        }


# ── Domain parsing ─────────────────────────────────────────────────────────────

def _extract_root_domain(url: str) -> str:
    """
    Extracts 'paypal.com' from 'http://secure.login.paypal.com/auth'.

    Uses tldextract when available (handles co.uk, com.au, etc.).
    Falls back to the original parts[-2].parts[-1] heuristic if not installed.
    """
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
        if not netloc:
            return ""

        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(netloc)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            return netloc  # IP or unrecognised — return as-is

        # Original fallback heuristic
        parts = netloc.split('.')
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return netloc

    except Exception:
        return ""


# ── RDAP lookup (two-stage with IANA fallback) ─────────────────────────────────

def _parse_registration_age(data: dict):
    """Pull age_days from an RDAP JSON dict. Returns None if not found."""
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            raw = event.get("eventDate", "")
            if raw:
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    return (datetime.now(timezone.utc) - dt).days
                except ValueError:
                    pass
    return None


def _check_rdap_age(domain: str) -> tuple[bool, bool]:
    """
    Queries RDAP for domain age.
    Returns: (young_domain_flag, whois_failed_flag)

    Two-stage strategy:
      1. rdap.org bootstrap router  — one hop, covers most gTLDs
      2. IANA bootstrap JSON        — authoritative fallback for ccTLDs
    Both attempts respect the strict 800 ms read budget.
    """
    if not domain:
        return False, True

    # ── Stage 1: rdap.org ──────────────────────────────────────────────────────
    try:
        r = _RDAP_SESSION.get(
            f"https://rdap.org/domain/{domain}",
            timeout=_RDAP_TIMEOUT,
            allow_redirects=True,
        )
        if r.status_code == 200:
            age = _parse_registration_age(r.json())
            if age is not None:
                return age < _YOUNG_DOMAIN_DAYS, False
            return False, False   # RDAP responded but no registration event

    except Exception:
        pass

    # ── Stage 2: IANA bootstrap (authoritative ccTLD fallback) ────────────────
    try:
        tld = domain.rsplit(".", 1)[-1]
        bootstrap = _RDAP_SESSION.get(
            "https://data.iana.org/rdap/dns.json",
            timeout=_RDAP_TIMEOUT,
        )
        if bootstrap.status_code == 200:
            for tlds_list, endpoints in bootstrap.json().get("services", []):
                if tld in tlds_list and endpoints:
                    base = endpoints[0].rstrip("/") + "/"
                    r2 = _RDAP_SESSION.get(
                        f"{base}domain/{domain}",
                        timeout=_RDAP_TIMEOUT,
                    )
                    if r2.status_code == 200:
                        age = _parse_registration_age(r2.json())
                        if age is not None:
                            return age < _YOUNG_DOMAIN_DAYS, False
                        return False, False

    except Exception:
        pass

    return False, True   # both stages failed — fail-open


# ── Public API (signature unchanged) ──────────────────────────────────────────

def analyze_domain(url: str) -> DomainSignals:
    """Main entry point for domain analysis."""
    root_domain = _extract_root_domain(url)
    tld = root_domain.split('.')[-1] if '.' in root_domain else ""

    # Serve from cache if available — avoids redundant RDAP calls
    cached = _cache_get(root_domain)
    if cached:
        return DomainSignals(**cached)

    suspicious_tld = tld in SUSPICIOUS_TLDS
    young_domain, whois_failed = _check_rdap_age(root_domain)

    result = DomainSignals(
        root_domain=root_domain,
        suspicious_tld=suspicious_tld,
        young_domain_flag=young_domain,
        whois_failed=whois_failed,
    )

    _cache_set(root_domain, result.__dict__ if hasattr(result, '__dict__') else dict(result))
    return result