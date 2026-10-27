"""
domain_normalizer.py — URL normalization and blacklist lookup variation generator.

Tier-2 responsibility (ONLY):
  • Normalize a raw URL into a canonical form
  • Generate all domain variations to check against the blacklist
    (subdomains, path-included keys, embedded redirect targets)

No risk scoring. No analysis. No decisions.
All thinking is done by Tier-1 and Tier-3.
"""

from urllib.parse import urlparse, parse_qs, unquote
import re

# Redirect parameter names whose values may contain an embedded target domain
_REDIRECT_PARAMS = frozenset({
    "redirect", "url", "next", "target",
    "dest", "destination", "redir", "return"
})


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure URL has a scheme so urlparse works correctly."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _extract_domain_variations(domain: str) -> set:
    """
    Generate all suffix-progressions of a domain for blacklist matching.
    e.g. a.b.evil.com → {a.b.evil.com, b.evil.com, evil.com}
    Ensures a blacklist entry for "evil.com" catches all its subdomains.
    """
    variations = set()
    parts = domain.split(".")
    while len(parts) >= 2:
        variations.add(".".join(parts))
        parts.pop(0)
    return variations


def _extract_embedded_domains(value: str) -> set:
    """
    Extract the destination domain from a redirect parameter value.
    e.g. ?redirect=http://evil.com/steal → {"evil.com"}
    """
    domains = set()
    try:
        decoded = unquote(value)
        if decoded.startswith(("http://", "https://")):
            parsed = urlparse(decoded)
            if parsed.netloc:
                domains.add(parsed.netloc.lower())
        elif re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", decoded):
            domains.add(decoded.lower())
    except Exception:
        pass
    return domains


# ── Public API ─────────────────────────────────────────────────────────────────

def get_lookup_variations(url: str) -> list:
    """
    Generate all string variations to check against the Tier-2 blacklist.

    Covers three attack surfaces:
      1. Domain + all subdomains   (evil.com catches login.evil.com)
      2. Domain + path             (evil.com/phish listed as full path)
      3. Embedded redirect targets (?redirect=http://evil.com → checks evil.com)
    """
    variations = set()

    try:
        url    = normalize_url(url)
        parsed = urlparse(url)

        domain = parsed.netloc.split(":")[0].lower()
        path   = parsed.path.lower()
        query  = parse_qs(parsed.query)

        # 1. Domain suffix variations
        if domain:
            variations.update(_extract_domain_variations(domain))

        # 2. Domain + path (for path-specific blacklist entries)
        if domain and path and path != "/":
            variations.add(f"{domain}{path}")

        # 3. Domains embedded inside redirect parameters
        for key, values in query.items():
            if key.lower() in _REDIRECT_PARAMS:
                for value in values:
                    variations.update(_extract_embedded_domains(value))

    except Exception:
        pass

    return list(variations)