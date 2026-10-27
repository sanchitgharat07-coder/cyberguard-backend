from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re

from .schemas import HTMLSignals

# ── KEEP brand map only as a high-confidence fast-path ────────────────────────
# This is NOT the primary detection mechanism anymore.
# Primary detection is now fully dynamic (see _check_brand_mismatch_dynamic).
# Only add entries here for brands with ambiguous names that the dynamic
# engine might miss (e.g. "ups" would match too many innocent words).

# Values are SETS of all authorized domains for that brand.
# A page is only flagged as mismatch if the current domain matches
# NONE of the authorized domains.
# e.g. Microsoft owns both microsoft.com AND microsoftonline.com —
# both must be listed or microsoftonline.com triggers a false positive.
BRAND_MAP = {
    "paypal":        {"paypal.com", "paypalobjects.com"},
    "google":        {"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "google.co.in"},
    "microsoft":     {"microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "azure.com"},
    "apple":         {"apple.com", "icloud.com", "appleid.apple.com"},
    "amazon":        {"amazon.com", "amazonaws.com", "amazon.in", "amazon.co.uk"},
    "facebook":      {"facebook.com", "meta.com", "fb.com"},
    "instagram":     {"instagram.com"},
    "linkedin":      {"linkedin.com"},
    "dropbox":       {"dropbox.com", "dropboxstatic.com"},
    "netflix":       {"netflix.com", "nflximg.net"},
    "twitter":       {"twitter.com", "x.com", "t.co"},
    "whatsapp":      {"whatsapp.com", "whatsapp.net"},
    "binance":       {"binance.com", "binance.us"},
    "coinbase":      {"coinbase.com", "coinbase.net"},
    "kucoin":        {"kucoin.com"},
    "kraken":        {"kraken.com"},
    "bybit":         {"bybit.com"},
    "exodus":        {"exodus.com"},
    "metamask":      {"metamask.io"},
    "trustwallet":   {"trustwallet.com"},
    "phantom":       {"phantom.app"},
    "ledger":        {"ledger.com"},
    "trezor":        {"trezor.io"},
    "chase":         {"chase.com", "jpmchase.com"},
    "wellsfargo":    {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com", "bac.com"},
    "unicamp":       {"unicamp.br"},
    "steam":         {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "roblox":        {"roblox.com", "rbxcdn.com"},
    "fedex":         {"fedex.com"},
}

# ── FREE HOSTING PLATFORMS ────────────────────────────────────────────────────
# Real brands with their own domain NEVER host on these platforms.
# If a page claims to be a bank / wallet / exchange but lives here → fake.
# This list is stable — new phishing sites appear daily but the platforms
# they abuse are the same ~20 services.

FREE_HOSTING_PLATFORMS = frozenset({
    "ghost.io", "ukit.me", "wix.com", "wixsite.com", "weebly.com",
    "webflow.io", "squarespace.com", "wordpress.com", "blogspot.com",
    "tumblr.com", "sites.google.com", "glitch.me", "netlify.app",
    "vercel.app", "github.io", "gitlab.io", "pages.dev",
    "firebaseapp.com", "web.app", "000webhostapp.com",
    "byethost.com", "infinityfreeapp.com", "epizy.com",
})

# ── STOP WORDS — ignored when extracting claimed brand name ──────────────────
# Common words that appear in titles but are not brand names.
_STOP_WORDS = frozenset({
    "the", "a", "an", "and", "or", "of", "to", "in", "for", "on",
    "with", "your", "our", "is", "are", "how", "all", "one", "new",
    "web3", "web", "app", "wallet", "login", "sign", "secure", "official",
    "platform", "portal", "account", "access", "crypto", "digital",
    "guide", "ultimate", "complete", "best", "top", "review", "log",
    "exchange", "trading", "defi", "nft", "blockchain", "token",
    "management", "support", "help", "service", "online", "free",
})

# Minimum length for a word to be considered a brand name candidate
_MIN_BRAND_WORD_LEN = 4

# "token" and "secret" removed — CSRF tokens use these names legitimately
# (e.g. GitHub's authenticity_token, Laravel's _token).
# Data theft is caught by cc/cvv/ssn/pin/otp which are never CSRF-related.
_SENSITIVE_FIELD_NAMES = re.compile(
    r"(pass|password|pwd|card|cc|cvv|cvc|ssn|pin|otp)",
    re.IGNORECASE,
)

_OBFUSCATION_PATTERNS = re.compile(
    r"(eval\s*\(|atob\s*\(|unescape\s*\(|fromCharCode\s*\()",
    re.IGNORECASE,
)

# URL path patterns that strongly indicate a login page — no HTML needed.
# "giris" = login/entry in Turkish; covers common phishing kits in any language.
_LOGIN_PATH_PATTERNS = re.compile(
    r"/(giris|login|signin|sign-in|log-in|logon|auth|authenticate"
    r"|account|portal|secure|member|kullanici|uye-giris)(\.|/|$)",
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _etld1(domain: str) -> str:
    """Return eTLD+1 from a netloc string (simple parts[-2].parts[-1])."""
    parts = domain.split(".")
    return f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else domain


def _is_free_hosting(domain: str) -> bool:
    """True if the domain is or is a subdomain of a known free hosting platform."""
    for platform in FREE_HOSTING_PLATFORMS:
        if domain == platform or domain.endswith("." + platform):
            return True
    return False


def _is_external(action_url: str, page_domain: str) -> bool:
    if not action_url or not action_url.startswith("http"):
        return False
    return _extract_domain(action_url) not in ("", page_domain)


def _extract_claimed_name(soup, url_lower: str) -> str:
    """
    Dynamically extract what name/brand this page CLAIMS to be.

    Priority order (most → least reliable):
      1. og:site_name  — explicitly set by the site author
      2. <title>       — usually "Brand | tagline" or "Brand - page"
      3. <h1>          — largest heading, often the product/brand name
      4. URL path      — last resort, slugs often contain the brand name
    """
    # 1. OpenGraph site name — most explicit
    og = soup.find("meta", property="og:site_name")
    if og and og.get("content", "").strip():
        return og["content"].strip()

    # 2. Page title — take the first segment before " | ", " - ", " : "
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
        for sep in [" | ", " - ", " : ", " — ", " – "]:
            if sep in title:
                return title.split(sep)[0].strip()
        return title

    # 3. First h1
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(" ", strip=True)

    # 4. URL path slug (e.g. /exodus-enweb/ → "exodus enweb")
    try:
        path = urlparse(url_lower).path.strip("/").split("/")[-1]
        return path.replace("-", " ").replace("_", " ")
    except Exception:
        return ""


def _words(text: str) -> list[str]:
    """Lowercase alphabetic words from a string, stop-words removed."""
    return [
        w for w in re.findall(r"[a-z]{%d,}" % _MIN_BRAND_WORD_LEN, text.lower())
        if w not in _STOP_WORDS
    ]


def _claimed_name_matches_domain(claimed_name: str, domain: str) -> bool:
    """
    True if the claimed brand name is plausibly represented in the domain.

    Logic: at least one meaningful word from the claimed name must appear
    as a substring in the domain's eTLD+1.

    e.g.  "Exodus Web3 Wallet" → words = ["exodus", "wallet"]
          domain = "intro-platform.ghost.io" → etld1 = "ghost.io"
          "exodus" not in "ghost.io" AND "wallet" not in "ghost.io" → False → MISMATCH
    """
    etld1 = _etld1(domain)
    for word in _words(claimed_name):
        if word in etld1:
            return True
    return False


# ── Dynamic brand mismatch detection ──────────────────────────────────────────

def _check_brand_mismatch_dynamic(
    soup,
    domain: str,
    url_lower: str,
) -> tuple[bool, bool]:
    """
    Detects brand impersonation without any hardcoded brand list.

    Returns: (brand_in_content, brand_domain_mismatch)

    Two independent signals fire mismatch:

    Signal A — Free-hosting incongruence:
      The page's claimed name has meaningful words that don't appear in the
      domain, AND the domain is a known free hosting platform.
      Rationale: ghost.io / ukit.me hosting a page that claims to be
      "Exodus Wallet" or "KuCoin Exchange" is always impersonation.

    Signal B — Claimed name vs domain token mismatch:
      Even on non-free-hosting domains, if a page title says "PayPal Login"
      but the domain is "secure-payments-verify.com", the brand words
      ("paypal", "login") don't appear in the domain → mismatch.
    """
    claimed_name = _extract_claimed_name(soup, url_lower)
    if not claimed_name or len(claimed_name) < 3:
        return False, False

    brand_words = _words(claimed_name)
    if not brand_words:
        return False, False

    name_matches_domain = _claimed_name_matches_domain(claimed_name, domain)
    on_free_host        = _is_free_hosting(domain)

    brand_in_content    = True   # we found a claimed name — something is there
    brand_mismatch      = False

    if not name_matches_domain:
        if on_free_host:
            # High confidence: real brand would never be on this host
            brand_mismatch = True
        else:
            # Medium confidence: name doesn't match domain on unknown host
            # Only flag if the claimed name looks like a real product/service
            # (i.e. has at least one word ≥ 5 chars — filters out generic titles)
            if any(len(w) >= 5 for w in brand_words):
                brand_mismatch = True

    return brand_in_content, brand_mismatch


# ── Public API ─────────────────────────────────────────────────────────────────

def analyze_html(html_content: str, final_url: str, status_code: int = 200) -> HTMLSignals:
    """
    Performs deep static inspection of HTML content relative to the final URL.
    Returns HTMLSignals dataclass — consumed directly by risk_aggregator.

    Brand mismatch detection is now fully dynamic:
      - No manual brand list needed for new brands
      - Catches any impersonation based on page content vs domain logic
      - Static BRAND_MAP kept only as a fast-path for known ambiguous names
    """
    signals   = HTMLSignals()
    domain    = _extract_domain(final_url)
    url_lower = final_url.lower()

    # ── 1A. STATIC BRAND CHECK — URL only, no HTML needed ────────────────────
    # Fast-path for the known-brand list. Runs before html_content guard
    # so an empty fetch still catches brands visible in the URL.
    for brand, authorized_domains in BRAND_MAP.items():
        if brand in url_lower:
            signals.brand_in_content = True
            if not any(auth in domain for auth in authorized_domains):
                signals.brand_domain_mismatch = True
            break

    # ── 1B. URL PATH LOGIN DETECTION — no HTML needed ───────────────────────
    # Detects login pages from URL path alone when fetch returned no HTML.
    # e.g. /giris.php, /login.php, /signin on any domain without HTML evidence.
    if not signals.login_form_detected:
        try:
            path = urlparse(final_url).path
            if _LOGIN_PATH_PATTERNS.search(path):
                signals.login_form_detected = True
        except Exception:
            pass

    # ── 1C. BOT-BLOCKING SIGNAL ──────────────────────────────────────────────
    # A site that returns 403/503 to our scanner is actively hiding its content.
    # Legitimate sites (banks, gov portals) don't block neutral UA scanners.
    # Only meaningful when combined with other signals (login path, young domain).
    # -3 = SSL error, -4 = connection refused (sentinels from http_fetcher)
    # Only flag bot-blocking on domains NOT in TRUSTED_ROOTS.
    # PayPal, Google etc. legitimately return 403 to scanner user-agents —
    # flagging them would cause false positives on every major brand.
    if status_code in (403, 503, 429, -3, -4):
        try:
            from tier1_ml.threshold_router import TRUSTED_ROOTS
            _etld1 = lambda u: ".".join(u.split(".")[-2:]) if u.count(".") >= 1 else u
            _netloc = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(final_url).netloc.lower().split(":")[0]
            if _etld1(_netloc) not in TRUSTED_ROOTS:
                signals.server_blocked_scan = True
        except Exception:
            signals.server_blocked_scan = True

    # ── HTML-dependent checks ─────────────────────────────────────────────────
    if not html_content:
        return signals

    soup = BeautifulSoup(html_content, "html.parser")

    # ── 1B. STATIC BRAND CHECK — HTML content ────────────────────────────────
    if not signals.brand_domain_mismatch:
        page_title = (soup.title.string or "").lower() if soup.title else ""
        headings   = " ".join(
            t.get_text(" ", strip=True).lower()
            for t in soup.find_all(["h1", "h2"])
        )
        for brand, authorized_domains in BRAND_MAP.items():
            if brand in page_title or brand in headings:
                signals.brand_in_content = True
                if not any(auth in domain for auth in authorized_domains):
                    signals.brand_domain_mismatch = True
                break

    # ── 1C. DYNAMIC BRAND CHECK — catches anything not in BRAND_MAP ──────────
    # This is the scalable engine. No manual additions ever needed.
    if not signals.brand_domain_mismatch:
        dyn_found, dyn_mismatch = _check_brand_mismatch_dynamic(
            soup, domain, url_lower
        )
        if dyn_found:
            signals.brand_in_content = True
        if dyn_mismatch:
            signals.brand_domain_mismatch = True

    # ── 2. FORM & INPUT ANALYSIS ──────────────────────────────────────────────
    forms           = soup.find_all("form")
    password_fields = soup.find_all("input", {"type": "password"})

    if password_fields:
        signals.login_form_detected = True

        for form in forms:
            action = form.get("action", "")
            if action and not action.startswith("http"):
                action = urljoin(final_url, action)
            if _is_external(action, domain):
                signals.external_form_action = True
                break

    # ── 3. HIDDEN TRAPS ───────────────────────────────────────────────────────
    for inp in soup.find_all("input"):
        field_type  = (inp.get("type") or "").lower()
        field_style = str(inp.get("style") or "").lower()
        field_name  = str(inp.get("name") or "")

        is_hidden = (
            field_type == "hidden"
            or "display:none"      in field_style
            or "display: none"     in field_style
            or "visibility:hidden" in field_style
        )
        if is_hidden and _SENSITIVE_FIELD_NAMES.search(field_name):
            signals.hidden_form_flag = True
            break

    # ── 4. META-REFRESH REDIRECT ──────────────────────────────────────────────
    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
    if meta_refresh:
        signals.meta_refresh_redirect = True

    # ── 5. JAVASCRIPT OBFUSCATION ─────────────────────────────────────────────
    inline_scripts = " ".join(
        s.get_text() for s in soup.find_all("script") if not s.get("src")
    )
    if _OBFUSCATION_PATTERNS.search(inline_scripts):
        signals.js_obfuscation_detected = True

    # ── 6. HIGH EXTERNAL RESOURCE RATIO (login pages only) ───────────────────
    if signals.login_form_detected:
        all_srcs = [
            tag.get("src") or tag.get("href") or ""
            for tag in soup.find_all(["img", "script", "link"])
        ]
        # Extract root domain (eTLD+1) of the page for comparison
        # so github.githubassets.com is not counted as external to github.com
        try:
            _page_parts = domain.split(".")
            _page_root  = f"{_page_parts[-2]}.{_page_parts[-1]}" if len(_page_parts) >= 2 else domain
        except Exception:
            _page_root = domain

        external_count = sum(
            1 for s in all_srcs
            if s.startswith("http")
            and _extract_domain(s) not in ("", domain)
            and _page_root not in _extract_domain(s)
        )
        ratio = external_count / max(len(all_srcs), 1)
        if ratio > 0.7:
            signals.high_external_resource_ratio = True

    return signals