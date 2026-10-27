"""
risk_aggregator.py — Deterministic rule-based decision engine.

Scoring model mirrors the original scoring.py logic:
  - Start from 0, accumulate penalty points
  - Threshold >= 3 → malicious, else safe

Old system penalty mapping (VirusTotal removed, rest preserved):
  SSL_MISSING    4.0  →  ssl_failed + login_form          +4
  AGE_NEW_RISK   5.0  →  young_domain + risky context     +3
  AGE_NEW_SAFE   1.5  →  young_domain alone               +1
  TRAP_HIDDEN    6.0  →  hidden_form_flag                 +4
  TRAP_LOGIN_NEW 1.5  →  login on young domain            +2
  AI_MALICIOUS   5.0  →  brand_domain_mismatch            +5
  AI_HIGH_CONF   2.0  →  brand_in_content (no mismatch)  +1
"""

from .schemas import Tier3Result, RedirectSignals, DomainSignals, SSLSignals, HTMLSignals

_MALICIOUS_THRESHOLD = 3


def aggregate_risk(
    url: str,
    redirect: RedirectSignals,
    domain: DomainSignals,
    ssl: SSLSignals,
    html: HTMLSignals,
) -> Tier3Result:
    """
    Deterministic risk scoring over aggregated forensic signals.
    Final decision: "malicious" (score >= 3) or "safe" (score < 3).
    """
    score = 0
    signals_triggered: list[str] = []

    def fire(points: int, reason: str) -> None:
        nonlocal score
        score += points
        signals_triggered.append(reason)

    # ── SSL CHECK (old: SSL_MISSING = 4.0) ────────────────────────────────────
    # Only penalise when there is a login page — plain HTTP sites without
    # login forms are not suspicious (e.g. neverssl.com).
    if getattr(ssl, "ssl_failed", False) and html.login_form_detected:
        fire(4, "No SSL on a login page (credentials sent unencrypted)")

    if getattr(ssl, "self_signed", False):
        fire(3, "Self-signed SSL certificate")

    if getattr(ssl, "cn_mismatch", False):
        fire(2, "SSL certificate CN/SAN does not match hostname")

    expiry = getattr(ssl, "ssl_expiry_days", None)
    if expiry is not None and 0 < expiry <= 7:
        fire(2, f"SSL certificate expires in {expiry} day(s)")

    # ── DOMAIN AGE (old: AGE_NEW_RISK=5.0, AGE_NEW_SAFE=1.5) ─────────────────
    if domain.young_domain_flag:
        if html.login_form_detected or getattr(html, "server_blocked_scan", False):
            fire(3, "Young domain (< 30 days) with login page or evasion")
        else:
            fire(1, "Young domain (< 30 days)")

    # ── HIDDEN TRAPS (old: TRAP_HIDDEN = 6.0) ─────────────────────────────────
    if html.hidden_form_flag:
        fire(4, "Hidden sensitive input fields detected (data theft risk)")

    # ── BRAND IMPERSONATION (old: AI_MALICIOUS = 5.0) ─────────────────────────
    if html.login_form_detected and html.brand_domain_mismatch:
        fire(5, "Brand mismatch on login form")
    elif html.brand_domain_mismatch:
        fire(4, "Brand name in URL/content on unauthorized domain")

    # ── LOGIN ON NEW DOMAIN (old: TRAP_LOGIN_NEW = 1.5) ───────────────────────
    if html.login_form_detected and domain.young_domain_flag:
        fire(2, "Login page on a brand new domain")

    # ── FORM ACTION ───────────────────────────────────────────────────────────
    if html.external_form_action:
        fire(3, "Login form submits to external domain")

    # ── EVASION / OBFUSCATION ─────────────────────────────────────────────────
    # FIX: JS obfuscation is common on legitimate sites (minification, analytics).
    # Only score when ALSO on a login page with a brand/domain mismatch —
    # prevents false positives on Google, Microsoft etc. that minify their JS.
    if (getattr(html, "js_obfuscation_detected", False)
            and html.login_form_detected
            and html.brand_domain_mismatch):
        fire(3, "JavaScript obfuscation on mismatched login page")

    if getattr(html, "server_blocked_scan", False) and html.login_form_detected:
        fire(2, "Server blocked forensic scanner on login page")

    if getattr(html, "meta_refresh_redirect", False):
        fire(1, "Meta-refresh redirect detected")

    # ── REDIRECT EVASION ──────────────────────────────────────────────────────
    if getattr(redirect, "shortener_detected", False):
        fire(2, "URL shortener used in redirect chain")

    # FIX: Excessive hops within the same domain is normal (OAuth, SSO flows).
    # Only penalise if the domain actually changed during the chain.
    if redirect.excessive_redirect_flag and getattr(redirect, "domain_changes", 0) > 0:
        fire(1, "Excessive redirect chain with domain changes")

    if getattr(redirect, "domain_changes", 0) >= 2:
        fire(2, f"Multi-domain redirect ({redirect.domain_changes} domain changes)")

    # ── INFRASTRUCTURE ────────────────────────────────────────────────────────
    if getattr(domain, "is_ip_address", False):
        fire(2, "Host is a bare IP address")

    if domain.suspicious_tld:
        tld = getattr(domain, "tld", "") or domain.root_domain.rsplit(".", 1)[-1]
        fire(1, f"Suspicious TLD: .{tld}")

    if getattr(ssl, "is_shared_cloud", False) and html.login_form_detected:
        fire(1, "Anonymous DV cert (cloud proxy) on login page")

    # Only score external resource ratio when brand mismatch is present —
    # legitimate sites like GitHub load from their own CDN subdomains which
    # may appear "external" to the html_analyzer's simple domain comparison.
    if getattr(html, "high_external_resource_ratio", False) and html.brand_domain_mismatch:
        fire(1, "Login page loads majority of assets from external domains")

    # WHOIS failure only as tie-breaker
    if domain.whois_failed and score >= 2:
        fire(1, "WHOIS/RDAP lookup failed (domain age unverifiable)")

    # ── Final decision ─────────────────────────────────────────────────────────
    final_decision = "malicious" if score >= _MALICIOUS_THRESHOLD else "safe"

    return Tier3Result(
        url=url,
        final_decision=final_decision,
        risk_score=score,
        signals_triggered=signals_triggered,
    )