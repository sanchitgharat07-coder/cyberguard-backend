import ssl
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import certifi

from .schemas import SSLSignals

# ── TLS context — one per process ─────────────────────────────────────────────
# check_hostname=False / CERT_NONE so we can read metadata even from
# self-signed or mismatched certs without raising before we can inspect them.

_CTX = ssl.create_default_context(cafile=certifi.where())
_CTX.check_hostname = False
_CTX.verify_mode    = ssl.CERT_NONE

_SSL_TIMEOUT_S = 1.0   # hard wall — must not block the main analysis pipeline

# ── Cloud / proxy issuer keywords (ported from original forensics.py) ─────────
# These CAs issue anonymous DV certs to anyone. When the Subject has no Org
# AND the issuer is one of these → the site is hiding behind a shared proxy.

_CLOUD_ISSUER_KEYWORDS = frozenset({
    "cloudflare",
    "let's encrypt",
    "letsencrypt",
    "cpanel",
    "fastly",
    "amazon",
    "aws",
    "digicert",
    "sectigo",
    "comodo",
    "godaddy",
    "google trust services",
    "zerossl",
    "buypass",
})

# ── Helpers ───────────────────────────────────────────────────────────────────

def _flatten(raw: tuple) -> dict:
    """Convert Python ssl's nested issuer/subject tuples into a flat dict."""
    result = {}
    for entry in raw:
        for pair in entry:
            if isinstance(pair, (tuple, list)) and len(pair) == 2:
                result[pair[0]] = pair[1]
    return result


def _cert_covers_host(cert: dict, hostname: str) -> bool:
    """
    True if hostname is covered by the cert's SANs or CN.

    Original code used string containment which gave false negatives on
    wildcard certs and false positives on partial matches
    (e.g. 'evil-paypal.com' matching 'paypal.com').
    This version does proper wildcard expansion.
    """
    hostname = hostname.lower()
    names: list[str] = []

    # SANs are the authoritative source (RFC 6125 — CN is legacy fallback only)
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            names.append(san_value.lower())

    # Fallback to CN only when no SANs exist
    if not names:
        subject = _flatten(cert.get("subject", ()))
        cn = subject.get("commonName", "")
        if cn:
            names.append(cn.lower())

    for name in names:
        if name == hostname:
            return True
        # Wildcard: *.example.com covers login.example.com but NOT example.com
        if name.startswith("*."):
            pattern_root = name[2:]                    # "example.com"
            parts        = hostname.split(".", 1)
            if len(parts) == 2 and parts[1] == pattern_root:
                return True

    return False


def _parse_expiry(cert: dict) -> Optional[int]:
    """Days until cert expiry, or None if the field is absent / unparsable."""
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    try:
        # Python ssl module returns e.g. "Jun 15 12:00:00 2025 GMT"
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        return (dt - datetime.now(timezone.utc)).days
    except ValueError:
        return None


# ── Public API ─────────────────────────────────────────────────────────────────

def inspect_ssl(url: str) -> SSLSignals:
    """
    Fetches and inspects SSL certificate metadata.
    Enforces a strict 1.0s timeout. Soft-fails on any connection error.

    Smart classification (ported from forensics.py, extended):

      ssl_valid = True always if the handshake succeeds, even for bad certs —
      we want to inspect the metadata, not enforce trust here.

      self_signed      — issuer dict == subject dict
      cn_mismatch      — hostname not covered by any SAN or CN (fixed wildcard logic)
      is_shared_cloud  — no Subject Org + issuer is a known cloud/CDN CA
                         (anonymous DV cert behind a proxy — original forensics.py signal)
      ssl_expiry_days  — days remaining; negative = already expired
      ssl_failed       — port 443 closed, timeout, or handshake error
    """
    signals = SSLSignals()

    try:
        parsed = urlparse(url if url.startswith(("http", "https")) else "http://" + url)
        domain = parsed.netloc.split(":")[0].lower()

        if not domain:
            return signals

        with socket.create_connection((domain, 443), timeout=_SSL_TIMEOUT_S) as sock:
            with _CTX.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=False)

                if not cert:
                    signals.ssl_failed = True
                    return signals

                signals.ssl_valid = True

                # ── Extract issuer / subject ───────────────────────────────────
                issuer_dict  = _flatten(cert.get("issuer",  ()))
                subject_dict = _flatten(cert.get("subject", ()))

                issuer_org = issuer_dict.get("organizationName", "")
                issuer_cn  = issuer_dict.get("commonName",       "")
                subject_org = subject_dict.get("organizationName", "")

                signals.issuer = issuer_org or issuer_cn or "Unknown"

                # ── Self-signed: issuer == subject ─────────────────────────────
                if issuer_dict == subject_dict:
                    signals.self_signed = True

                # ── CN / SAN mismatch (fixed wildcard logic) ───────────────────
                if not _cert_covers_host(cert, domain):
                    signals.cn_mismatch = True

                # ── Smart proxy / cloud detection (from forensics.py) ──────────
                issuer_str      = (issuer_org + " " + issuer_cn).lower()
                is_cloud_issuer = any(k in issuer_str for k in _CLOUD_ISSUER_KEYWORDS)

                if subject_org:
                    # OV / EV cert — verified identity, never a blind proxy
                    signals.is_shared_cloud = False
                else:
                    # No Subject Org (DV cert) + cloud issuer = anonymous proxy
                    signals.is_shared_cloud = is_cloud_issuer

                # ── Certificate expiry ─────────────────────────────────────────
                signals.ssl_expiry_days = _parse_expiry(cert)

    except Exception:
        # Port 443 closed, timeout, handshake failure, or bad cert chain
        signals.ssl_failed = True

    return signals