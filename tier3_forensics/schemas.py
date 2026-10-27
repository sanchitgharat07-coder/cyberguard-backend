from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# ---------------------------------------------------------
# 1. Fetcher Schema
# ---------------------------------------------------------
@dataclass
class FetchResult:
    """Standardized response from the http_fetcher."""
    requested_url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    html_content: Optional[str] = None
    content_type: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    success: bool = False
    error_message: Optional[str] = None

# ---------------------------------------------------------
# 2. Individual Analyzer Signal Schemas
# ---------------------------------------------------------
@dataclass
class RedirectSignals:
    """Output from redirect_analyzer."""
    redirect_count: int = 0
    excessive_redirect_flag: bool = False
    suspicious_routing: bool = False        # e.g. HTTP → HTTPS → different HTTP
    # v2 additions
    domain_changes: int = 0                 # number of eTLD+1 changes across hops
    cross_domain_redirect: bool = False     # any domain change occurred
    shortener_detected: bool = False        # bit.ly / tinyurl etc. in chain

@dataclass
class DomainSignals:
    """Output from domain_analyzer."""
    root_domain: str = ""
    suspicious_tld: bool = False
    young_domain_flag: bool = False
    whois_failed: bool = False
    # v2 additions
    tld: str = ""                           # raw TLD string for aggregator logging
    is_ip_address: bool = False             # host is a bare IP — strong phishing signal

@dataclass
class SSLSignals:
    """Output from ssl_inspector."""
    ssl_valid: bool = False
    self_signed: bool = False
    cn_mismatch: bool = False
    issuer: Optional[str] = None
    ssl_failed: bool = False                # True if port 443 closed or handshake drops
    # v2 additions
    is_shared_cloud: bool = False           # anonymous DV cert from CDN/proxy issuer
    ssl_expiry_days: Optional[int] = None  # days until cert expiry; None = unknown

@dataclass
class HTMLSignals:
    """Output from html_analyzer."""
    login_form_detected: bool = False
    hidden_form_flag: bool = False
    brand_in_content: bool = False
    brand_domain_mismatch: bool = False
    external_form_action: bool = False      # form submits data to a different domain
    # v2 additions
    js_obfuscation_detected: bool = False         # eval / atob / fromCharCode in inline scripts
    meta_refresh_redirect: bool = False           # <meta http-equiv="refresh"> present
    high_external_resource_ratio: bool = False    # >70% of assets load from foreign domains
    server_blocked_scan: bool = False             # site returned 403/503 to our scanner

# ---------------------------------------------------------
# 3. Final Aggregation Schema
# ---------------------------------------------------------
@dataclass
class Tier3Result:
    """
    The final, deterministic output returned to the main worker.
    Strictly structured to ensure app.py never crashes parsing it.
    """
    url: str
    final_decision: str  # STRICTLY: "malicious" or "safe"
    risk_score: int
    signals_triggered: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Utility to easily serialize the result for JSON API responses."""
        return {
            "url": self.url,
            "final_decision": self.final_decision,
            "risk_score": self.risk_score,
            "signals_triggered": self.signals_triggered,
            "metadata": self.metadata,
        }