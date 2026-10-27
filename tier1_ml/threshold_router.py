"""
threshold_router.py — Tier-1 routing logic.

Tier-1 has ONE job: resolve clearly safe URLs fast.
It NEVER resolves malicious — it lacks forensic depth to make that call.

  prob < T_SAFE  → resolve SAFE at Tier-1    (5ms, user not kept waiting)
  anything else  → escalate to Tier-3        (4-8 sec, full forensic verdict)

Tier-2 (blacklist RAM) intercepts known-bad URLs in 1ms before Tier-3 runs.
Tier-3 makes ALL malicious decisions — every verdict has real evidence behind it.
"""

from config import Config


def route_traffic(url: str, phishing_prob: float, feature_vector_flat: list) -> dict:
    """
    Applies deterministic overrides then routes the URL.
    Returns a routing instruction dictionary consumed by worker.py.
    """
    # 1. Deterministic overrides (Feature 10 = TLD, Feature 15 = Brand Mismatch)
    # Push borderline-safe URLs into escalation territory if structural red flags exist.
    has_suspicious_tld = (feature_vector_flat[10] == 1)
    has_brand_mismatch = (feature_vector_flat[15] == 1)

    if has_suspicious_tld or has_brand_mismatch:
        phishing_prob = max(phishing_prob, 0.50)

    # 2. Routing — safe filter only
    if phishing_prob < Config.T_SAFE:
        # High confidence the URL is clean — resolve immediately, no Tier-3 needed
        return {
            "action":     "resolve",
            "tier":       1,
            "prediction": "safe",
            "confidence": round((1.0 - phishing_prob) * 100, 2),
            "reason":     "Prob < T_SAFE — resolved safe at Tier-1"
        }

    # Everything else escalates — uncertain, suspicious, or high-probability malicious.
    # Tier-3 forensics makes the final call with full evidence.
    return {
        "action":       "escalate",
        "tier":         3,
        "prediction":   "unknown",
        "current_prob": round(phishing_prob, 4),
        "reason":       "Escalated to Tier-3 for forensic verification"
    }