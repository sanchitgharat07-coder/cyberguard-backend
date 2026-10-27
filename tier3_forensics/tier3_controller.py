import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .schemas import Tier3Result, HTMLSignals
from .http_fetcher import fetch_url
from .redirect_analyzer import analyze_redirects
from .domain_analyzer import analyze_domain
from .ssl_inspector import inspect_ssl
from .html_analyzer import analyze_html
from .risk_aggregator import aggregate_risk


def run_tier3(url: str) -> Tier3Result:
    """
    Orchestrates the Tier-3 forensic pipeline.

    Execution order:
      1. Normalize URL
      2. HTTP fetch  (sequential — everything else depends on final_url)
      3. domain + SSL run IN PARALLEL  (both are network-bound, independent)
      4. redirect + HTML run while 3 is in flight  (both are CPU-bound / instant)
      5. Aggregate all signals → deterministic decision

    Soft-fail guarantee:
      Every stage is wrapped; a crash in any single module never propagates.
      On total failure returns Tier3Result with final_decision="safe", score=0,
      analysis_status="error" so app.py always gets a parseable object.
    """
    t_start = time.perf_counter()

    # ── 1. Normalize ──────────────────────────────────────────────────────────
    target_url = url if url.startswith(("http://", "https://")) else "http://" + url

    # ── 2. HTTP Fetch ─────────────────────────────────────────────────────────
    # Everything downstream depends on final_url, so this must be sequential.
    try:
        fetch_result = fetch_url(target_url)
    except Exception as exc:
        return _error_result(target_url, target_url, t_start, str(exc))

    # CRITICAL: analyze the DESTINATION, not the entry point.
    # If bit.ly/abc → phishing.com, we must inspect phishing.com.
    analysis_url = (
        fetch_result.final_url
        if (fetch_result.success and fetch_result.final_url)
        else target_url
    )

    # If fetch succeeded over HTTPS, the site clearly has valid SSL.
    # ssl_inspector may have timed out separately (firewall, rate-limit).
    # Trust the fetch result over the direct socket probe in this case.
    # success=True means the TCP+TLS handshake completed — HTTPS is working.
    # Status code (200, 403, 302 etc.) is an application-layer response,
    # not evidence of missing SSL. Override ssl_failed if fetch succeeded.
    _fetch_https_ok = (
        fetch_result.success
        and analysis_url.startswith("https://")
    )

    # ── 3 + 4. Parallel signal collection ────────────────────────────────────
    # domain_analyzer and ssl_inspector both open network sockets — run them
    # together so their timeouts overlap instead of stacking.
    # redirect_analyzer and html_analyzer are pure-CPU — submitted at the same
    # time so they execute during the network wait at zero extra latency cost.

    redirect_info = HTMLSignals()   # placeholders in case of exception
    html_info     = HTMLSignals()
    domain_info   = None
    ssl_info      = None

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            f_redirect = pool.submit(analyze_redirects, fetch_result.redirect_chain)
            f_domain   = pool.submit(analyze_domain,   analysis_url)
            f_ssl      = pool.submit(inspect_ssl,      analysis_url)
            f_html     = pool.submit(
                analyze_html,
                fetch_result.html_content if (fetch_result.success and fetch_result.html_content) else "",
                analysis_url,
                fetch_result.status_code or 0,
            )

            # Collect results — each wrapped individually so one failure
            # doesn't discard the others.
            try:
                redirect_info = f_redirect.result()
            except Exception:
                from .schemas import RedirectSignals
                redirect_info = RedirectSignals()

            try:
                domain_info = f_domain.result()
            except Exception:
                from .schemas import DomainSignals
                domain_info = DomainSignals()

            try:
                ssl_info = f_ssl.result()
            except Exception:
                from .schemas import SSLSignals
                ssl_info = SSLSignals()

            try:
                html_info = f_html.result()
            except Exception:
                html_info = HTMLSignals()   # all fields default False — safe fallback

    except Exception as exc:
        return _error_result(target_url, analysis_url, t_start, str(exc))

    # ── 5. Override ssl_failed if fetch confirmed HTTPS is working ───────────
    # Prevents false positive when our SSL socket probe times out but the
    # site is clearly serving HTTPS (fetch returned 200 over https://).
    if _fetch_https_ok and getattr(ssl_info, "ssl_failed", False):
        ssl_info.ssl_failed    = False
        ssl_info.ssl_valid     = True

    # ── 6. Risk aggregation ───────────────────────────────────────────────────
    try:
        tier3_result = aggregate_risk(
            url=analysis_url,
            redirect=redirect_info,
            domain=domain_info,
            ssl=ssl_info,
            html=html_info,
        )
    except Exception as exc:
        return _error_result(target_url, analysis_url, t_start, str(exc))

    # ── DEBUG — remove before production ─────────────────────────────────────
    print(f"🔬 [DEBUG] fetch: status={fetch_result.status_code} success={fetch_result.success} error={fetch_result.error_message}")
    print(f"🔬 [DEBUG] domain: {domain_info}")
    print(f"🔬 [DEBUG] ssl:    {ssl_info}")
    print(f"🔬 [DEBUG] redirect: {redirect_info}")
    print(f"🔬 [DEBUG] html signals: {html_info} | score: {tier3_result.risk_score} | decision: {tier3_result.final_decision}")

    # ── Metadata ──────────────────────────────────────────────────────────────
    tier3_result.metadata = {
        "fetch_success":    fetch_result.success,
        "response_time_ms": round(fetch_result.response_time_ms, 2),
        "total_time_ms":    round((time.perf_counter() - t_start) * 1000, 2),
        "fetch_error":      fetch_result.error_message,
        "requested_url":    target_url,
        "effective_url":    analysis_url,
        "status_code":      fetch_result.status_code,
    }

    return tier3_result


# ── Internal helper ───────────────────────────────────────────────────────────

def _error_result(
    requested_url: str,
    effective_url: str,
    t_start: float,
    error: str,
) -> Tier3Result:
    """
    Returns a safe, fully-structured Tier3Result on total pipeline failure.
    app.py can always call .to_dict() on this without crashing.
    """
    return Tier3Result(
        url=effective_url,
        final_decision="safe",
        risk_score=0,
        signals_triggered=[],
        metadata={
            "fetch_success":    False,
            "response_time_ms": 0.0,
            "total_time_ms":    round((time.perf_counter() - t_start) * 1000, 2),
            "fetch_error":      error,
            "requested_url":    requested_url,
            "effective_url":    effective_url,
            "status_code":      0,
        },
    )