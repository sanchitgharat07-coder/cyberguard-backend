"""
tier3_live_eval.py  —  v2
Signal names corrected to match risk_aggregator.py output strings.
Run from backend root: python tier3_live_eval.py
"""

import time
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed

from tier3_forensics.tier3_controller import run_tier3

# ── Configuration ─────────────────────────────────────────────────
SAMPLE_CSV  = "phishtank_sample_200.csv"
OUTPUT_CSV  = "tier3_eval_results.csv"
MAX_WORKERS = 5

# ── Signal map: paper label → substring to match in signals_triggered
# Built directly from risk_aggregator.py fire() calls
SIGNAL_MAP = {
    "SSL Anomaly (no SSL + login)":       "No SSL on a login page",
    "Self-Signed Certificate":            "Self-signed SSL",
    "SSL CN Mismatch":                    "SSL certificate CN/SAN",
    "SSL Expiry Critical":                "SSL certificate expires",
    "Young Domain (high risk)":           "Young domain (< 30 days) with login",
    "Young Domain (low risk)":            "Young domain (< 30 days)",
    "Hidden Form Fields":                 "Hidden sensitive input",
    "Brand Mismatch on Login":            "Brand mismatch on login form",
    "Brand Mismatch (no login)":          "Brand name in URL/content",
    "Login on New Domain":                "Login page on a brand new domain",
    "External Form Action":               "Login form submits to external",
    "JS Obfuscation + Mismatch":          "JavaScript obfuscation on mismatched",
    "Scanner Blocked on Login":           "Server blocked forensic scanner",
    "Meta-Refresh Redirect":              "Meta-refresh redirect",
    "URL Shortener in Chain":             "URL shortener used",
    "Excessive Redirects + Domain Change":"Excessive redirect chain",
    "Multi-Domain Redirect":              "Multi-domain redirect",
    "Bare IP Address":                    "Host is a bare IP",
    "Suspicious TLD":                     "Suspicious TLD",
    "External Resource Ratio":            "Login page loads majority",
    "WHOIS Failed (tie-breaker)":         "WHOIS/RDAP lookup failed",
}


def evaluate_single(row):
    url = row["url"]
    t_start = time.perf_counter()

    try:
        result   = run_tier3(url)
        elapsed  = round((time.perf_counter() - t_start) * 1000, 2)
        fetch_ok = result.metadata.get("fetch_success", False)
        decision = result.final_decision.lower()
        score    = result.risk_score
        triggered = result.signals_triggered or []

        if not fetch_ok:
            outcome = "SAFE_UNVERIFIED"
        elif decision == "malicious":
            outcome = "MALICIOUS"
        else:
            outcome = "SAFE"

        # Match signals by substring
        signal_hits = {
            label: int(any(sub in s for s in triggered))
            for label, sub in SIGNAL_MAP.items()
        }

        return {
            "url"       : url,
            "outcome"   : outcome,
            "risk_score": score,
            "latency_ms": elapsed,
            "fetch_ok"  : fetch_ok,
            "n_signals" : len(triggered),
            "signals_raw": " | ".join(triggered),
            **signal_hits,
        }

    except Exception as exc:
        elapsed = round((time.perf_counter() - t_start) * 1000, 2)
        return {
            "url"       : url,
            "outcome"   : "SAFE_UNVERIFIED",
            "risk_score": 0,
            "latency_ms": elapsed,
            "fetch_ok"  : False,
            "n_signals" : 0,
            "signals_raw": f"EXCEPTION: {exc}",
            **{label: 0 for label in SIGNAL_MAP},
        }


def run_evaluation():
    print("="*65)
    print("TIER-3 LIVE EVALUATION  —  OpenPhish verified URLs")
    print("="*65)

    df    = pd.read_csv(SAMPLE_CSV)
    total = len(df)
    print(f"Loaded {total} URLs | Workers: {MAX_WORKERS}\n")

    results   = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(evaluate_single, row): row
            for _, row in df.iterrows()
        }
        for future in as_completed(futures):
            res = future.result()
            results.append(res)
            completed += 1
            if completed % 25 == 0 or completed == total:
                n_mal = sum(1 for r in results
                            if r["outcome"] == "MALICIOUS")
                n_unv = sum(1 for r in results
                            if r["outcome"] == "SAFE_UNVERIFIED")
                print(f"  [{completed:>3}/{total}]  "
                      f"MALICIOUS={n_mal}  "
                      f"SAFE_UNVERIFIED={n_unv}")

    results_df = pd.DataFrame(results)
    results_df.to_csv(OUTPUT_CSV, index=False)

    # ── Counts ────────────────────────────────────────────────────
    n_malicious  = (results_df["outcome"] == "MALICIOUS").sum()
    n_safe       = (results_df["outcome"] == "SAFE").sum()
    n_unverified = (results_df["outcome"] == "SAFE_UNVERIFIED").sum()
    n_reachable  = n_malicious + n_safe

    recall_reachable = (n_malicious/n_reachable*100
                        if n_reachable > 0 else 0)
    recall_total     = n_malicious/total*100

    # ── Latency ───────────────────────────────────────────────────
    reach_df   = results_df[results_df["fetch_ok"] == True]
    lat_mean   = reach_df["latency_ms"].mean()   if len(reach_df) else 0
    lat_median = reach_df["latency_ms"].median() if len(reach_df) else 0
    lat_p95    = reach_df["latency_ms"].quantile(0.95) if len(reach_df) else 0

    # ── Per-signal hit rates (all evaluated URLs) ──────────────────
    signal_rates = {
        label: results_df[label].mean() * 100
        for label in SIGNAL_MAP
        if label in results_df.columns
    }

    # ── Avg signals per malicious URL ─────────────────────────────
    mal_df = results_df[results_df["outcome"] == "MALICIOUS"]
    avg_sig = mal_df["n_signals"].mean() if len(mal_df) else 0

    # ── Print summary ─────────────────────────────────────────────
    print("\n" + "="*65)
    print("RESULTS SUMMARY")
    print("="*65)
    print(f"Total evaluated             : {total}")
    print(f"Reachable                   : {n_reachable} "
          f"({n_reachable/total*100:.1f}%)")
    print(f"SAFE_UNVERIFIED (soft-fail) : {n_unverified} "
          f"({n_unverified/total*100:.1f}%)")
    print()
    print(f"MALICIOUS correctly flagged : {n_malicious}")
    print(f"SAFE  (missed by Tier-3)    : {n_safe}")
    print()
    print(f"Recall of reachable URLs    : {recall_reachable:.2f}%")
    print(f"Recall of all 200 URLs      : {recall_total:.2f}%")
    print(f"  ↑ Use recall_reachable as oracle rate in paper")

    print(f"\nLATENCY  (reachable URLs only)")
    print(f"  Mean   : {lat_mean:.0f} ms")
    print(f"  Median : {lat_median:.0f} ms")
    print(f"  P95    : {lat_p95:.0f} ms")

    print(f"\nPER-SIGNAL HIT RATES  (all 200 URLs)")
    print(f"  {'Signal':<40} {'Hit Rate':>8}")
    print(f"  {'-'*50}")
    for label, rate in sorted(
        signal_rates.items(), key=lambda x: -x[1]
    ):
        bar = "█" * int(rate / 5)
        print(f"  {label:<40} {rate:>7.1f}%  {bar}")

    print(f"\n  Avg signals per confirmed phishing URL: {avg_sig:.2f}")

    # ── Cascade projection with measured oracle ───────────────────
    print("\n" + "="*65)
    print("CASCADE RECALL PROJECTION  (measured oracle)")
    print("="*65)
    oracle = recall_reachable / 100

    esc_phish   = 141_821   # from your clean Tier-1 evaluation
    high_phish  = 194_511
    total_phish = 361_419

    proj = (int(esc_phish*oracle) + int(high_phish*oracle)) / \
            total_phish * 100

    print(f"Measured oracle rate        : {oracle*100:.2f}%")
    print(f"Projected cascade recall    : {proj:.2f}%")
    print(f"  Escalated phishing rescued: {int(esc_phish*oracle):,}")
    print(f"  High-conf phishing rescued: {int(high_phish*oracle):,}")

    print(f"\nFull results → {OUTPUT_CSV}")
    print("="*65)
    print("\nPaste this entire output back.")


if __name__ == "__main__":
    run_evaluation()