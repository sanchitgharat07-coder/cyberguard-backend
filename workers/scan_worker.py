import time
from flask_socketio import SocketIO

from utils.url_parser import normalize_url
from utils.helpers import get_current_timestamp, format_latency

from tier1_ml.feature_extractor import generate_data_set
from tier1_ml.model_loader import get_model
from tier1_ml.threshold_router import route_traffic

from tier3_forensics.tier3_controller import run_tier3

from database.logger import log_scan_result


def process_scan_task(target_url: str, uid: str, client_id: str, socketio: SocketIO, source: str = 'Manual'):
    """
    Background worker executing the Uncertainty-Aware Cascade.
    Final verdict is always binary: SAFE or MALICIOUS.

    Tier-1 → safe filter only (resolves SAFE fast)
    Tier-2 → blacklist interception (resolves MALICIOUS for known-bad domains)
    Tier-3 → full forensics (makes all remaining decisions)
    """

    start_time     = get_current_timestamp()
    normalized_url = normalize_url(target_url)

    try:
        # ── TIER 1 — Lexical ML safe filter ──────────────────────────────────
        socketio.emit(
            'scan_update',
            {'step': 1, 'message': 'Running Tier-1 ML analysis...', 'progress': 0.25},
            to=client_id
        )

        feature_vector = generate_data_set(normalized_url)
        features_flat  = feature_vector[0]
        model          = get_model()
        phishing_prob  = model.predict_proba(feature_vector)[0][1]
        routing        = route_traffic(normalized_url, phishing_prob, features_flat)

        # Tier-1 only resolves SAFE — never malicious
        if routing['action'] == 'resolve':
            latency = format_latency(start_time, get_current_timestamp())

            final_payload = {
                "uid":          uid,
                "url":          normalized_url,
                "prediction":   routing['prediction'].upper(),
                "confidence":   routing['confidence'],
                "tier_resolved": routing['tier'],
                "latency_ms":   latency,
                "forensics_score": 0,
                "signals":      [],
                "reason":       routing['reason'],
                "source":       source,
            }

            socketio.emit('scan_update',
                {'step': 3, 'message': 'Analysis complete.', 'progress': 1.0},
                to=client_id)
            socketio.emit('scan_result', final_payload, to=client_id)
            log_scan_result(uid, final_payload)
            return

        # ── TIER 2 — Blacklist interception ───────────────────────────────────
        socketio.emit(
            'scan_update',
            {'step': 2, 'message': 'Checking threat intelligence...', 'progress': 0.45},
            to=client_id
        )

        from tier2_intel.domain_normalizer import get_lookup_variations
        from tier2_intel.blacklist_loader  import check_tier2_intel

        variations     = get_lookup_variations(normalized_url)
        tier2_decision = check_tier2_intel(variations)  # 'malicious' or 'unknown'

        if tier2_decision == 'malicious':
            latency = format_latency(start_time, get_current_timestamp())

            final_payload = {
                "uid":           uid,
                "url":           normalized_url,
                "prediction":    "MALICIOUS",
                "confidence":    99.0,
                "tier_resolved": 2,
                "latency_ms":    latency,
                "forensics_score": 0,
                "signals":       ["Domain matched threat intelligence blacklist"],
                "reason":        "Resolved via Tier-2 Threat Intelligence.",
                "source":        source,
            }

            socketio.emit('scan_update',
                {'step': 3, 'message': 'Matched Threat Intel Database.', 'progress': 1.0},
                to=client_id)
            socketio.emit('scan_result', final_payload, to=client_id)
            log_scan_result(uid, final_payload)
            return

        # ── TIER 3 — Deep forensics ───────────────────────────────────────────
        socketio.emit(
            'scan_update',
            {'step': 2, 'message': 'Escalating to Tier-3 Deep Forensics...', 'progress': 0.60},
            to=client_id
        )

        tier3_result_obj = run_tier3(normalized_url)
        t3_dict          = tier3_result_obj.to_dict()

        # Write confirmed malicious domains to Firebase blacklist
        # so Tier-2 catches them in 1ms on all future scans
        if t3_dict['final_decision'] == 'malicious':
            from tier2_intel.blacklist_sync import report_malicious
            report_malicious(
                url=normalized_url,
                signals=t3_dict.get('signals_triggered', [])
            )

        latency = format_latency(start_time, get_current_timestamp())

        final_payload = {
            "uid":           uid,
            "url":           normalized_url,
            "prediction":    t3_dict['final_decision'].upper(),
            "confidence":    99.0 if t3_dict['final_decision'] == 'malicious'
                             else round((1 - phishing_prob) * 100, 2),
            "tier_resolved": 3,
            "latency_ms":    latency,
            "forensics_score": t3_dict['risk_score'],
            "signals":       t3_dict['signals_triggered'],
            "reason":        "Resolved via Tier-3 Deep Content Forensics.",
            "source":        source,
        }

        socketio.emit('scan_update',
            {'step': 3, 'message': 'Deep Forensics complete.', 'progress': 1.0},
            to=client_id)
        socketio.emit('scan_result', final_payload, to=client_id)
        log_scan_result(uid, final_payload)
        return

    except Exception as e:
        print(f"❌ [WORKER ERROR] {str(e)}")
        socketio.emit('scan_error', {
            'error':   'Analysis failed in background worker.',
            'details': str(e)
        }, to=client_id)