# backend/sockets/events.py

from flask import request
from .socket_handler import socketio
from workers.task_queue import task_queue
from workers.scan_worker import process_scan_task
from utils.validators import is_valid_url
from utils.auth import verify_user_token


@socketio.on('start_scan')                      # matches hook: socket.emit('start_scan', ...)
def handle_scan_request(data):
    client_id = request.sid
    target_url = data.get('url', '').strip()
    id_token   = data.get('token', '').strip()
    source     = data.get('source', 'Manual')   # 'QR Scan' | 'Manual' — for scan history

    # ── 1. Enforce authentication ──────────────────────────────────────────────
    # Emit 'auth_error' (not 'scan_error') so the hook can handle it distinctly —
    # frontend shows "sign in again" instead of a generic scan failure message.
    if not id_token:
        socketio.emit('auth_error', {
            'error': 'Authentication required. No session token provided.'
        }, to=client_id)
        return

    uid = verify_user_token(id_token)
    if not uid:
        socketio.emit('auth_error', {
            'error': 'Invalid or expired session token. Please sign in again.'
        }, to=client_id)
        return

    # ── 2. Validate URL ────────────────────────────────────────────────────────
    if not is_valid_url(target_url):
        socketio.emit('scan_error', {
            'error': 'Invalid URL format.'
        }, to=client_id)
        return

    # ── 3. Dispatch to background worker ──────────────────────────────────────
    # uid is verified — worker uses it to save scan result to Firebase
    # source is passed so scan history entries are tagged correctly
    print(f"🔐 User {uid} initiated scan for {target_url}")
    task_queue.enqueue_scan(process_scan_task, target_url, uid, client_id, socketio, source)