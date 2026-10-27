# backend/workers/task_queue.py

class TaskQueue:
    """
    A lightweight wrapper for offloading heavy ML and Forensic tasks
    to background threads. Keeps the main WebSocket thread responsive
    to other mobile clients while a scan is processing.
    """
    def __init__(self, socketio):
        self.socketio = socketio

    def enqueue_scan(self, worker_function, target_url, uid, client_id, socketio, source='Manual'):
        """
        Dispatches the scan to a background worker.
        source: 'QR Scan' | 'Manual' — passed through to scan history tagging.
        """
        self.socketio.start_background_task(
            worker_function,
            target_url,
            uid,
            client_id,
            socketio,
            source,
        )


# Singleton instance
task_queue = None

def init_queue(socketio_instance):
    global task_queue
    task_queue = TaskQueue(socketio_instance)
    return task_queue