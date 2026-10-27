# websocket/socket_handler.py

from flask_socketio import SocketIO

# Initialize SocketIO with permissive CORS for React Native testing
# async_mode='eventlet' is highly recommended for production concurrency
socketio = SocketIO(cors_allowed_origins="*", async_mode='eventlet')

def init_websockets(app):
    """Attaches the WebSocket server to the main Flask app."""
    socketio.init_app(app)
    print("✅ WebSocket server initialized.")
    return socketio