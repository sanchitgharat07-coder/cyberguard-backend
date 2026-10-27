import time

def get_current_timestamp() -> float:
    """Returns high-precision timestamp for latency tracking."""
    return time.time()

def format_latency(start_time: float, end_time: float) -> float:
    """Calculates latency in milliseconds."""
    return round((end_time - start_time) * 1000, 2)