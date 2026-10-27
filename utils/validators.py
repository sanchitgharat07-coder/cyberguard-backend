import re
from urllib.parse import urlparse

def is_valid_url(url: str) -> bool:
    """
    Validates if the provided string is structurally a URL.
    Prevents injection attacks and wasted ML inference.
    """
    if not url or len(url) > 2048:
        return False
        
    # Regex for basic URL structure (allows IPs and localhost for testing)
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
    # If it lacks a scheme, pretend it has one for regex validation
    check_url = url if url.startswith(('http', 'https')) else f"http://{url}"
    return re.match(regex, check_url) is not None