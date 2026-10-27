from urllib.parse import urlparse

def normalize_url(raw_url: str) -> str:
    """
    Standardizes a URL. Strips leading/trailing whitespace and 
    ensures a scheme is present for the fetcher.
    """
    cleaned = raw_url.strip()
    if not cleaned.startswith(('http://', 'https://', 'ftp://')):
        cleaned = 'http://' + cleaned
        
    # Optional: Strip fragments (#) as they are strictly client-side
    parsed = urlparse(cleaned)
    normalized = parsed._replace(fragment="").geturl()
    
    return normalized