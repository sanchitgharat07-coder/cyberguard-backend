import time
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .schemas import FetchResult

# ── Tuning constants ───────────────────────────────────────────────────────────

_CONNECT_TIMEOUT_S = 3.0    # TCP + TLS handshake budget
_READ_TIMEOUT_S    = 5.0    # time to receive first byte after connect
_MAX_REDIRECTS     = 5
_MAX_BYTES         = 1_048_576  # 1 MB hard cap on HTML payload

# ── Browser-realistic headers ──────────────────────────────────────────────────
# Expanded from original — adds DNT, Connection, Upgrade-Insecure-Requests
# to better mimic Chrome and bypass bot-detection that checks for these headers.

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer":         "https://www.google.com/",
    "DNT":             "1",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ── Shared persistent session ─────────────────────────────────────────────────
# A module-level session reuses the TCP/TLS connection pool across calls in the
# same process — avoids a full handshake on every URL in a batch job.
# No retries on status codes; we want raw results for forensic accuracy.

def _build_session() -> Session:
    session = Session()
    session.headers.update(_HEADERS)
    session.max_redirects = _MAX_REDIRECTS

    adapter = HTTPAdapter(
        max_retries=Retry(total=0),   # no silent retries — fail fast, fail clean
        pool_connections=10,
        pool_maxsize=20,
    )
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session

_SESSION = _build_session()


# ── Public API ─────────────────────────────────────────────────────────────────

def fetch_url(target_url: str) -> FetchResult:
    """
    Safely executes an HTTP GET with strict deployment constraints.
    Returns the final_url after all redirects for Brand-Mismatch analysis.

    Key upgrades over v1:
      • Persistent connection pool (no new TCP handshake per call)
      • Split connect/read timeout — slow servers can't eat the full budget
      • stream=True + iter_content() — 1 MB cap without buffering whole response
      • Full redirect chain including the original URL and final destination
      • Sentinel status codes (-1 redirect loop, -2 timeout) for clean branching
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    t0 = time.perf_counter()

    try:
        response = _SESSION.get(
            target_url,
            timeout=(_CONNECT_TIMEOUT_S, _READ_TIMEOUT_S),
            allow_redirects=True,
            verify=True,    # always validate SSL during fetch
            stream=True,    # enables byte-capped read below
        )

        response_time_ms = (time.perf_counter() - t0) * 1000

        # ── Redirect chain ─────────────────────────────────────────────────────
        # Original only captured history URLs; we also prepend the origin and
        # append the final destination for a complete, unambiguous chain.
        chain: list[str] = [target_url]
        for hist_resp in response.history:
            loc = hist_resp.headers.get("Location", "")
            if loc and loc not in chain:
                chain.append(loc)
        if response.url not in chain:
            chain.append(response.url)

        # ── Byte-capped HTML read ──────────────────────────────────────────────
        # stream=True means nothing is buffered yet; we pull at most _MAX_BYTES.
        # This prevents a 50 MB page from blowing memory before we can cap it.
        html_payload = ""
        if response.status_code == 200:
            chunks: list[bytes] = []
            consumed = 0
            for chunk in response.iter_content(chunk_size=8192):
                chunks.append(chunk)
                consumed += len(chunk)
                if consumed >= _MAX_BYTES:
                    break
            html_payload = b"".join(chunks).decode("utf-8", errors="replace")

        response.close()

        return FetchResult(
            requested_url=target_url,
            final_url=response.url,
            status_code=response.status_code,
            html_content=html_payload,
            content_type=response.headers.get("Content-Type", ""),
            redirect_chain=chain,
            response_time_ms=round(response_time_ms, 2),
            success=True,
        )

    except Exception as exc:
        response_time_ms = (time.perf_counter() - t0) * 1000

        # Map exception types to the same sentinel codes the original used,
        # plus a human-readable error_message for logs.
        import requests as _req
        if isinstance(exc, _req.exceptions.TooManyRedirects):
            code, msg = -1, "Redirect loop detected (>5)"
        elif isinstance(exc, _req.exceptions.Timeout):
            code, msg = -2, "Target server timed out"
        elif isinstance(exc, _req.exceptions.SSLError):
            code, msg = -3, f"SSL error: {str(exc)[:80]}"
        elif isinstance(exc, _req.exceptions.ConnectionError):
            code, msg = -4, f"Connection error: {str(exc)[:80]}"
        elif isinstance(exc, _req.exceptions.RequestException):
            code, msg = 0,  f"Network error: {str(exc)[:80]}"
        else:
            code, msg = 0, "Unexpected fetch failure"

        return FetchResult(
            requested_url=target_url,
            final_url=target_url,
            status_code=code,
            html_content="",
            redirect_chain=[target_url],
            response_time_ms=round(response_time_ms, 2),
            success=False,
            error_message=msg,
        )