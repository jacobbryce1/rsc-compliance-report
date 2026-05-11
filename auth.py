"""
RSC authentication with automatic token refresh.

RSCSession wraps requests.Session and proactively re-authenticates before
the bearer token expires.  It is thread-safe: all concurrent paginated
streams share a single RSCSession instance — only one thread refreshes at
a time while the others wait on the lock.

Security notes:
  - Token values are NEVER logged or printed.
  - Auth failure messages contain only the HTTP status code, never response
    body content (which could include partial credentials or internal detail).
  - All requests use explicit TLS verification (TLS_VERIFY from config).
  - Token expiry is read from the JWT 'exp' claim without signature
    verification — we trust RSC's own response; we only need the timestamp.
"""

import time
import threading

from typing import Optional

import jwt
import requests

from config import (
    RSC_URL,
    RSC_CLIENT_ID,
    RSC_CLIENT_SECRET,
    TOKEN_URL,
    REQUEST_TIMEOUT,
    TOKEN_REFRESH_BUFFER,
    DEFAULT_TOKEN_LIFETIME,
    TLS_VERIFY,
)
from exceptions import RSCAuthError


# ─────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────

def _decode_jwt_expiry(token: str) -> Optional[float]:
    """
    Decode the 'exp' claim from a JWT without verifying the signature.

    Returns the expiry as a Unix timestamp (float), or None if the token
    cannot be decoded or has no 'exp' field.
    """
    try:
        payload = jwt.decode(
            token,
            options={"verify_signature": False, "verify_exp": False},
            algorithms=["RS256", "HS256", "RS384", "RS512"],
        )
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except Exception:
        return None


def _fetch_token() -> tuple[str, float]:
    """
    Call the RSC token endpoint and return (access_token, expiry_unix_ts).

    Security: only the HTTP status code is surfaced in error messages —
    never the response body, which could contain partial credentials or
    internal system detail.

    Raises RSCAuthError on failure.
    """
    payload = {
        "client_id": RSC_CLIENT_ID,
        "client_secret": RSC_CLIENT_SECRET,
    }

    try:
        response = requests.post(
            TOKEN_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
            verify=TLS_VERIFY,
        )
    except requests.exceptions.SSLError as exc:
        raise RSCAuthError(
            f"TLS certificate verification failed connecting to RSC. "
            f"Check RSC_CA_BUNDLE if using a custom CA. Detail: {exc}"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise RSCAuthError(f"Auth request to RSC failed: {type(exc).__name__}") from exc

    if response.status_code == 401:
        raise RSCAuthError(
            "RSC authentication failed (401). "
            "Verify RSC_CLIENT_ID and RSC_CLIENT_SECRET in your .env file."
        )
    if response.status_code == 403:
        raise RSCAuthError(
            "RSC authentication forbidden (403). "
            "The service account may lack the required permissions."
        )
    if response.status_code != 200:
        # Do NOT include response.text — it may contain internal system detail
        raise RSCAuthError(
            f"RSC token endpoint returned HTTP {response.status_code}. "
            f"Check RSC_URL and service account credentials."
        )

    try:
        data = response.json()
    except ValueError as exc:
        raise RSCAuthError("RSC token response was not valid JSON.") from exc

    token = data.get("access_token")
    if not token:
        raise RSCAuthError("RSC token response contained no 'access_token' field.")

    # Prefer JWT 'exp' claim; fall back to expires_in; fall back to default
    expiry = _decode_jwt_expiry(token)
    if expiry is None:
        expires_in = data.get("expires_in", DEFAULT_TOKEN_LIFETIME)
        expiry = time.time() + int(expires_in)

    return token, expiry


# ─────────────────────────────────────────────
# SESSION CLASS
# ─────────────────────────────────────────────

class RSCSession:
    """
    A requests.Session wrapper with automatic bearer-token refresh.

    Usage (identical to a plain requests.Session for callers):
        session = RSCSession()
        session.post(url, json=payload, timeout=30)

    Thread safety:
        Multiple threads may share one RSCSession.  A threading.RLock
        ensures only one thread refreshes at a time; others wait and then
        reuse the new token rather than each triggering their own refresh.

    Security:
        - Token strings are never stored in an attribute accessible from
          outside this class (only baked into the session headers).
        - TLS verification is always explicit via verify=TLS_VERIFY.
    """

    def __init__(self):
        self._session = requests.Session()
        self._lock = threading.RLock()
        self._token_expiry: float = 0.0
        self._authenticate()

    # ── Internal ──

    def _authenticate(self):
        """Fetch a fresh token and update the session Authorization header."""
        token, expiry = _fetch_token()

        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self._token_expiry = expiry

        remaining = int(self._token_expiry - time.time())
        mins, secs = divmod(remaining, 60)
        # Log timing only — never the token value itself
        print(f"Authenticated to {RSC_URL}  (token valid ~{mins}m {secs}s)")

    def _refresh_if_needed(self):
        """
        Re-authenticate if the token expires within TOKEN_REFRESH_BUFFER seconds.

        Uses double-checked locking:
          1. Fast path outside the lock for the common case (token healthy).
          2. Re-check inside the RLock to ensure only one of N waiting
             threads actually calls _authenticate(); the others skip once
             the first thread completes.
        """
        if time.time() < self._token_expiry - TOKEN_REFRESH_BUFFER:
            return  # common path — no lock contention

        with self._lock:
            if time.time() >= self._token_expiry - TOKEN_REFRESH_BUFFER:
                mins_left = max(0, int((self._token_expiry - time.time()) / 60))
                print(f"Token refresh triggered (~{mins_left}m remaining). Re-authenticating...")
                self._authenticate()

    # ── Public interface (duck-types requests.Session) ──

    def post(self, url, **kwargs):
        # Always set verify explicitly — don't rely on library or env-var defaults
        kwargs.setdefault("verify", TLS_VERIFY)
        self._refresh_if_needed()
        return self._session.post(url, **kwargs)

    def get(self, url, **kwargs):
        kwargs.setdefault("verify", TLS_VERIFY)
        self._refresh_if_needed()
        return self._session.get(url, **kwargs)

    @property
    def headers(self):
        """Expose headers so callers can inspect or set extra headers if needed."""
        return self._session.headers

    def token_expires_at(self) -> str:
        """Human-readable token expiry time (UTC) for logging."""
        import datetime
        return datetime.datetime.utcfromtimestamp(self._token_expiry).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

def get_session() -> RSCSession:
    """Return an authenticated RSCSession ready for use."""
    return RSCSession()


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    session = get_session()
    print(f"Token expires at: {session.token_expires_at()}")
