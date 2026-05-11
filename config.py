import os
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# REQUIRED ENVIRONMENT VARIABLES
# Validate at import time so misconfiguration fails loudly and immediately
# rather than crashing mid-run with an AttributeError.
# ─────────────────────────────────────────────

def _require_env(name: str) -> str:
    """Return the value of a required env var, or raise a clear ConfigurationError."""
    val = os.getenv(name)
    if not val or not val.strip():
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set or is empty. "
            f"Copy .env.example to .env and fill in your RSC credentials."
        )
    return val.strip()


RSC_URL          = _require_env("RSC_URL").rstrip("/")
RSC_CLIENT_ID    = _require_env("RSC_CLIENT_ID")
RSC_CLIENT_SECRET = _require_env("RSC_CLIENT_SECRET")

# API endpoints
TOKEN_URL   = f"{RSC_URL}/api/client_token"
GRAPHQL_URL = f"{RSC_URL}/api/graphql"

# ─────────────────────────────────────────────
# TLS / TRANSPORT SECURITY
# Explicit — never rely solely on library defaults.
# Setting this to False disables certificate verification; NEVER do that in
# production. If you need a custom CA bundle set RSC_CA_BUNDLE in your .env.
# ─────────────────────────────────────────────
TLS_VERIFY = os.getenv("RSC_CA_BUNDLE") or True  # True = use system CA store

# Pagination
PAGE_SIZE = 200

# History window — how many months back to pull compliance/snapshot data
HISTORY_MONTHS = 12

# Concurrency — number of parallel fetch streams (EC2 / EBS / RDS / S3 etc.)
MAX_WORKERS = 4

# HTTP request timeout in seconds (per individual POST)
REQUEST_TIMEOUT = 120

# Retry behaviour for transient failures
MAX_RETRIES = 3          # max attempts per page before giving up
RETRY_BACKOFF_BASE = 2   # exponential backoff multiplier (2 → 2s, 4s, 8s…)

# Token refresh — proactively re-authenticate this many seconds before expiry
# RSC tokens typically last 3600s (1 hour); we refresh 5 minutes early to
# avoid any clock-skew or slow-request edge cases during long runs.
TOKEN_REFRESH_BUFFER = 300    # seconds before expiry to trigger refresh
DEFAULT_TOKEN_LIFETIME = 3600 # assumed lifetime if JWT 'exp' claim is absent

# Output
OUTPUT_DIR = "output"

# Incremental CSV flush threshold — write to disk every N rows to keep RAM low
CSV_FLUSH_ROWS = 1000

# Classification: SLA names that count as "Do Not Protect"
DNP_SLA_NAMES = [
    "do not protect",
    "dnp",
    "do-not-protect",
    "no backup",
]

# Tags that indicate DNP
DNP_TAG_KEYS = [
    "backup-policy",
    "BackupPolicy",
    "rubrik:dnp",
]
DNP_TAG_VALUES = [
    "none",
    "dnp",
    "do-not-protect",
    "false",
]
