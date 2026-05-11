import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import GRAPHQL_URL, PAGE_SIZE, REQUEST_TIMEOUT, MAX_RETRIES, RETRY_BACKOFF_BASE, TLS_VERIFY


# ─────────────────────────────────────────────
# CORE HTTP LAYER
# ─────────────────────────────────────────────

def run_query(session, query, variables=None):
    """
    Execute a single GraphQL query and return the data payload.

    Handles:
    - 401 Unauthorized    (token expired mid-request — session refreshes and retries once)
    - 429 rate limiting   (iterative, honours Retry-After header)
    - 5xx transient errors (exponential backoff, up to MAX_RETRIES)
    - Request timeouts    (REQUEST_TIMEOUT seconds per call)

    Security:
    - Response bodies are NEVER printed verbatim — they may contain internal
      system details or partial sensitive data. Only the HTTP status code and
      a sanitized error type are logged.
    - TLS verification is set explicitly on every request via TLS_VERIFY.
    """
    payload = {"query": query}
    if variables:
        payload["variables"] = variables

    attempt = 0
    auth_retried = False   # guard: only refresh+retry once per call to avoid loops

    while True:
        try:
            response = session.post(
                GRAPHQL_URL,
                json=payload,
                timeout=REQUEST_TIMEOUT,
                verify=TLS_VERIFY,
            )
        except Exception as exc:
            attempt += 1
            if attempt > MAX_RETRIES:
                # Log exception type only — not the full message which may contain URLs/IPs
                print(f"Request error after {MAX_RETRIES} retries: {type(exc).__name__}")
                return None
            wait = RETRY_BACKOFF_BASE ** attempt
            print(f"Request failed ({type(exc).__name__}). Retrying in {wait}s ({attempt}/{MAX_RETRIES})...")
            time.sleep(wait)
            continue

        if response.status_code == 401:
            # Token expired mid-flight (e.g. clock skew beat the refresh buffer).
            # RSCSession._refresh_if_needed() won't help here because we just got
            # a 401 — force a fresh authenticate() then retry exactly once.
            if not auth_retried and hasattr(session, "_authenticate"):
                print("401 Unauthorized — forcing token refresh and retrying...")
                with session._lock:
                    session._authenticate()
                auth_retried = True
                continue  # retry with fresh token
            print("401 Unauthorized after token refresh. Giving up on this request.")
            return None

        if response.status_code == 429:
            # RSC rate-limit — honour the Retry-After header (iterative, not recursive)
            retry_after = int(response.headers.get("Retry-After", 10))
            print(f"Rate limited. Waiting {retry_after}s...")
            time.sleep(retry_after)
            continue  # rate-limit doesn't count against the failure attempt counter

        if response.status_code >= 500:
            attempt += 1
            if attempt > MAX_RETRIES:
                print(f"Server error HTTP {response.status_code} after {MAX_RETRIES} retries. Giving up.")
                return None
            wait = RETRY_BACKOFF_BASE ** attempt
            print(f"Server error HTTP {response.status_code}. Retrying in {wait}s ({attempt}/{MAX_RETRIES})...")
            time.sleep(wait)
            continue

        if response.status_code != 200:
            # Do NOT print response.text — it may contain internal system detail
            print(f"Query failed: HTTP {response.status_code}")
            return None

        try:
            data = response.json()
        except ValueError:
            print("Query returned non-JSON response.")
            return None

        if "errors" in data:
            # Log error codes/types only — not full error messages which can leak schema info
            error_types = [e.get("extensions", {}).get("code", "UNKNOWN") for e in data["errors"]]
            print(f"GraphQL errors: {error_types}")

        return data.get("data")


# ─────────────────────────────────────────────
# PAGINATED FETCHER  (single stream)
# ─────────────────────────────────────────────

def run_paginated_query(session, query, path_to_connection, variables=None, label=""):
    """
    Follow cursor-based pagination until all pages are fetched.

    Args:
        session:              authenticated requests.Session
        query:                GraphQL query string (must accept $first/$after vars)
        path_to_connection:   dot-separated key path to the connection object,
                              e.g. "awsNativeEc2Instances" or "snappableConnection"
        variables:            extra GraphQL variables (merged with first/after)
        label:                human-readable stream name for progress output

    Returns:
        list of all node dicts across all pages
    """
    all_nodes = []
    cursor = None
    page = 1

    if variables is None:
        variables = {}

    variables = dict(variables)          # don't mutate caller's dict
    variables["first"] = PAGE_SIZE

    prefix = f"[{label}] " if label else ""

    while True:
        variables["after"] = cursor

        page_attempt = 0
        data = None
        while page_attempt <= MAX_RETRIES:
            data = run_query(session, query, variables)
            if data is not None:
                break
            page_attempt += 1
            wait = RETRY_BACKOFF_BASE ** page_attempt
            print(f"{prefix}Page {page} failed. Retrying in {wait}s ({page_attempt}/{MAX_RETRIES})...")
            time.sleep(wait)

        if data is None:
            print(f"{prefix}Pagination aborted at page {page} after {MAX_RETRIES} retries.")
            break

        # Navigate to the connection object (supports dot-paths, e.g. "a.b.c")
        connection = data
        for key in path_to_connection.split("."):
            connection = connection[key]

        nodes = connection.get("nodes", [])
        page_info = connection.get("pageInfo", {})

        all_nodes.extend(nodes)
        print(f"{prefix}Page {page}: {len(nodes)} objects (running total: {len(all_nodes)})")

        if not page_info.get("hasNextPage", False):
            break

        cursor = page_info.get("endCursor")
        page += 1

    return all_nodes


# ─────────────────────────────────────────────
# CONCURRENT FETCHER  (multiple streams)
# ─────────────────────────────────────────────

def run_concurrent_paginated_queries(session, stream_specs, max_workers=4):
    """
    Fan out multiple independent paginated queries in parallel.

    Args:
        session:      authenticated requests.Session  (thread-safe for reads)
        stream_specs: list of dicts, each with keys:
                        label             - display name (str)
                        query             - GraphQL query string
                        path_to_connection- connection key path (str)
                        variables         - optional extra vars dict
        max_workers:  thread pool size

    Returns:
        dict keyed by label → list of node dicts
    """
    results = {}
    lock = threading.Lock()

    def _fetch(spec):
        label = spec["label"]
        nodes = run_paginated_query(
            session,
            spec["query"],
            spec["path_to_connection"],
            variables=spec.get("variables"),
            label=label,
        )
        with lock:
            results[label] = nodes
        return label, len(nodes)

    print(f"Starting {len(stream_specs)} concurrent streams (max_workers={max_workers})...")
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_fetch, spec): spec["label"] for spec in stream_specs}
        for fut in as_completed(futures):
            label = futures[fut]
            try:
                _, count = fut.result()
                print(f"  ✓ {label} complete — {count} objects")
            except Exception as exc:
                print(f"  ✗ {label} raised exception: {exc}")
                results.setdefault(label, [])

    return results
