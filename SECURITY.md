# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

This tool handles RSC service account credentials and produces detailed reports of your AWS cloud backup estate — including account numbers, resource identifiers, VPC topology, SLA assignments, snapshot history, and compliance status. Responsible disclosure is important.

### How to Report

Use **GitHub's private vulnerability reporting**:

1. Go to the [Security tab](../../security) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details — include steps to reproduce, impact assessment, and any suggested remediation if you have one

We aim to acknowledge reports within **3 business days** and provide a fix or mitigation within **14 days** for high/critical issues.

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept code if applicable)
- The version(s) affected
- Any suggested fix

### Out of Scope

- Vulnerabilities in Rubrik Security Cloud (RSC) itself — report those directly to Rubrik
- Denial-of-service against the local Python process
- Issues that require physical access to the machine running the tool
- API rate-limit overages caused by misconfigured concurrency or page-size settings

---

## Security Design

This tool was reviewed against **OWASP Top 10 (2021)**, **NIST Cybersecurity Framework**, **CIS Controls v8**, **ISO 27001:2022**, and **SOC 2**. The controls below map directly to that review.

### Credential Handling

- All credentials (`RSC_URL`, `RSC_CLIENT_ID`, `RSC_CLIENT_SECRET`) are loaded exclusively from environment variables or a `.env` file — never hardcoded in source.
- All three required variables are validated at startup by `config._require_env()`. Missing or empty values raise an `EnvironmentError` and halt execution before any API calls are attempted, preventing partial-credential runs that could silently produce incomplete results.
- The `.env` file is listed in `.gitignore` and must never be committed to version control. The `.env.example` template contains no real values.
- Token values are never written to stdout, log files, or exception messages. Only timing metadata (minutes and seconds remaining) is logged when a refresh is triggered.

### Token Lifecycle

- `RSCSession` in `auth.py` proactively refreshes the access token `TOKEN_REFRESH_BUFFER` seconds (default: 300 s / 5 minutes) before expiry, preventing mid-run failures on long 12-month history pulls.
- Token expiry is read from the JWT `exp` claim without signature verification (we trust the RSC response; we need only the timestamp). If the claim is absent, `expires_in` from the response body is used; if that is also absent, `DEFAULT_TOKEN_LIFETIME` (3,600 s) is assumed.
- Token refresh uses **double-checked locking** via a `threading.RLock`. The fast path checks expiry without acquiring the lock. Inside the lock, the condition is re-evaluated so that only one of N concurrent worker threads triggers a refresh — the others wait and then skip once the token is already fresh.
- On receipt of a `401 Unauthorized` response during a query, the session forces an immediate re-authentication under the lock and retries the request exactly once. A second `401` after a fresh token is treated as a hard failure rather than an infinite loop.
- SSL errors during authentication raise `RSCAuthError` immediately and are never retried.

### Network Security

- TLS certificate verification is controlled by the `TLS_VERIFY` constant in `config.py`, which defaults to `True` (system CA store). It is passed explicitly as `verify=TLS_VERIFY` on every `requests.post()` call in both `auth.py` and `queries.py` — the code never relies on the `requests` library default or on environment variables such as `REQUESTS_CA_BUNDLE` to control this behaviour.
- Environments using corporate TLS inspection proxies can set `RSC_CA_BUNDLE=/path/to/ca-bundle.crt` in `.env`. This value is read into `TLS_VERIFY` at startup. Setting `TLS_VERIFY = False` is not supported and would require a source code change — making it a deliberate, reviewable decision rather than a runtime option.
- `SSLError` is not caught by the generic retry loop; it propagates immediately as `RSCAuthError` with a clear message identifying the TLS failure.
- All RSC API communication is HTTPS only. There is no HTTP fallback.

### GraphQL Injection Prevention

*(OWASP A03 — Injection; CIS Control 16; ISO 27001 A.14.2)*

- All variable values passed to GraphQL queries are placed in the GraphQL `variables` dict and sent as typed parameters, never string-interpolated into the query body.
- Query strings in `extract.py` are static constant strings. No runtime values — including timestamps, account IDs, or any API-sourced data — are concatenated into query documents.
- The `allAwsCloudAccountsFeaturesWithExoConfigs` call (used to resolve 12-digit AWS account numbers) uses hardcoded enum values (`CLOUD_NATIVE_PROTECTION`, all valid `CloudAccountStatus` values). These are compile-time constants, not user input, so there is no injection surface on this call.
- This pattern means no API-sourced or user-controlled data flows into any query string at any point in the call chain.

### Output File Security

*(NIST PR.DS-1; CIS Control 3; ISO 27001 A.8.2; SOC 2 Confidentiality)*

- All output files — full compliance report, per-account summary, unprotected objects, non-compliant objects, and the run audit log — are written with `os.chmod(path, 0o600)` (owner read/write only) on every flush and after every write operation.
- The output directory is created with `chmod 0o700` (owner access only) via `os.chmod(OUTPUT_DIR, 0o700)` at the start of each run.
- Output files contain sensitive cloud infrastructure data: 12-digit AWS account numbers, resource identifiers, VPC IDs, SLA names, snapshot timestamps, compliance classification, and archival/replication compliance status. They should be treated with the same sensitivity as your backup infrastructure inventory and not placed on shared or world-readable filesystems.

### Error Handling and Information Leakage

*(OWASP A09; NIST PR.DS; ISO 27001 A.12.4)*

- Raw API response bodies are never printed to stdout or captured in exception messages. HTTP error paths in `queries.py` log only the numeric status code (`HTTP 4xx / 5xx`).
- Network exception strings from `requests` (which may contain full URLs, headers, or partial payloads) are reduced to the exception type name only: `type(exc).__name__`.
- GraphQL error responses from RSC are reduced to the `extensions.code` field of each error object (e.g. `["UNAUTHORIZED"]`), capped to the list of codes. Full error messages — which can contain schema hints or internal system detail — are not forwarded to output.
- `SystemExit` is not used anywhere in the codebase. Authentication and API failures raise typed exceptions (`RSCAuthError`, `RSCAPIError`) that propagate through the call stack to `main()`, which catches them, logs a sanitised message, writes the run audit log, and calls `sys.exit(1)` cleanly. This ensures partial CSV output is flushed and closed before the process exits.

### Run Audit Trail

*(NIST DE.CM; CIS Control 8; ISO 27001 A.12.4; SOC 2 Security)*

- Every run writes a structured JSON audit record to `output/run_audit_<timestamp>.log`.
- The record captures: `run_timestamp`, `hostname`, `python_version`, `platform`, `history_months`, `history_window_start`, `history_window_end`, `object_counts` (per type), `total_objects`, `exit_status`, and `error` (if any).
- The audit log does not contain credentials, tokens, or API response content.
- Audit logs are written with `chmod 0o600`.
- The `finally` block in `main()` guarantees the audit log is always written, even if an unhandled exception occurs after the run begins.

### Dependency Management

*(OWASP A06; CIS Control 7; ISO 27001 A.12.6)*

- All dependencies are pinned to minimum safe versions in `requirements.txt`.
- `PyJWT>=2.4.0` is required. PyJWT versions below 2.4.0 are vulnerable to CVE-2022-29217 (algorithm confusion / key confusion attack). This is enforced in `requirements.txt` and verified during `pip install`.
- `requests>=2.32.0` is required. Earlier versions have known SSRF and header-injection issues.
- Run a local dependency audit before deploying or releasing:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

---

## Files Generated at Runtime

| File | Contents | Protected by |
|------|----------|--------------|
| `.env` | RSC credentials | `.gitignore`, OS file permissions |
| `output/compliance_report_*.csv` | Full per-object compliance data (all AWS types) | `chmod 0o600` |
| `output/compliance_summary_*.csv` | Per-account coverage table | `chmod 0o600` |
| `output/unprotected_objects_*.csv` | UNPROTECTED objects only | `chmod 0o600` |
| `output/non_compliant_objects_*.csv` | PROTECTED_NON_COMPLIANT objects only | `chmod 0o600` |
| `output/run_audit_*.log` | Structured JSON run metadata | `chmod 0o600` |

> Output files contain AWS account numbers, resource IDs, VPC topology, SLA assignments, snapshot dates, and compliance classification. Treat them with the same sensitivity as your backup infrastructure inventory.

---

## Threat Model

This tool is designed for **single-user, trusted-host execution** — a security analyst or cloud administrator running the tool on their own workstation or a bastion host to generate point-in-time or historical compliance reports. The threat model assumes:

- **The host is trusted.** The tool does not defend against a compromised OS or a malicious local user with read access to the output directory. File permissions (`0o600` / `0o700`) mitigate casual exposure but are not a substitute for host security.
- **The RSC instance is trusted.** The tool validates the URL scheme at startup but does not defend against a compromised RSC instance returning malicious data in field values. Consumers of the CSV and JSON outputs should treat field values as untrusted data in any downstream processing that renders or executes them.
- **The `.env` file is protected by the OS.** File permissions and `.gitignore` are the primary controls — not encryption. Do not store `.env` on shared or world-readable filesystems, and do not store it in cloud object storage without appropriate access controls.
- **Network path to RSC is trusted via TLS.** Certificate verification is explicitly enforced, but the tool does not implement certificate pinning. A compromised CA in the system trust store could perform MITM undetected. For high-security environments, use `RSC_CA_BUNDLE` to pin to a specific intermediate CA.
- **The history window datetime values are internally generated.** The `rangeStart` and `rangeEnd` values passed to GraphQL are constructed from `datetime.now(utc)` in `main.py` — they are not user-supplied inputs. The parameterised variable pattern is nevertheless enforced as a defence-in-depth measure and to maintain the correct architectural separation between query structure and query values.

---

## Security Contact

For questions about the security design of this tool, open a GitHub Discussion rather than a private vulnerability report.
