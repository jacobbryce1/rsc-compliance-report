# RSC Compliance Report Generator

Point-in-time and historical compliance reporting tool for AWS cloud assets protected by Rubrik Security Cloud (RSC). Designed for security audits, SLA compliance reviews, and executive reporting across environments of any size.

> **Not affiliated with Rubrik.** This is an independent, community-built tool. See [Legal & Disclaimer](#legal--disclaimer) for full details.

---

## Overview

This tool connects to your RSC instance via the GraphQL API and queries all AWS native object types in parallel. It produces detailed CSV reports covering per-object protection status, SLA compliance, snapshot history, and per-account coverage — with data scoped to a configurable historical window (default: 12 months).

Protection status is determined from multiple signals: effective SLA assignment, compliance status from `snappableConnection`, snapshot recency, SLA pause state, relic state, and DNP classification via SLA name or AWS resource tags.

**v1.0.0** includes a full security hardening pass reviewed against OWASP Top 10 (2021), NIST Cybersecurity Framework, CIS Controls v8, ISO 27001:2022, and SOC 2. See [Security](#security) for details.

---

## Features

| Feature | Details |
|---------|---------|
| ☁️ AWS native coverage | EC2, EBS, RDS, S3, and DynamoDB across all connected accounts |
| ⚡ Parallel stream fetching | All object types and compliance queries run concurrently |
| 🗓️ 12-month history window | Compliance data scoped to a configurable lookback period |
| 📊 Per-account coverage reporting | Coverage % per AWS account with PROTECTED / DNP / UNPROTECTED breakdown |
| 🏷️ DNP tag detection | Classifies objects as Do Not Protect via SLA name or AWS resource tags |
| 🔑 Automatic token refresh | Proactive refresh 5 minutes before expiry; force-refresh on 401 |
| 📐 Cursor-based pagination | Follows RSC's GraphQL cursor model with exponential backoff retries |
| 💾 Incremental CSV writing | Flushes to disk every 1,000 rows — flat memory usage on large estates |
| 🧾 Run audit log | Structured JSON record of each run: hostname, time window, object counts, exit status |
| 🔒 Security hardened | Reviewed against 5 security frameworks; see [SECURITY.md](SECURITY.md) |

---

## Covered Object Types

| Object Type | RSC Endpoint | Notes |
|-------------|-------------|-------|
| EC2 Instances | `awsNativeEc2Instances` | Full SLA, tag, snapshot, and compliance data |
| EBS Volumes | `awsNativeEbsVolumes` | Including size, type, and availability zone |
| RDS Instances | `awsNativeRdsInstances` | Includes engine, class, Multi-AZ, and VPC |
| S3 Buckets | `snappableConnection` (filter: `AWS_NATIVE_S3_BUCKET`) | Includes archival and replication compliance status |
| DynamoDB Tables | `snappableConnection` (filter: `AWS_NATIVE_DYNAMODB_TABLE`) | Includes archival and replication compliance status |

Compliance enrichment for EC2, EBS, and RDS is fetched concurrently from `snappableConnection` with object-type filters, providing `complianceStatus`, `archiveSnapshots`, `missedSnapshots`, `totalSnapshots`, and `lastSnapshot`. S3 and DynamoDB carry compliance data inline from their own stream queries, including `protectionStatus`, `archivalComplianceStatus`, and `replicationComplianceStatus`.

AWS account numbers (12-digit) are resolved separately via `allAwsCloudAccountsFeaturesWithExoConfigs` and joined to all object rows by RSC account UUID.

---

## Protection Status Classifications

| Status | Meaning |
|--------|---------|
| `PROTECTED_COMPLIANT` | Has an active SLA and is in compliance |
| `PROTECTED_NON_COMPLIANT` | Has an active SLA but is out of compliance |
| `DO_NOT_PROTECT` | Intentionally excluded via DNP SLA or resource tag |
| `UNPROTECTED` | No SLA assigned |
| `PROTECTED_UNKNOWN` | Has an SLA but compliance status is unavailable |
| `PROTECTED_NO_SNAPSHOTS` | Has an SLA but no snapshots have been taken yet |

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.8 or higher |
| Network | HTTPS access to your RSC instance (port 443) |
| RSC Permissions | Service account with read access to AWS native objects, SLA domains, snappable compliance data, and cloud account metadata (`allAwsCloudAccountsFeaturesWithExoConfigs`) |
| Disk Space | ~10 MB per run for a typical mid-size environment |
| RAM | 256 MB minimum; estate size is handled by incremental CSV writing |

> You must have a valid API key and an active Rubrik Security Cloud subscription. This tool does not bypass licensing or provide unauthorised access to any Rubrik features.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/jacobbryce1/rsc-compliance-report.git
cd rsc-compliance-report

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp .env.example .env
# Edit .env with your RSC credentials

# Run
python main.py
```

---

## Configuration

### 1. Create your `.env` file

```bash
cp .env.example .env
```

```dotenv
# .env
RSC_URL=https://your-org.my.rubrik.com
RSC_CLIENT_ID=your-client-id-here
RSC_CLIENT_SECRET=your-client-secret-here

# Optional: custom CA bundle for corporate TLS inspection proxies
# RSC_CA_BUNDLE=/path/to/custom-ca-bundle.crt
```

> ⚠️ **Never commit `.env` to version control.** It is already listed in `.gitignore`.
> `RSC_URL`, `RSC_CLIENT_ID`, and `RSC_CLIENT_SECRET` are validated at startup — the tool
> will refuse to run with a clear error message if any are missing or empty.

### 2. RSC Service Account Setup

1. Log into RSC → **Settings** → **Service Accounts**
2. Create a new service account
3. Assign read-only access to AWS native objects, SLA domains, and compliance data *(principle of least privilege)*
4. Copy the Client ID and Secret into your `.env` file

### 3. Tunable Settings

All settings live in `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `RSC_URL` | *(required)* | Your RSC instance URL |
| `RSC_CLIENT_ID` | *(required)* | Service account client ID |
| `RSC_CLIENT_SECRET` | *(required)* | Service account secret |
| `RSC_CA_BUNDLE` | *(unset)* | Path to custom CA bundle (optional) |
| `HISTORY_MONTHS` | `12` | How many months back to scope compliance data |
| `MAX_WORKERS` | `4` | Concurrent parallel fetch streams |
| `PAGE_SIZE` | `200` | Objects per GraphQL page |
| `REQUEST_TIMEOUT` | `120` | HTTP timeout per request (seconds) |
| `MAX_RETRIES` | `3` | Retry attempts per page on failure |
| `TOKEN_REFRESH_BUFFER` | `300` | Seconds before expiry to proactively refresh token |
| `CSV_FLUSH_ROWS` | `1000` | Rows buffered before flushing to disk |
| `OUTPUT_DIR` | `output` | Directory for all output files |
| `DNP_SLA_NAMES` | see config | SLA names treated as Do Not Protect |
| `DNP_TAG_KEYS` / `DNP_TAG_VALUES` | see config | AWS tags that indicate DNP |

---

## Usage

### Running a Report

```bash
python main.py
```

The tool will:

1. Validate credentials and establish an authenticated session
2. Compute a `HISTORY_MONTHS`-month time window ending now
3. Fetch SLA domains and AWS account metadata (including 12-digit account numbers via `allAwsCloudAccountsFeaturesWithExoConfigs`)
4. Concurrently fetch compliance status for EC2, EBS, and RDS from `snappableConnection`
5. Concurrently fetch full inventory for EC2, EBS, RDS, S3, and DynamoDB
6. Flatten, classify, and stream-write all objects to CSV
7. Print a console summary and write per-account and problem-object reports
8. Write a structured run audit log

Progress is printed throughout, including per-page fetch counts for each stream.

### DNP Classification

An object is classified as `DO_NOT_PROTECT` if:

- Its effective SLA name matches any entry in `DNP_SLA_NAMES` (case-insensitive), **or**
- One of its AWS resource tags has a key matching `DNP_TAG_KEYS` with a value matching `DNP_TAG_VALUES`, **or**
- For S3 and DynamoDB (which do not return tags via `snappableConnection`): RSC's own `protectionStatus` field returns `DoNotProtect`

The third check ensures DNP objects are correctly classified even when tag-based detection cannot apply. DNP objects count toward coverage in the audit summary (Protected + DNP %) to distinguish intentional exclusions from truly unprotected objects.

---

## Output Files

Each run writes the following to `output/` (all with `chmod 0o600`):

| File | Description |
|------|-------------|
| `compliance_report_<timestamp>.csv` | Full per-object detail across all AWS object types |
| `compliance_summary_<timestamp>.csv` | Per-account coverage table with coverage % |
| `unprotected_objects_<timestamp>.csv` | Objects with status `UNPROTECTED` only |
| `non_compliant_objects_<timestamp>.csv` | Objects with status `PROTECTED_NON_COMPLIANT` only |
| `run_audit_<timestamp>.log` | Structured JSON run audit record |

The output directory itself is created with `chmod 0o700` (owner access only).

### Report Columns

The full compliance report includes:

`rsc_object_id`, `object_type`, `native_id`, `object_name`, `aws_account_number`, `aws_account_name`, `rubrik_account_id`, `region`, `sla_id`, `sla_name`, `compliance_status`, `protection_status`, `protection_source`, `status_detail`, `last_snapshot_date`, `first_snapshot_date`, `missed_snapshots`, `archive_snapshots`, `archival_compliance_status`, `replication_compliance_status`, `total_snapshots`, `is_relic`, `sla_paused`, `sla_assignment`, `rsc_protection_status`, `tag_environment`, `tag_application`, `tag_owner`, `tag_cost_center`, `all_tags`, `report_date`, `report_timestamp`, `history_start`, `history_end`, plus object-type-specific fields (`instance_type`, `vpc_id`, `volume_type`, `size_gb`, `db_engine`, etc.)

Key new columns added for OCC audit alignment:

| Column | Description |
|--------|-------------|
| `protection_source` | How the SLA was assigned: `direct_assignment`, `tag_or_policy_rule`, or `none` (EC2/EBS/RDS only — derived from RSC `slaAssignment` field) |
| `archive_snapshots` | Count of snapshots stored in archival storage |
| `archival_compliance_status` | RSC's archival-tier compliance verdict (S3/DynamoDB; null for unprotected objects) |
| `replication_compliance_status` | RSC's replication-tier compliance verdict (S3/DynamoDB; null for unprotected objects) |
| `rsc_protection_status` | RSC's raw `protectionStatus` value for S3/DynamoDB: `Protected`, `NoSla`, or `DoNotProtect` |

### Audit Log Fields

`run_timestamp`, `hostname`, `python_version`, `platform`, `history_months`, `history_window_start`, `history_window_end`, `object_counts` (per type), `total_objects`, `exit_status`, `error`

---

## Architecture

```
RSC GraphQL API
         |
         | HTTPS / TLS enforced
         v
+--------------------------------+
|   RSCSession (auth.py)         |
|   - Proactive token refresh    |
|     (5 min before expiry)      |
|   - Thread-safe RLock          |
|   - Force refresh on 401       |
|   - Explicit verify=TLS_VERIFY |
+---------------+----------------+
                |
                v
+--------------------------------+
|   HTTP Layer (queries.py)      |
|   - Cursor-based pagination    |
|   - Exponential backoff retry  |
|   - 429 rate-limit handling    |
|   - Sanitised error messages   |
+---------------+----------------+
                |
       ┌────────┴─────────┐
       | ThreadPoolExecutor|  (MAX_WORKERS=4)
       └────────┬─────────┘
     ┌──────────┼──────────┬──────────┬──────────┐
     v          v          v          v          v
  EC2         EBS         RDS        S3       DynamoDB
  stream      stream      stream     stream    stream
     └──────────┴──────────┴──────────┴──────────┘
                |
                v
+--------------------------------+
|   Account Native ID Lookup     |
|   (allAwsCloudAccounts…)       |
|   - Resolves 12-digit AWS IDs  |
|   - Joined by RSC account UUID |
+---------------+----------------+
                |
                v
+--------------------------------+
|   Compliance Enrichment        |
|   (snappableConnection)        |
|   - EC2 / EBS / RDS in         |
|     parallel; archive counts   |
+---------------+----------------+
                |
                v
+--------------------------------+
|   Classifier (classify.py)     |
|   - Protection status          |
|   - DNP detection (SLA + tag)  |
|   - Tag extraction             |
+---------------+----------------+
                |
                v
+--------------------------------+
|   IncrementalCSVWriter         |
|   - Flushes every 1,000 rows   |
|   - chmod 0o600 on flush       |
|   - Flat memory usage          |
+---------------+----------------+
                |
                v
+--------------------------------+
|   Reports & Audit Log          |
|   - Per-account coverage CSV   |
|   - Unprotected objects CSV    |
|   - Non-compliant objects CSV  |
|   - JSON run audit log         |
|   - Console summary            |
+--------------------------------+
```

---

## Project Structure

```
rsc-compliance-report/
├── .env.example          # Credential template — copy to .env
├── .gitignore
├── README.md
├── SECURITY.md
├── requirements.txt      # Pinned dependencies (pip-audit clean)
├── auth.py               # RSCSession — token fetch, proactive refresh, TLS
├── classify.py           # Protection status logic, DNP detection, tag extraction
├── config.py             # All settings, env var validation, TLS constant
├── exceptions.py         # RSCAuthError, RSCAPIError, RSCConfigError
├── extract.py            # GraphQL query builders, parallel stream specs
├── main.py               # Entry point, IncrementalCSVWriter, run audit log
├── queries.py            # HTTP layer, pagination, retry, rate limiting
└── output/               # Runtime output (gitignored, chmod 0o700)
    ├── compliance_report_*.csv
    ├── compliance_summary_*.csv
    ├── unprotected_objects_*.csv
    ├── non_compliant_objects_*.csv
    └── run_audit_*.log
```

---

## Security

This tool was reviewed against **OWASP Top 10 (2021)**, **NIST Cybersecurity Framework**, **CIS Controls v8**, **ISO 27001:2022**, and **SOC 2**. The following hardening measures are in place:

### Credential Protection
- Credentials are loaded exclusively from environment variables or `.env` — never hardcoded in source.
- All three required variables (`RSC_URL`, `RSC_CLIENT_ID`, `RSC_CLIENT_SECRET`) are validated at startup. Missing or empty values raise a clear `EnvironmentError` and halt execution before any API calls are made.

### Secure File Handling
- All output files are written with `chmod 0o600` (owner read/write only) on every flush. The output directory is created with `chmod 0o700`.
- Output files contain AWS account numbers, resource IDs, VPC topology, SLA assignments, and backup compliance status — treat them accordingly.

### Network Security
- TLS certificate verification is explicitly enforced via a `TLS_VERIFY` constant used on every `requests` call. SSL errors are never retried and always raise immediately.
- Custom CA bundles are supported via `RSC_CA_BUNDLE` for corporate proxy environments. Disabling verification entirely is not supported.

### GraphQL Injection Prevention
- All variable values — including datetime bounds for the history window — are passed through the GraphQL `variables` dict, never string-interpolated into query bodies. Query strings contain only static structure and typed variable declarations (`$rangeStart: DateTime`, `$rangeEnd: DateTime`).

### Error Handling
- Raw API response bodies are never printed to stdout or included in exception messages. Error output is limited to HTTP status codes and exception type names.
- Custom typed exceptions (`RSCAuthError`, `RSCAPIError`) replace `SystemExit`, ensuring cleanup code runs on failure and callers can handle specific error modes.

### Dependency Auditing
All dependencies are pinned in `requirements.txt`, including a minimum `PyJWT>=2.4.0` to address CVE-2022-29217. Run a local audit with:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```

### Reporting Vulnerabilities
See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Please do **not** open a public GitHub issue for security vulnerabilities.

---

## Troubleshooting

**"Required environment variable is not set" on startup**
Check that `RSC_URL`, `RSC_CLIENT_ID`, and `RSC_CLIENT_SECRET` are all set in your `.env` file. `RSC_URL` must include the `https://` scheme (e.g. `https://your-org.my.rubrik.com`).

**"Authentication failed (401)"**
Verify your `RSC_CLIENT_ID` and `RSC_CLIENT_SECRET`. Confirm the service account is active in RSC Settings → Service Accounts and has not expired.

**"Authentication forbidden (403)"**
The service account exists but lacks the required permissions. Check that it has read access to AWS native objects and snappable compliance data.

**"TLS certificate verification failed"**
Your environment uses a corporate TLS inspection proxy. Set `RSC_CA_BUNDLE=/path/to/ca-bundle.crt` in your `.env` file. Never set `verify=False`.

**Token expiry during long runs**
The token is refreshed automatically 5 minutes before expiry. If you see a 401 mid-run, the tool will force a refresh and retry the request exactly once. Persistent 401s after refresh indicate a credential or service account issue.

**Rate limiting (429 responses)**
The tool respects `Retry-After` headers and retries without counting the 429 against the failure budget. Frequent 429s suggest the concurrent stream count (`MAX_WORKERS`) or page size (`PAGE_SIZE`) may need reducing.

**Empty report / no objects found**
Verify the service account has read access to AWS native objects in RSC. Check that AWS accounts are connected and showing objects in the RSC UI. The time window defaults to the past 12 months — objects created or deleted outside this window may not appear in compliance data.

**Slow runs / timeouts**
Each request has a `REQUEST_TIMEOUT` of 120 seconds. Reduce `MAX_WORKERS` or `PAGE_SIZE` in `config.py` if you see consistent timeout errors. Compliance enrichment and inventory fetches run concurrently — individual stream failures are logged and retried up to `MAX_RETRIES` times.

---

## Updating

```bash
cd rsc-compliance-report
source venv/bin/activate
git pull
pip install -r requirements.txt    # picks up any updated pinned deps
python main.py
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please run `pip-audit -r requirements.txt` before submitting and ensure new GraphQL variable values are passed through the `variables` dict rather than interpolated into query strings.

---

## Legal & Disclaimer

This project is an **independent, open-source tool** and is **not affiliated with, authorized, maintained, sponsored, or endorsed by Rubrik, Inc.** in any way. All product and company names are the registered trademarks of their respective owners. The use of any trade name or trademark is for identification and reference purposes only and does not imply any affiliation with or endorsement by the trademark holder.

This software is provided **"as-is," without warranty of any kind**, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement. Use of this tool is entirely at your own risk. The authors and contributors are not responsible for any data loss, API rate-limit overages, account suspensions, security incidents, or other damages resulting from the use or misuse of this software.

You must have a valid API key and an active subscription or license for Rubrik Security Cloud (RSC). This software does not bypass any licensing checks or provide unauthorised access to Rubrik features.

The compliance status, protection classifications, and coverage percentages produced by this tool are derived from data available through the RSC GraphQL API at the time of the run. They are provided for informational and audit-assistance purposes only and should not be relied upon as the sole basis for security, compliance, or regulatory decisions. Always validate findings against your authoritative compliance management processes.

For questions about the security design of this tool, open a GitHub Discussion. To report a vulnerability, follow the process in [SECURITY.md](SECURITY.md).

---

## License

[Apache 2.0](LICENSE)
