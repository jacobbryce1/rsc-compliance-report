#!/usr/bin/env python3
"""
RSC Compliance Report Generator — 12-month history edition

Fetches EC2 / EBS / RDS / S3 / DynamoDB inventory and compliance data from Rubrik
Security Cloud for the past HISTORY_MONTHS, using parallel streams and
cursor-based pagination to stay well within API timeout limits.

Output files (written to OUTPUT_DIR, permissions 0o600):
  compliance_report_<timestamp>.csv     — full per-object detail
  compliance_summary_<timestamp>.csv    — per-account coverage table
  unprotected_objects_<timestamp>.csv   — UNPROTECTED objects only
  non_compliant_objects_<timestamp>.csv — PROTECTED_NON_COMPLIANT only
  run_audit_<timestamp>.log             — structured run audit record
"""

import csv
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone

from dateutil.relativedelta import relativedelta

import pandas as pd

from config import OUTPUT_DIR, HISTORY_MONTHS, CSV_FLUSH_ROWS
from auth import get_session
from exceptions import RSCAuthError, RSCAPIError, RSCConfigError
from extract import (
    get_sla_domains,
    get_aws_accounts,
    get_aws_cloud_account_native_ids,
    get_compliance_status_all,
    get_all_objects_concurrent,
)
from classify import flatten_object, build_account_lookup


# ─────────────────────────────────────────────
# TIME WINDOW
# ─────────────────────────────────────────────

def build_time_window(months=HISTORY_MONTHS):
    """Return (start_iso, end_iso) for the last `months` calendar months."""
    now = datetime.now(tz=timezone.utc)
    start = now - relativedelta(months=months)
    start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), now.strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────
# INCREMENTAL CSV WRITER
# ─────────────────────────────────────────────

class IncrementalCSVWriter:
    """
    Buffers rows in memory and flushes to disk every `flush_every` rows.
    Writes the header once on first flush, then appends subsequent batches.

    Security: output files are created with mode 0o600 (owner read/write only)
    because they contain cloud infrastructure inventory data (account numbers,
    resource IDs, backup compliance status).
    """

    def __init__(self, path, flush_every=CSV_FLUSH_ROWS):
        self.path = path
        self.flush_every = flush_every
        self._buffer = []
        self._fieldnames = None
        self._header_written = False
        self.total_written = 0

    def add(self, row: dict):
        if self._fieldnames is None:
            self._fieldnames = list(row.keys())
        self._buffer.append(row)
        if len(self._buffer) >= self.flush_every:
            self.flush()

    def flush(self):
        if not self._buffer:
            return
        mode = "a" if self._header_written else "w"
        with open(self.path, mode, newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=self._fieldnames, extrasaction="ignore")
            if not self._header_written:
                writer.writeheader()
                self._header_written = True
            writer.writerows(self._buffer)
        # Restrict to owner read/write — cloud inventory is sensitive
        os.chmod(self.path, 0o600)
        self.total_written += len(self._buffer)
        self._buffer = []

    def close(self):
        self.flush()


def _secure_write_csv(df, path):
    """Write a DataFrame to CSV and restrict permissions to 0o600."""
    df.to_csv(path, index=False)
    os.chmod(path, 0o600)


# ─────────────────────────────────────────────
# RUN AUDIT LOG
# ─────────────────────────────────────────────

def _write_audit_log(path: str, record: dict):
    """
    Write a structured JSON audit record for this run.

    Captured fields (ISO 27001 A.12.4 / CIS Control 8 / SOC 2 Security):
      - run_timestamp, history_window_start/end
      - hostname, python_version, platform
      - object_counts, total_objects
      - exit_status, error (if any)

    Security: the audit log does NOT contain credentials, tokens, or
    response body content.  It is written with 0o600 permissions.
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)
    os.chmod(path, 0o600)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    report_date = datetime.now().strftime("%Y-%m-%d")

    print(f"\n{'='*60}")
    print(f"RSC Compliance Report — {timestamp}")
    print(f"History window: {HISTORY_MONTHS} months")
    print(f"{'='*60}\n")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # Restrict the output directory itself to owner only
    os.chmod(OUTPUT_DIR, 0o700)

    audit = {
        "run_timestamp": timestamp,
        "hostname": socket.gethostname(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "history_months": HISTORY_MONTHS,
        "history_window_start": None,
        "history_window_end": None,
        "object_counts": {},
        "total_objects": 0,
        "exit_status": "IN_PROGRESS",
        "error": None,
    }
    audit_path = os.path.join(OUTPUT_DIR, f"run_audit_{timestamp}.log")

    try:
        # ── Time window ──
        start_time, end_time = build_time_window(HISTORY_MONTHS)
        audit["history_window_start"] = start_time
        audit["history_window_end"] = end_time
        print(f"Time window: {start_time}  →  {end_time}\n")

        session = get_session()

        # ── DISCOVERY ──
        print("\nFetching SLA Domains...")
        slas = get_sla_domains(session)
        print(f"   Found {len(slas)} SLA domains")

        print("\nFetching AWS Accounts...")
        accounts = get_aws_accounts(session)
        print(f"   Found {len(accounts)} AWS accounts")

        # Enrich accounts with 12-digit AWS account numbers via the cloud accounts endpoint
        print("   Fetching AWS account native IDs...")
        native_id_map = get_aws_cloud_account_native_ids(session)
        enriched = 0
        for acct in accounts:
            native_id = native_id_map.get(acct.get("id", ""))
            if native_id:
                acct["nativeId"] = native_id
                enriched += 1
        print(f"   Enriched {enriched}/{len(accounts)} accounts with 12-digit AWS account numbers")

        for acct in accounts[:10]:
            aws_num = acct.get("nativeId", "N/A")
            print(
                f"     - {acct.get('name')} [{aws_num}]"
                f"  EC2:{acct.get('ec2InstanceCount',0)}"
                f"  EBS:{acct.get('ebsVolumeCount',0)}"
                f"  RDS:{acct.get('rdsInstanceCount',0)}"
                f"  S3:{acct.get('s3BucketCount',0)}"
            )
        if len(accounts) > 10:
            print(f"     ... and {len(accounts) - 10} more")

        account_lookup = build_account_lookup(accounts)

        # ── COMPLIANCE ENRICHMENT (parallel streams) ──
        print("\nFetching compliance status (parallel, 12-month window)...")
        compliance_lookup = get_compliance_status_all(session, start_time, end_time)
        print(f"   Compliance data for {len(compliance_lookup)} objects\n")

        # ── INVENTORY EXTRACTION (parallel streams) ──
        print("Fetching object inventory (EC2 / EBS / RDS / S3 / DynamoDB in parallel)...")
        raw_streams = get_all_objects_concurrent(session, start_time, end_time)

        # ── FLATTEN + STREAM-WRITE TO CSV ──
        full_path = os.path.join(OUTPUT_DIR, f"compliance_report_{timestamp}.csv")
        writer = IncrementalCSVWriter(full_path, flush_every=CSV_FLUSH_ROWS)

        type_order = [("EC2", "EC2"), ("EBS", "EBS"), ("RDS", "RDS"), ("S3", "S3"), ("DynamoDB", "DynamoDB")]
        object_counts = {}

        for label, object_type in type_order:
            nodes = raw_streams.get(label, [])
            object_counts[object_type] = len(nodes)
            print(f"   Processing {len(nodes)} {object_type} objects...")
            for obj in nodes:
                row = flatten_object(obj, object_type, compliance_lookup, account_lookup)
                row["report_date"] = report_date
                row["report_timestamp"] = timestamp
                row["history_start"] = start_time
                row["history_end"] = end_time
                writer.add(row)

        writer.close()
        total = writer.total_written
        audit["object_counts"] = object_counts
        audit["total_objects"] = total

        print(f"\n{'_'*60}")
        print(f"Total objects written: {total}")
        for ot, cnt in object_counts.items():
            print(f"  {ot}: {cnt}")
        print(f"{'_'*60}")

        if total == 0:
            print("\nNo objects found.")
            audit["exit_status"] = "COMPLETED_EMPTY"
            _write_audit_log(audit_path, audit)
            return

        print(f"\nFull report: {full_path}")

        # ── SUMMARIES ──
        df = pd.read_csv(full_path)
        _print_summary(df)

        # ── SUMMARY CSV ──
        if df["aws_account_name"].str.len().sum() > 0:
            summary_path = os.path.join(OUTPUT_DIR, f"compliance_summary_{timestamp}.csv")
            _write_account_summary(df, summary_path)
            print(f"\nSummary: {summary_path}")

        # ── PROBLEM FILES ──
        unprotected_df = df[df["protection_status"] == "UNPROTECTED"]
        if not unprotected_df.empty:
            path = os.path.join(OUTPUT_DIR, f"unprotected_objects_{timestamp}.csv")
            _secure_write_csv(unprotected_df, path)
            print(f"Unprotected objects ({len(unprotected_df)}): {path}")

        non_compliant_df = df[df["protection_status"] == "PROTECTED_NON_COMPLIANT"]
        if not non_compliant_df.empty:
            path = os.path.join(OUTPUT_DIR, f"non_compliant_objects_{timestamp}.csv")
            _secure_write_csv(non_compliant_df, path)
            print(f"Non-compliant objects ({len(non_compliant_df)}): {path}")

        audit["exit_status"] = "COMPLETED"

    except RSCAuthError as exc:
        print(f"\nAUTHENTICATION ERROR: {exc}")
        print("Check your .env credentials and RSC service account permissions.")
        audit["exit_status"] = "FAILED_AUTH"
        audit["error"] = str(exc)
        _write_audit_log(audit_path, audit)
        sys.exit(1)

    except RSCAPIError as exc:
        print(f"\nAPI ERROR: {exc}")
        audit["exit_status"] = "FAILED_API"
        audit["error"] = str(exc)
        _write_audit_log(audit_path, audit)
        sys.exit(1)

    except KeyboardInterrupt:
        print("\nRun interrupted by user.")
        audit["exit_status"] = "INTERRUPTED"
        _write_audit_log(audit_path, audit)
        sys.exit(130)

    except Exception as exc:
        print(f"\nUNEXPECTED ERROR: {type(exc).__name__}: {exc}")
        audit["exit_status"] = "FAILED_UNEXPECTED"
        audit["error"] = f"{type(exc).__name__}: {exc}"
        _write_audit_log(audit_path, audit)
        raise

    finally:
        # Always write the audit log, even if we're about to raise
        if audit.get("exit_status") in ("COMPLETED", "COMPLETED_EMPTY"):
            _write_audit_log(audit_path, audit)

    print(f"\n{'='*60}")
    print(f"Done! Files in ./{OUTPUT_DIR}/")
    print(f"Audit log: {audit_path}")
    print(f"{'='*60}\n")


# ─────────────────────────────────────────────
# REPORTING HELPERS
# ─────────────────────────────────────────────

def _print_summary(df):
    print(f"\n{'_'*60}")
    print("PROTECTION STATUS SUMMARY")
    print(f"{'_'*60}")
    summary = df.groupby(["object_type", "protection_status"]).size().unstack(fill_value=0)
    print(summary.to_string())

    print(f"\n{'_'*60}")
    print("TOTALS")
    print(f"{'_'*60}")
    totals = df["protection_status"].value_counts()
    total = len(df)
    for status, count in totals.items():
        pct = 100 * count / total
        print(f"  {status}: {count} ({pct:.1f}%)")

    protected = totals.get("PROTECTED_COMPLIANT", 0) + totals.get("DO_NOT_PROTECT", 0)
    non_compliant = totals.get("PROTECTED_NON_COMPLIANT", 0)
    unprotected = totals.get("UNPROTECTED", 0)
    print(f"\n  AUDIT SUMMARY:")
    print(f"    Protected + DNP:  {protected}/{total} ({100*protected/total:.1f}%)")
    print(f"    Non-compliant:    {non_compliant}/{total} ({100*non_compliant/total:.1f}%)")
    print(f"    Unprotected:      {unprotected}/{total} ({100*unprotected/total:.1f}%)")

    print(f"\n{'_'*60}")
    print("SLA DISTRIBUTION")
    print(f"{'_'*60}")
    sla_dist = df.groupby(["sla_name", "object_type"]).size().unstack(fill_value=0)
    sla_dist["total"] = sla_dist.sum(axis=1)
    sla_dist = sla_dist.sort_values("total", ascending=False)
    print(sla_dist.head(15).to_string())

    print(f"\n{'_'*60}")
    print("COMPLIANCE DATA SOURCE")
    print(f"{'_'*60}")
    for src, count in df["compliance_status"].value_counts().items():
        print(f"  {src}: {count}")


def _write_account_summary(df, path):
    print(f"\n{'_'*60}")
    print("PER-ACCOUNT COVERAGE")
    print(f"{'_'*60}")

    # pandas read_csv converts empty strings to NaN; groupby dropna=True (default)
    # silently drops NaN index values producing an empty DataFrame.
    # Fill before grouping so every row is counted regardless of whether the
    # AWS account number is populated.
    df_acct = df.copy()
    df_acct["aws_account_number"] = df_acct["aws_account_number"].fillna("").astype(str)
    df_acct["aws_account_name"]   = df_acct["aws_account_name"].fillna("(unknown)").astype(str)

    acct_grp = (
        df_acct.groupby(["aws_account_number", "aws_account_name", "protection_status"])
        .size()
        .unstack(fill_value=0)
    )
    acct_grp["total"] = acct_grp.sum(axis=1)
    pc  = acct_grp.get("PROTECTED_COMPLIANT", 0)
    dnp = acct_grp.get("DO_NOT_PROTECT", 0)
    acct_grp["coverage_pct"] = ((pc + dnp) / acct_grp["total"] * 100).round(1)
    print(acct_grp.to_string())
    _secure_write_csv(acct_grp, path)


if __name__ == "__main__":
    main()
