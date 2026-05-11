#!/usr/bin/env python3
"""
RSC Field Discovery Script

Uses GraphQL introspection to answer two specific questions:

  1. What fields does AwsNativeAccount expose?
     → Find the right field name for the 12-digit AWS account number.

  2. What fields does the Snappable type expose?
     → Confirm whether slaAssignment is available and what it's called.

Also fetches one live AwsNativeAccount node and one live snappableConnection
node (S3 bucket) and dumps their raw JSON so we can see actual field values.
"""

import json
import sys
from auth import get_session
from queries import run_query


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def introspect_type(session, type_name):
    """Return all field names + types for a given GraphQL type via introspection."""
    query = """
    query IntrospectType($name: String!) {
      __type(name: $name) {
        name
        kind
        fields {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
      }
    }
    """
    data = run_query(session, query, variables={"name": type_name})
    if not data or not data.get("__type"):
        print(f"  Type '{type_name}' not found in schema (None returned).")
        return []
    fields = data["__type"].get("fields") or []
    return fields


def print_fields(type_name, fields, filter_terms=None):
    """Pretty-print field list, optionally highlighting matches."""
    print(f"\n{'─'*60}")
    print(f"  Type: {type_name}  ({len(fields)} fields)")
    print(f"{'─'*60}")
    for f in sorted(fields, key=lambda x: x["name"]):
        t = f["type"]
        type_str = t.get("name") or f"{t.get('kind')}({(t.get('ofType') or {}).get('name', '?')})"
        flag = ""
        if filter_terms:
            if any(term.lower() in f["name"].lower() for term in filter_terms):
                flag = "  ◄◄◄"
        print(f"    {f['name']:<45} {type_str}{flag}")


def fetch_raw_node(session, query, path, label):
    """Fetch the first node from a paginated query and dump it as JSON."""
    data = run_query(session, query, variables={"first": 1, "after": None})
    if not data:
        print(f"  No data returned for {label}.")
        return
    conn = data
    for key in path.split("."):
        conn = conn.get(key, {})
    nodes = conn.get("nodes", [])
    if not nodes:
        print(f"  No nodes returned for {label}.")
        return
    print(f"\n{'─'*60}")
    print(f"  Raw node dump: {label}")
    print(f"{'─'*60}")
    print(json.dumps(nodes[0], indent=2, default=str))


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    print(f"\n{'='*60}")
    print("RSC Field Discovery")
    print(f"{'='*60}\n")

    session = get_session()

    # ── 1. AwsNativeAccount — find the AWS account number field ──
    print("\n[1] Introspecting AwsNativeAccount...")
    print("    Looking for fields containing: account, native, cloud, external, id, number")
    fields = introspect_type(session, "AwsNativeAccount")
    if fields:
        print_fields(
            "AwsNativeAccount",
            fields,
            filter_terms=["account", "native", "cloud", "external", "id", "number"],
        )

    # ── 2. Snappable — find slaAssignment and related fields ──
    print("\n[2] Introspecting Snappable type...")
    print("    Looking for fields containing: sla, assignment, compliance, protection")
    fields_snappable = introspect_type(session, "Snappable")
    if fields_snappable:
        print_fields(
            "Snappable",
            fields_snappable,
            filter_terms=["sla", "assignment", "compliance", "protection"],
        )

    # ── 3. Also try CdmHierarchySnappable in case Snappable is an interface ──
    print("\n[3] Introspecting CdmHierarchySnappable (fallback)...")
    fields_cdm = introspect_type(session, "CdmHierarchySnappable")
    if fields_cdm:
        print_fields(
            "CdmHierarchySnappable",
            fields_cdm,
            filter_terms=["sla", "assignment", "compliance", "protection"],
        )

    # ── 4. Live raw node: one AwsNativeAccount ──
    print("\n[4] Fetching one live AwsNativeAccount node (all scalar fields)...")
    acct_query = """
    query DiscoverAccount($first: Int, $after: String) {
      awsNativeAccounts(
        first: $first
        after: $after
        sortBy: NAME
        sortOrder: ASC
        awsNativeProtectionFeature: EC2
      ) {
        nodes {
          id
          name
          status
          ec2InstanceCount
          ebsVolumeCount
          rdsInstanceCount
          s3BucketCount
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    fetch_raw_node(session, acct_query, "awsNativeAccounts", "AwsNativeAccount node")

    # ── 5. Live raw node: one S3 snappable ──
    print("\n[5] Fetching one live snappableConnection node (S3 bucket)...")
    snap_query = """
    query DiscoverSnappable($first: Int, $after: String) {
      snappableConnection(
        first: $first
        after: $after
        filter: { objectType: [AWS_NATIVE_S3_BUCKET] }
      ) {
        nodes {
          id
          name
          objectType
          complianceStatus
          location
          lastSnapshot
          localSnapshots
          missedSnapshots
          archiveSnapshots
          totalSnapshots
          physicalBytes
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    fetch_raw_node(session, snap_query, "snappableConnection", "snappableConnection S3 node")

    # ── 6. Live raw node: one EC2 instance — check for account number fields ──
    print("\n[6] Fetching one live EC2 instance node (checking account fields)...")
    ec2_query = """
    query DiscoverEC2($first: Int, $after: String) {
      awsNativeEc2Instances(
        first: $first
        after: $after
        sortBy: EC2_INSTANCE_NAME
        ec2InstanceFilters: {}
      ) {
        nodes {
          id
          instanceName
          instanceNativeId
          region
          awsNativeAccountName
          awsAccountRubrikId
          slaAssignment
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    fetch_raw_node(session, ec2_query, "awsNativeEc2Instances", "EC2 instance node")

    print(f"\n{'='*60}")
    print("Discovery complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
