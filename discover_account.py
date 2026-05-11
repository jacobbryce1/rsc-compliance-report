#!/usr/bin/env python3
"""
RSC Account Number Discovery — Round 2

The first discovery pass showed AwsNativeAccount has no obvious
scalar field for the 12-digit AWS account number.  This script
probes the three most likely hiding spots:

  1. physicalPath nodes — in RSC, the hierarchy path node for an
     AWS account often has the 12-digit account ID as its 'name'.

  2. cloudSlabDns — a String field that may encode the account ID.

  3. Nested awsNativeAccount sub-object on an EC2 instance —
     the per-instance relationship might expose more fields than
     the top-level account list.

  4. Introspect PathNode type to understand what physicalPath contains.

  5. Try awsNativeAccountId directly on an EC2 instance node.
"""

import json
import sys
from auth import get_session
from queries import run_query


def introspect_type(session, type_name):
    query = """
    query IntrospectType($name: String!) {
      __type(name: $name) {
        name
        fields {
          name
          type {
            name
            kind
            ofType { name kind }
          }
        }
      }
    }
    """
    data = run_query(session, query, variables={"name": type_name})
    if not data or not data.get("__type"):
        return None
    return data["__type"].get("fields") or []


def dump(label, obj):
    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"{'─'*60}")
    print(json.dumps(obj, indent=2, default=str))


def main():
    print(f"\n{'='*60}")
    print("RSC Account Number Discovery — Round 2")
    print(f"{'='*60}\n")

    session = get_session()

    # ── 1. Introspect PathNode ──
    print("[1] Introspecting PathNode type...")
    fields = introspect_type(session, "PathNode")
    if fields:
        for f in sorted(fields, key=lambda x: x["name"]):
            t = f["type"]
            type_str = t.get("name") or f"{t.get('kind')}({(t.get('ofType') or {}).get('name','?')})"
            print(f"    {f['name']:<35} {type_str}")
    else:
        print("  PathNode not found or no fields.")

    # ── 2. Live AwsNativeAccount with cloudSlabDns + physicalPath ──
    print("\n[2] Fetching AwsNativeAccount with cloudSlabDns and physicalPath...")
    q2 = """
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
          cloudSlabDns
          physicalPath {
            fid
            objectType
            name
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    data = run_query(session, q2, variables={"first": 5, "after": None})
    if data:
        nodes = data.get("awsNativeAccounts", {}).get("nodes", [])
        for node in nodes:
            dump(f"AwsNativeAccount: {node.get('name')}", node)
    else:
        print("  Query failed.")

    # ── 3. EC2 instance — try awsNativeAccountId scalar ──
    print("\n[3] EC2 instance — probing awsNativeAccountId scalar field...")
    q3 = """
    query DiscoverEC2Acct($first: Int, $after: String) {
      awsNativeEc2Instances(
        first: $first
        after: $after
        sortBy: EC2_INSTANCE_NAME
        ec2InstanceFilters: {}
      ) {
        nodes {
          id
          instanceName
          awsNativeAccountName
          awsAccountRubrikId
          awsNativeAccountId
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    data3 = run_query(session, q3, variables={"first": 1, "after": None})
    if data3:
        nodes = data3.get("awsNativeEc2Instances", {}).get("nodes", [])
        if nodes:
            dump("EC2 node with awsNativeAccountId", nodes[0])
        else:
            print("  No EC2 nodes returned.")
    else:
        print("  Query failed (awsNativeAccountId may not be a valid field).")

    # ── 4. Try awsNativeAccount nested sub-object on EC2 ──
    print("\n[4] EC2 instance — probing awsNativeAccount sub-object...")
    q4 = """
    query DiscoverEC2NestedAcct($first: Int, $after: String) {
      awsNativeEc2Instances(
        first: $first
        after: $after
        sortBy: EC2_INSTANCE_NAME
        ec2InstanceFilters: {}
      ) {
        nodes {
          id
          instanceName
          awsNativeAccount {
            id
            name
            cloudSlabDns
            physicalPath {
              fid
              objectType
              name
            }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    data4 = run_query(session, q4, variables={"first": 1, "after": None})
    if data4:
        nodes = data4.get("awsNativeEc2Instances", {}).get("nodes", [])
        if nodes:
            dump("EC2 node with nested awsNativeAccount", nodes[0])
        else:
            print("  No EC2 nodes returned.")
    else:
        print("  Query failed (awsNativeAccount sub-object may not exist on EC2).")

    # ── 5. Introspect AwsNativeEc2Instance for any account-related fields ──
    print("\n[5] Introspecting AwsNativeEc2Instance — account-related fields...")
    ec2_fields = introspect_type(session, "AwsNativeEc2Instance")
    if ec2_fields:
        acct_fields = [f for f in ec2_fields
                       if any(t in f["name"].lower() for t in ["account", "native", "cloud", "aws"])]
        print(f"  Account-related fields on AwsNativeEc2Instance ({len(acct_fields)} found):")
        for f in sorted(acct_fields, key=lambda x: x["name"]):
            t = f["type"]
            type_str = t.get("name") or f"{t.get('kind')}({(t.get('ofType') or {}).get('name','?')})"
            print(f"    {f['name']:<45} {type_str}")
    else:
        print("  AwsNativeEc2Instance not found.")

    # ── 6. Introspect AwsNativeRdsInstance — check awsNativeAccountDetails ──
    print("\n[6] Introspecting AwsNativeRdsInstance — account-related fields...")
    rds_fields = introspect_type(session, "AwsNativeRdsInstance")
    if rds_fields:
        acct_fields = [f for f in rds_fields
                       if any(t in f["name"].lower() for t in ["account", "native", "cloud", "aws"])]
        print(f"  Account-related fields on AwsNativeRdsInstance ({len(acct_fields)} found):")
        for f in sorted(acct_fields, key=lambda x: x["name"]):
            t = f["type"]
            type_str = t.get("name") or f"{t.get('kind')}({(t.get('ofType') or {}).get('name','?')})"
            print(f"    {f['name']:<45} {type_str}")

    # ── 7. Fetch one RDS instance with awsNativeAccountDetails ──
    print("\n[7] Fetching one RDS instance — probing awsNativeAccountDetails for account ID...")
    q7 = """
    query DiscoverRDS($first: Int, $after: String) {
      awsNativeRdsInstances(
        first: $first
        after: $after
        rdsInstanceFilters: {}
      ) {
        nodes {
          id
          dbInstanceName
          awsAccountRubrikId
          awsNativeAccountDetails {
            id
            name
            status
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    data7 = run_query(session, q7, variables={"first": 1, "after": None})
    if data7:
        nodes = data7.get("awsNativeRdsInstances", {}).get("nodes", [])
        if nodes:
            dump("RDS node with awsNativeAccountDetails", nodes[0])
    else:
        print("  Query failed.")

    print(f"\n{'='*60}")
    print("Discovery complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
