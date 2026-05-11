#!/usr/bin/env python3
"""
RSC Account Number Discovery — Round 3

From round 2 we know:
  - physicalPath is empty on all accounts
  - cloudSlabDns is a CloudSlab DNS name, not the account number
  - awsNativeAccountId scalar doesn't exist on EC2
  - awsNativeAccountDetails exists on BOTH EC2 and RDS (type: AwsNativeAccountDetails)
  - We've only ever queried id/name/status from it

This script:
  1. Introspects AwsNativeAccountDetails to find all fields (especially any account number)
  2. Fetches a live EC2 with all AwsNativeAccountDetails fields
  3. Introspects AwsNativeEbsVolume for account fields (EBS is our biggest object type)
  4. Checks whether Snappable.protectionStatus values match our classification states
  5. Fetches a live S3 snappable including protectionStatus
"""

import json
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


def introspect_enum(session, type_name):
    query = """
    query IntrospectEnum($name: String!) {
      __type(name: $name) {
        name
        enumValues { name }
      }
    }
    """
    data = run_query(session, query, variables={"name": type_name})
    if not data or not data.get("__type"):
        return None
    return [v["name"] for v in (data["__type"].get("enumValues") or [])]


def dump(label, obj):
    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"{'─'*60}")
    print(json.dumps(obj, indent=2, default=str))


def main():
    print(f"\n{'='*60}")
    print("RSC Account Number Discovery — Round 3")
    print(f"{'='*60}\n")

    session = get_session()

    # ── 1. Introspect AwsNativeAccountDetails ──
    print("[1] Introspecting AwsNativeAccountDetails...")
    fields = introspect_type(session, "AwsNativeAccountDetails")
    if fields:
        print(f"  {len(fields)} fields found:")
        for f in sorted(fields, key=lambda x: x["name"]):
            t = f["type"]
            type_str = t.get("name") or f"{t.get('kind')}({(t.get('ofType') or {}).get('name','?')})"
            flag = "  ◄◄◄" if any(k in f["name"].lower() for k in ["account", "native", "id", "number", "cloud", "external"]) else ""
            print(f"    {f['name']:<40} {type_str}{flag}")
    else:
        print("  AwsNativeAccountDetails not found.")

    # ── 2. Live EC2 with full AwsNativeAccountDetails ──
    print("\n[2] Fetching EC2 with full awsNativeAccountDetails...")
    q2 = """
    query DiscoverEC2AccountDetails($first: Int, $after: String) {
      awsNativeEc2Instances(
        first: $first
        after: $after
        sortBy: EC2_INSTANCE_NAME
        ec2InstanceFilters: {}
      ) {
        nodes {
          id
          instanceName
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
    data2 = run_query(session, q2, variables={"first": 1, "after": None})
    if data2:
        nodes = data2.get("awsNativeEc2Instances", {}).get("nodes", [])
        if nodes:
            dump("EC2 node with awsNativeAccountDetails", nodes[0])
    else:
        print("  Query failed.")

    # ── 3. Introspect AwsNativeEbsVolume for account fields ──
    print("\n[3] Introspecting AwsNativeEbsVolume — account-related fields...")
    ebs_fields = introspect_type(session, "AwsNativeEbsVolume")
    if ebs_fields:
        acct_fields = [f for f in ebs_fields
                       if any(k in f["name"].lower() for k in ["account", "native", "cloud", "aws"])]
        print(f"  {len(acct_fields)} account-related fields:")
        for f in sorted(acct_fields, key=lambda x: x["name"]):
            t = f["type"]
            type_str = t.get("name") or f"{t.get('kind')}({(t.get('ofType') or {}).get('name','?')})"
            print(f"    {f['name']:<45} {type_str}")

    # ── 4. Live EBS with awsNativeAccountDetails ──
    print("\n[4] Fetching EBS with awsNativeAccountDetails...")
    q4 = """
    query DiscoverEBS($first: Int, $after: String) {
      awsNativeEbsVolumes(
        first: $first
        after: $after
        ebsVolumeFilters: {}
      ) {
        nodes {
          id
          volumeName
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
    data4 = run_query(session, q4, variables={"first": 1, "after": None})
    if data4:
        nodes = data4.get("awsNativeEbsVolumes", {}).get("nodes", [])
        if nodes:
            dump("EBS node with awsNativeAccountDetails", nodes[0])
    else:
        print("  Query failed.")

    # ── 5. ProtectionStatusEnum values ──
    print("\n[5] Introspecting ProtectionStatusEnum values...")
    values = introspect_enum(session, "ProtectionStatusEnum")
    if values:
        print(f"  ProtectionStatusEnum values: {values}")
    else:
        print("  Not found.")

    # ── 6. SlaAssignmentTypeEnum values (what AwsNativeAccount.slaAssignment returns) ──
    print("\n[6] Introspecting SlaAssignmentTypeEnum values...")
    sla_values = introspect_enum(session, "SlaAssignmentTypeEnum")
    if sla_values:
        print(f"  SlaAssignmentTypeEnum values: {sla_values}")
    else:
        print("  Not found.")

    # ── 7. Live S3 snappable including protectionStatus ──
    print("\n[7] Fetching S3 snappable with protectionStatus...")
    q7 = """
    query DiscoverS3Proto($first: Int, $after: String) {
      snappableConnection(
        first: $first
        after: $after
        filter: { objectType: [AWS_NATIVE_S3_BUCKET] }
      ) {
        nodes {
          id
          name
          complianceStatus
          protectionStatus
          archivalComplianceStatus
          replicationComplianceStatus
          slaDomain {
            id
            name
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    data7 = run_query(session, q7, variables={"first": 3, "after": None})
    if data7:
        nodes = data7.get("snappableConnection", {}).get("nodes", [])
        for node in nodes:
            dump(f"S3 snappable: {node.get('name','?')}", node)
    else:
        print("  Query failed.")

    print(f"\n{'='*60}")
    print("Discovery complete.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
