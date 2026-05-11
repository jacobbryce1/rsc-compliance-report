#!/usr/bin/env python3
"""Quick test to find correct EC2 enum and account number approach."""

from auth import get_session
from queries import run_query


def main():
    session = get_session()

    # Test EC2 enum variants
    print("=== Testing EC2 ObjectTypeEnum variants ===\n")
    for enum_val in ["AwsNativeEc2Instance", "Ec2Instance", "RubrikEc2Instance"]:
        query = f"""
        query {{
          snappableConnection(
            first: 5
            filter: {{
              objectType: [{enum_val}]
            }}
          ) {{
            nodes {{
              id
              name
              complianceStatus
              lastSnapshot
            }}
            pageInfo {{ hasNextPage }}
          }}
        }}
        """
        data = run_query(session, query)
        if data:
            nodes = data.get("snappableConnection", {}).get("nodes", [])
            print(f"  {enum_val}: {len(nodes)} results")
            for n in nodes[:2]:
                print(f"    {n.get('name')}: {n.get('complianceStatus')} (last: {n.get('lastSnapshot')})")
        else:
            print(f"  {enum_val}: FAILED")
        print()

    # Test account number approaches
    print("=== Testing account number discovery ===\n")

    # Approach 1: AwsCloudAccountConfigsInput - discover what it needs
    query = """
    query {
      __type(name: "AwsCloudAccountConfigsInput") {
        inputFields {
          name
          type { name kind ofType { name kind } }
        }
      }
    }
    """
    data = run_query(session, query)
    if data and data.get("__type"):
        print("  AwsCloudAccountConfigsInput fields:")
        for f in data["__type"]["inputFields"]:
            type_info = f["type"]
            type_str = type_info.get("name") or f"{type_info.get('kind')}({type_info.get('ofType', {}).get('name')})"
            print(f"    {f['name']}: {type_str}")

    # Approach 2: Try getting account info from awsNativeAccount directly
    print("\n  Testing awsNativeAccount for account number...")
    query2 = """
    query {
      awsNativeAccounts(
        first: 3
        awsNativeProtectionFeature: EC2
      ) {
        nodes {
          id
          name
          status
          cloudSlabDns
          cloudType
          serviceType
        }
      }
    }
    """
    data = run_query(session, query2)
    if data:
        for acct in data.get("awsNativeAccounts", {}).get("nodes", []):
            print(f"    {acct.get('name')}: id={acct.get('id')}, dns={acct.get('cloudSlabDns')}, type={acct.get('cloudType')}, service={acct.get('serviceType')}")

    # Approach 3: Get account number from EC2 instance's cloudNativeId pattern
    print("\n  Testing EC2 cloudNativeId + account details...")
    query3 = """
    query {
      awsNativeEc2Instances(first: 2, ec2InstanceFilters: {}) {
        nodes {
          instanceName
          instanceNativeId
          cloudNativeId
          awsAccountRubrikId
          awsNativeAccountDetails {
            id
            name
            status
          }
          awsAccount {
            id
            name
            cloudSlabDns
          }
        }
      }
    }
    """
    data = run_query(session, query3)
    if data:
        for node in data.get("awsNativeEc2Instances", {}).get("nodes", []):
            print(f"    Instance: {node.get('instanceName')}")
            print(f"      instanceNativeId: {node.get('instanceNativeId')}")
            print(f"      cloudNativeId: {node.get('cloudNativeId')}")
            print(f"      awsAccountRubrikId: {node.get('awsAccountRubrikId')}")
            print(f"      awsNativeAccountDetails: {node.get('awsNativeAccountDetails')}")
            print(f"      awsAccount: {node.get('awsAccount')}")
            print()

    # Approach 4: S3 snappableConnection location field
    print("\n  Testing S3 location field values...")
    query4 = """
    query {
      snappableConnection(
        first: 5
        filter: { objectType: [AWS_NATIVE_S3_BUCKET] }
      ) {
        nodes {
          name
          location
        }
      }
    }
    """
    data = run_query(session, query4)
    if data:
        for node in data.get("snappableConnection", {}).get("nodes", []):
            print(f"    {node.get('name')}: location='{node.get('location')}'")


if __name__ == "__main__":
    main()
