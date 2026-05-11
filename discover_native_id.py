#!/usr/bin/env python3
"""
Test allAwsCloudAccountsFeaturesWithExoConfigs — find valid enum values
and confirm nativeId returns the 12-digit AWS account number.
"""
import json
from auth import get_session
from queries import run_query


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
        return []
    return [v["name"] for v in (data["__type"].get("enumValues") or [])]


def main():
    session = get_session()

    # Step 1 — discover valid enum values
    print("Introspecting CloudAccountFeature enum...")
    features = introspect_enum(session, "CloudAccountFeature")
    print(f"  Values: {features}\n")

    print("Introspecting CloudAccountStatus enum...")
    statuses = introspect_enum(session, "CloudAccountStatus")
    print(f"  Values: {statuses}\n")

    query = """
    query AwsCloudAccountsList(
      $feature: CloudAccountFeature!
      $statusFilters: [CloudAccountStatus!]!
    ) {
      allAwsCloudAccountsFeaturesWithExoConfigs(awsCloudAccountsArg: {
        feature: $feature
        statusFilters: $statusFilters
        includeInternalFeatures: true
      }) {
        awsCloudAccount {
          id
          nativeId
          accountName
          cloudType
          orgName
          orgId
          serviceType
        }
      }
    }
    """

    # Step 2 — try all status combinations with all features
    status_combos = [statuses] if statuses else [["CONNECTED"], ["CONNECTED", "DISCONNECTED"]]

    for feature in (features or ["CLOUD_NATIVE_PROTECTION", "NATIVE_PROTECTION"]):
        for status_list in status_combos:
            print(f"Trying feature={feature}, statusFilters={status_list}...")
            data = run_query(session, query, variables={
                "feature": feature,
                "statusFilters": status_list,
            })
            if data is None:
                print("  Query failed (400 or error).")
                continue
            accounts = data.get("allAwsCloudAccountsFeaturesWithExoConfigs", [])
            if accounts:
                print(f"  SUCCESS — {len(accounts)} accounts returned:")
                for a in accounts:
                    acct = a.get("awsCloudAccount", {})
                    print(json.dumps(acct, indent=4))
                # Found results — stop searching
                return
            else:
                print("  0 accounts returned.")

    print("\nNo accounts found with any feature/status combination.")


if __name__ == "__main__":
    main()
