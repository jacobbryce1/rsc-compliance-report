"""
Data extraction layer — GraphQL queries against Rubrik Security Cloud.

Historical window note:
  The RSC GraphQL inventory endpoints (awsNativeEc2Instances, awsNativeEbsVolumes,
  awsNativeRdsInstances) and snappableConnection do not accept a timeRange argument.
  Queries return current object state plus full snapshot history fields
  (newestSnapshot, oldestSnapshot, missedSnapshots, totalSnapshots) which naturally
  cover the entire protection history.  The 12-month window is recorded in the
  report output columns (history_start, history_end) for downstream CSV filtering.
"""

from queries import run_query, run_paginated_query, run_concurrent_paginated_queries
from config import PAGE_SIZE, MAX_WORKERS


# ─────────────────────────────────────────────
# DISCOVERY QUERIES
# ─────────────────────────────────────────────

def get_sla_domains(session):
    """Fetch all SLA domains."""
    query = """
    query ListSLAs {
      slaDomains(first: 100, filter: []) {
        nodes {
          id
          name
          ... on GlobalSlaReply {
            objectTypes
            description
          }
        }
      }
    }
    """
    data = run_query(session, query)
    if data:
        return data["slaDomains"]["nodes"]
    return []


def get_aws_accounts(session):
    """Fetch all connected AWS accounts."""
    query = """
    query ListAWSAccounts($first: Int, $after: String) {
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
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
    return run_paginated_query(session, query, "awsNativeAccounts", label="AWS Accounts")


def get_aws_cloud_account_native_ids(session):
    """
    Fetch the 12-digit AWS account number (nativeId) for all accounts via
    allAwsCloudAccountsFeaturesWithExoConfigs.

    This endpoint is the only one in RSC that exposes the real AWS account ID.
    Requires feature=CLOUD_NATIVE_PROTECTION and all status values to ensure
    every connected account is returned regardless of current health state.

    Returns:
        dict keyed by RSC UUID → 12-digit AWS account number string
        e.g. {"4ef32b15-...": "638694371957", ...}
    """
    query = """
    query AwsCloudAccountNativeIds(
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
        }
      }
    }
    """
    data = run_query(session, query, variables={
        "feature": "CLOUD_NATIVE_PROTECTION",
        "statusFilters": [
            "CONNECTING", "CONNECTED", "DISABLED",
            "DISCONNECTED", "MISSING_PERMISSIONS", "DISABLING",
        ],
    })

    result = {}
    if data:
        for entry in data.get("allAwsCloudAccountsFeaturesWithExoConfigs", []):
            acct = entry.get("awsCloudAccount", {})
            rubrik_id  = acct.get("id", "")
            native_id  = acct.get("nativeId", "")
            acct_name  = acct.get("accountName", "")
            if rubrik_id and native_id:
                result[rubrik_id] = native_id
            # Also key by account name as a secondary join path
            if acct_name and native_id:
                result[f"name:{acct_name}"] = native_id
    return result


# ─────────────────────────────────────────────
# OBJECT INVENTORY — STREAM SPECS
# ─────────────────────────────────────────────

def _ec2_stream_spec():
    query = """
    query EC2Inventory($first: Int, $after: String) {
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
          instanceType
          vpcId
          awsNativeAccountName
          awsAccountRubrikId
          effectiveSlaDomain {
            id
            name
          }
          newestSnapshot {
            date
            id
          }
          oldestSnapshot {
            date
          }
          tags {
            key
            value
          }
          isRelic
          slaPauseStatus
          slaAssignment
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
    return {
        "label": "EC2",
        "query": query,
        "path_to_connection": "awsNativeEc2Instances",
    }


def _ebs_stream_spec():
    query = """
    query EBSInventory($first: Int, $after: String) {
      awsNativeEbsVolumes(
        first: $first
        after: $after
        ebsVolumeFilters: {}
      ) {
        nodes {
          id
          volumeName
          volumeNativeId
          volumeType
          region
          sizeInGiBs
          availabilityZone
          awsNativeAccountName
          awsAccountRubrikId
          effectiveSlaDomain {
            id
            name
          }
          newestSnapshot {
            date
            id
          }
          oldestSnapshot {
            date
          }
          tags {
            key
            value
          }
          isRelic
          slaPauseStatus
          slaAssignment
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
    return {
        "label": "EBS",
        "query": query,
        "path_to_connection": "awsNativeEbsVolumes",
    }


def _rds_stream_spec():
    query = """
    query RDSInventory($first: Int, $after: String) {
      awsNativeRdsInstances(
        first: $first
        after: $after
        rdsInstanceFilters: {}
      ) {
        nodes {
          id
          dbInstanceName
          dbEngine
          dbInstanceClass
          region
          vpcId
          isMultiAz
          awsNativeAccountDetails {
            id
            name
            status
          }
          awsAccountRubrikId
          effectiveSlaDomain {
            id
            name
          }
          newestSnapshot {
            date
            id
          }
          oldestSnapshot {
            date
          }
          tags {
            key
            value
          }
          isRelic
          slaPauseStatus
          slaAssignment
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
    return {
        "label": "RDS",
        "query": query,
        "path_to_connection": "awsNativeRdsInstances",
    }


def _s3_stream_spec():
    query = """
    query S3Inventory($first: Int, $after: String) {
      snappableConnection(
        first: $first
        after: $after
        filter: {
          objectType: [AWS_NATIVE_S3_BUCKET]
        }
      ) {
        nodes {
          id
          name
          objectType
          slaDomain {
            id
            name
          }
          complianceStatus
          protectionStatus
          archivalComplianceStatus
          replicationComplianceStatus
          location
          lastSnapshot
          localSnapshots
          missedSnapshots
          archiveSnapshots
          totalSnapshots
          physicalBytes
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
    return {
        "label": "S3",
        "query": query,
        "path_to_connection": "snappableConnection",
    }


def _dynamodb_stream_spec():
    query = """
    query DynamoDBInventory($first: Int, $after: String) {
      snappableConnection(
        first: $first
        after: $after
        filter: {
          objectType: [AWS_NATIVE_DYNAMODB_TABLE]
        }
      ) {
        nodes {
          id
          name
          objectType
          slaDomain {
            id
            name
          }
          complianceStatus
          protectionStatus
          archivalComplianceStatus
          replicationComplianceStatus
          location
          lastSnapshot
          localSnapshots
          missedSnapshots
          archiveSnapshots
          totalSnapshots
          physicalBytes
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
    return {
        "label": "DynamoDB",
        "query": query,
        "path_to_connection": "snappableConnection",
    }


# ─────────────────────────────────────────────
# PUBLIC INVENTORY FETCHERS
# ─────────────────────────────────────────────

def get_ec2_instances(session, start_time=None, end_time=None):
    """Fetch all EC2 instances."""
    spec = _ec2_stream_spec()
    return run_paginated_query(session, spec["query"], spec["path_to_connection"], label="EC2")


def get_ebs_volumes(session, start_time=None, end_time=None):
    """Fetch all EBS volumes."""
    spec = _ebs_stream_spec()
    return run_paginated_query(session, spec["query"], spec["path_to_connection"], label="EBS")


def get_rds_instances(session, start_time=None, end_time=None):
    """Fetch all RDS instances."""
    spec = _rds_stream_spec()
    return run_paginated_query(session, spec["query"], spec["path_to_connection"], label="RDS")


def get_s3_buckets(session, start_time=None, end_time=None):
    """Fetch all S3 buckets."""
    spec = _s3_stream_spec()
    return run_paginated_query(session, spec["query"], spec["path_to_connection"], label="S3")


def get_dynamodb_tables(session, start_time=None, end_time=None):
    """Fetch all DynamoDB tables."""
    spec = _dynamodb_stream_spec()
    return run_paginated_query(session, spec["query"], spec["path_to_connection"], label="DynamoDB")


def get_all_objects_concurrent(session, start_time=None, end_time=None):
    """
    Fetch EC2, EBS, RDS, S3, and DynamoDB objects in parallel using multiple streams.

    Returns:
        dict keyed by object type label → list of raw node dicts
        e.g. {"EC2": [...], "EBS": [...], "RDS": [...], "S3": [...], "DynamoDB": [...]}
    """
    specs = [
        _ec2_stream_spec(),
        _ebs_stream_spec(),
        _rds_stream_spec(),
        _s3_stream_spec(),
        _dynamodb_stream_spec(),
    ]
    return run_concurrent_paginated_queries(session, specs, max_workers=MAX_WORKERS)


# ─────────────────────────────────────────────
# COMPLIANCE ENRICHMENT
# ─────────────────────────────────────────────

def get_compliance_status_all(session, start_time=None, end_time=None):
    """
    Fetch compliance status for all AWS objects via snappableConnection.

    Returns a dict keyed by RSC object ID containing complianceStatus,
    lastSnapshot, missedSnapshots, totalSnapshots, and location.
    """
    type_map = {
        "EC2": "Ec2Instance",
        "EBS": "AwsNativeEbsVolume",
        "RDS": "AwsNativeRdsInstance",
    }

    specs = []
    for display_name, enum_value in type_map.items():
        query = f"""
        query Compliance_{display_name}($first: Int, $after: String) {{
          snappableConnection(
            first: $first
            after: $after
            filter: {{
              objectType: [{enum_value}]
            }}
          ) {{
            nodes {{
              id
              name
              complianceStatus
              lastSnapshot
              missedSnapshots
              archiveSnapshots
              totalSnapshots
              location
            }}
            pageInfo {{
              hasNextPage
              endCursor
            }}
          }}
        }}
        """
        specs.append({
            "label": f"compliance_{display_name}",
            "query": query,
            "path_to_connection": "snappableConnection",
        })

    print("   Fetching compliance data concurrently for EC2 / EBS / RDS...")
    streams = run_concurrent_paginated_queries(session, specs, max_workers=MAX_WORKERS)

    all_compliance = {}
    for label, nodes in streams.items():
        for node in nodes:
            all_compliance[node["id"]] = {
                "complianceStatus": node.get("complianceStatus"),
                "lastSnapshot":     node.get("lastSnapshot"),
                "missedSnapshots":  node.get("missedSnapshots"),
                "archiveSnapshots": node.get("archiveSnapshots"),
                "totalSnapshots":   node.get("totalSnapshots"),
                "location":         node.get("location"),
            }
        print(f"   {label}: {len(nodes)} objects")

    return all_compliance
