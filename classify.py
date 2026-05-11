from config import DNP_SLA_NAMES, DNP_TAG_KEYS, DNP_TAG_VALUES


def classify_protection_status(sla_name, compliance_status, tags, has_snapshot=False):
    """
    Classify an object into a protection state.
    Returns: (protection_status, detail)
    """
    sla_lower = (sla_name or "").lower().strip()
    tags_dict = {t.get("key", "").lower(): t.get("value", "").lower() for t in (tags or [])}

    # 1. DNP via SLA name
    if sla_lower in DNP_SLA_NAMES:
        return "DO_NOT_PROTECT", f"DNP SLA: {sla_name}"

    # 2. DNP via tags
    for tag_key in DNP_TAG_KEYS:
        if tag_key.lower() in tags_dict:
            tag_val = tags_dict[tag_key.lower()]
            if tag_val in [v.lower() for v in DNP_TAG_VALUES]:
                return "DO_NOT_PROTECT", f"DNP Tag: {tag_key}={tag_val}"

    # 3. Unprotected
    if not sla_name or sla_lower in ("unprotected", "none", ""):
        return "UNPROTECTED", "No SLA assigned"

    # 4. Has SLA - use compliance status if available
    if compliance_status:
        if compliance_status == "IN_COMPLIANCE":
            return "PROTECTED_COMPLIANT", f"SLA: {sla_name}"
        elif compliance_status == "OUT_OF_COMPLIANCE":
            return "PROTECTED_NON_COMPLIANT", f"SLA: {sla_name} (non-compliant)"
        elif compliance_status == "UNPROTECTED":
            return "UNPROTECTED", "Compliance reports unprotected"
        elif compliance_status in ("NOT_AVAILABLE", "NOT_APPLICABLE", "EMPTY", "NULL"):
            if has_snapshot:
                return "PROTECTED_COMPLIANT", f"SLA: {sla_name} (has snapshots)"
            else:
                return "PROTECTED_UNKNOWN", f"SLA: {sla_name} (status: {compliance_status})"

    # 5. Derive from SLA + snapshot
    if has_snapshot:
        return "PROTECTED_COMPLIANT", f"SLA: {sla_name} (has snapshots)"
    else:
        return "PROTECTED_NO_SNAPSHOTS", f"SLA: {sla_name} (no snapshots yet)"


def extract_tag_value(tags, key_variants):
    """Given a list of tag dicts and possible key names, return the first match."""
    if not tags:
        return None
    tags_lower = {t.get("key", "").lower(): t.get("value", "") for t in tags}
    for variant in key_variants:
        if variant.lower() in tags_lower:
            return tags_lower[variant.lower()]
    return None


def build_account_lookup(accounts):
    """
    Build lookup dicts for account enrichment.
    Returns dict keyed by both Rubrik ID and account name.

    NOTE: RSC does not expose the 12-digit AWS account number via the
    awsNativeAccounts list endpoint — both nativeAccountId and cloudNativeId
    return HTTP 400 on this RSC version.  aws_account_number will be blank
    until a supported field is identified.  The fallback chain is kept so
    it populates automatically if a future API version adds the field.
    """
    lookup = {}
    for acct in accounts:
        info = {
            "name": acct.get("name", ""),
            # nativeId is injected from allAwsCloudAccountsFeaturesWithExoConfigs
            # before this lookup is built (see main.py enrichment step).
            # Other field names are kept as fallbacks for future API version changes.
            "aws_account_number": (
                acct.get("nativeId")
                or acct.get("cloudNativeId")
                or acct.get("nativeAccountId")
                or acct.get("cloudAccountId")
                or ""
            ),
            "rubrik_id": acct.get("id", ""),
        }
        # Key by Rubrik UUID
        lookup[acct.get("id", "")] = info
        # Key by name
        if acct.get("name"):
            lookup[acct["name"]] = info
    return lookup


def flatten_object(obj, object_type, compliance_lookup=None, account_lookup=None):
    """Flatten a raw RSC object node into a flat dict for CSV output."""

    # ── Account info ──
    account_details = obj.get("awsNativeAccountDetails") or {}
    account_name = obj.get("awsNativeAccountName") or account_details.get("name") or ""
    rubrik_account_id = obj.get("awsAccountRubrikId") or account_details.get("id") or ""

    # Get real AWS account number from lookup
    aws_account_number = ""
    if account_lookup:
        match = account_lookup.get(rubrik_account_id) or account_lookup.get(account_name)
        if match:
            aws_account_number = match.get("aws_account_number", "")
            if not account_name:
                account_name = match.get("name", "")

    # For S3 (snappableConnection) - use location and compliance_lookup location
    location = obj.get("location") or ""
    if not account_name and location:
        # Location often contains account path like "Rubrik Gaia Native/us-west-2"
        parts = location.split("/")
        possible_name = parts[0] if parts else location
        if account_lookup and possible_name in account_lookup:
            match = account_lookup[possible_name]
            account_name = match.get("name", possible_name)
            aws_account_number = match.get("aws_account_number", "")
        else:
            account_name = possible_name

    # ── SLA info ──
    sla_info = obj.get("effectiveSlaDomain") or obj.get("slaDomain") or {}
    sla_name = sla_info.get("name")
    sla_id = sla_info.get("id")

    # Normalise the various "no SLA" strings the API returns across object types.
    # snappableConnection returns "Unprotected" (title-case) while native endpoints
    # return the enum string "UNPROTECTED" or None.  Treat them all as None so the
    # classifier, SLA distribution pivot, and summary groupby stay consistent.
    if sla_name and sla_name.lower() in ("unprotected", "none"):
        sla_name = None

    # ── Snapshot info ──
    newest_snapshot = obj.get("newestSnapshot") or {}
    oldest_snapshot = obj.get("oldestSnapshot") or {}
    last_snapshot_date = newest_snapshot.get("date") if isinstance(newest_snapshot, dict) else None
    if not last_snapshot_date and obj.get("lastSnapshot"):
        last_snapshot_date = obj.get("lastSnapshot")
    has_snapshot = last_snapshot_date is not None

    first_snapshot_date = oldest_snapshot.get("date") if isinstance(oldest_snapshot, dict) else None

    # ── Compliance enrichment ──
    compliance_status = obj.get("complianceStatus")
    rsc_id = obj.get("id", "")
    missed_snapshots = obj.get("missedSnapshots")
    total_snapshots = obj.get("totalSnapshots")
    # archive_snapshots is present inline for S3/DynamoDB (snappableConnection);
    # for EC2/EBS/RDS it is populated below from the compliance_lookup.
    archive_snapshots = obj.get("archiveSnapshots")
    # protectionStatus/archivalComplianceStatus/replicationComplianceStatus are
    # only populated for S3/DynamoDB (snappableConnection).
    # Confirmed ProtectionStatusEnum values: DoNotProtect, NoSla, Protected
    rsc_protection_status = obj.get("protectionStatus") or ""
    archival_compliance_status = obj.get("archivalComplianceStatus")
    replication_compliance_status = obj.get("replicationComplianceStatus")

    if compliance_lookup and rsc_id in compliance_lookup:
        enrichment = compliance_lookup[rsc_id]
        if not compliance_status:
            compliance_status = enrichment.get("complianceStatus")
        if not last_snapshot_date and enrichment.get("lastSnapshot"):
            last_snapshot_date = enrichment["lastSnapshot"]
            has_snapshot = True
        if missed_snapshots is None:
            missed_snapshots = enrichment.get("missedSnapshots")
        if total_snapshots is None:
            total_snapshots = enrichment.get("totalSnapshots")
        if archive_snapshots is None:
            archive_snapshots = enrichment.get("archiveSnapshots")
        # Use location from compliance if we don't have account info
        if not account_name and enrichment.get("location"):
            loc = enrichment["location"]
            parts = loc.split("/")
            possible_name = parts[0] if parts else loc
            if account_lookup and possible_name in account_lookup:
                match = account_lookup[possible_name]
                account_name = match.get("name", possible_name)
                aws_account_number = match.get("aws_account_number", "")
            else:
                account_name = possible_name

    # ── Tags ──
    tags = obj.get("tags") or []

    # ── Protection source ──
    # Maps RSC slaAssignment values to human-readable labels that tell OCC auditors
    # *how* the object was put under protection.
    # Confirmed SlaAssignmentTypeEnum values (via introspection): Direct, Derived, Unassigned
    #   Direct    = SLA manually assigned to the object
    #   Derived   = SLA inherited via a tag-based or parent-policy rule (Synchrony's primary model)
    #   Unassigned = no SLA assignment
    # Note: slaAssignment is only available on native endpoints (EC2/EBS/RDS).
    # For S3/DynamoDB (snappableConnection) this will be empty — protectionStatus is used instead.
    _SLA_ASSIGNMENT_SOURCE = {
        "DIRECT":      "direct_assignment",
        "DERIVED":     "tag_or_policy_rule",
        "UNASSIGNED":  "none",
        "NA":          "none",
    }
    sla_assignment_raw = (obj.get("slaAssignment") or "").strip()
    protection_source = _SLA_ASSIGNMENT_SOURCE.get(
        sla_assignment_raw.upper(),
        "none" if not sla_assignment_raw else sla_assignment_raw.lower(),
    )

    # ── Classify ──
    protection_status, status_detail = classify_protection_status(
        sla_name, compliance_status, tags, has_snapshot
    )

    # ── DNP override for S3/DynamoDB ──
    # snappableConnection exposes protectionStatus directly. If RSC says DoNotProtect
    # but our tag-based classifier didn't catch it (because snappable types don't
    # return tags), trust RSC's own determination.
    if rsc_protection_status == "DoNotProtect" and protection_status != "DO_NOT_PROTECT":
        protection_status = "DO_NOT_PROTECT"
        status_detail = "DNP: RSC protectionStatus=DoNotProtect"

    # ── Extract tag values ──
    environment = extract_tag_value(tags, ["Environment", "Env", "environment", "env"])
    application = extract_tag_value(tags, [
        "Application", "App", "application", "app",
        "Service", "service", "Project", "project"
    ])
    owner = extract_tag_value(tags, ["Owner", "owner", "Team", "team", "owner_email"])
    cost_center = extract_tag_value(tags, ["CostCenter", "cost-center", "costcenter", "Cost Center"])

    # ── Object name and native ID ──
    if object_type == "EC2":
        name = obj.get("instanceName") or obj.get("name") or ""
        native_id = obj.get("instanceNativeId") or ""
        extra = {"instance_type": obj.get("instanceType"), "vpc_id": obj.get("vpcId")}
    elif object_type == "EBS":
        name = obj.get("volumeName") or obj.get("name") or ""
        native_id = obj.get("volumeNativeId") or ""
        extra = {
            "volume_type": obj.get("volumeType"),
            "size_gb": obj.get("sizeInGiBs"),
            "availability_zone": obj.get("availabilityZone"),
        }
    elif object_type == "RDS":
        name = obj.get("dbInstanceName") or obj.get("name") or ""
        native_id = obj.get("cloudNativeId") or name
        extra = {
            "db_engine": obj.get("dbEngine"),
            "db_instance_class": obj.get("dbInstanceClass"),
            "is_multi_az": obj.get("isMultiAz"),
            "vpc_id": obj.get("vpcId"),
        }
    elif object_type == "S3":
        name = obj.get("name") or ""
        native_id = name
        extra = {
            "total_snapshots": total_snapshots,
            "missed_snapshots": missed_snapshots,
            "physical_bytes": obj.get("physicalBytes"),
        }
    elif object_type == "DynamoDB":
        name = obj.get("name") or ""
        native_id = name
        extra = {
            "total_snapshots": total_snapshots,
            "missed_snapshots": missed_snapshots,
            "physical_bytes": obj.get("physicalBytes"),
        }
    else:
        name = obj.get("name", "unknown")
        native_id = obj.get("id", "")
        extra = {}

    # ── Build row ──
    row = {
        "rsc_object_id": rsc_id,
        "object_type": object_type,
        "native_id": native_id,
        "object_name": name,
        "aws_account_number": aws_account_number,
        "aws_account_name": account_name,
        "rubrik_account_id": rubrik_account_id,
        "region": obj.get("region", ""),
        "sla_id": sla_id,
        "sla_name": sla_name,
        "compliance_status": compliance_status or "NOT_AVAILABLE",
        "protection_status": protection_status,
        "protection_source": protection_source,
        "status_detail": status_detail,
        "last_snapshot_date": last_snapshot_date,
        "first_snapshot_date": first_snapshot_date,
        "missed_snapshots": missed_snapshots,
        "archive_snapshots": archive_snapshots,
        "archival_compliance_status": archival_compliance_status,
        "replication_compliance_status": replication_compliance_status,
        "total_snapshots": total_snapshots,
        "is_relic": obj.get("isRelic", False),
        "sla_paused": obj.get("slaPauseStatus", False),
        "sla_assignment": sla_assignment_raw,
        "rsc_protection_status": rsc_protection_status,
        "tag_environment": environment,
        "tag_application": application,
        "tag_owner": owner,
        "tag_cost_center": cost_center,
        "all_tags": "; ".join([f"{t['key']}={t['value']}" for t in tags]) if tags else "",
    }

    row.update(extra)
    return row
