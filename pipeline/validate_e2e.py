#!/usr/bin/env python
"""End-to-end validation of scan pipeline output."""

import json
import os
import sys

RESULTS_PATH = "pipeline/data/scan_results.jsonl"
QUARANTINE_PATH = "pipeline/data/quarantine.jsonl"
LOG_PATH = "pipeline/data/pipeline_run_log.json"

VALID_STATUSES = {"success", "partial", "failed", "empty"}
REQUIRED_FIELDS = ["scan_id", "timestamp", "scan_status", "schema_id", "repo_full_name"]

errors = []
pings = []
quarantine_pings = []


def check(condition, msg):
    if not condition:
        errors.append(msg)
        print(f"  FAIL: {msg}")
    else:
        print(f"  PASS: {msg}")


# --- Load results ---
print("=== Loading scan_results.jsonl ===")
if not os.path.exists(RESULTS_PATH):
    print(f"  ERROR: {RESULTS_PATH} not found")
    sys.exit(1)

with open(RESULTS_PATH) as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            ping = json.loads(line)
            pings.append(ping)
        except json.JSONDecodeError as e:
            errors.append(f"Line {i}: invalid JSON: {e}")

print(f"  Loaded {len(pings)} pings from scan_results.jsonl")

# --- Load quarantine ---
quarantine_records = []
if os.path.exists(QUARANTINE_PATH):
    with open(QUARANTINE_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rec = json.loads(line)
                    quarantine_records.append(rec)
                    quarantine_pings.append(rec.get("ping", rec))
                except json.JSONDecodeError:
                    pass
    print(f"  Loaded {len(quarantine_pings)} pings from quarantine.jsonl")

# Quarantined pings are raw scanner output (pre-v7.2 schema) —
# they were quarantined precisely because they lack schema_id, scan_status, etc.
# We validate them separately: they must have validation_errors and a ping dict.

# --- Validate scan_results.jsonl pings (these are schema-compliant) ---
print("\n=== Validating scan_results.jsonl pings ===")

for i, ping in enumerate(pings):
    # Required fields
    for field in REQUIRED_FIELDS:
        if field not in ping:
            errors.append(f"Result ping {i}: missing required field '{field}'")

    # Valid status
    status = ping.get("scan_status")
    if status not in VALID_STATUSES:
        errors.append(f"Result ping {i}: invalid scan_status='{status}'")

    # Failed pings must have failure_reason
    if status == "failed":
        fr = ping.get("failure_reason")
        if not fr or not isinstance(fr, str):
            errors.append(f"Result ping {i}: failed ping missing failure_reason string")

    # Success pings must have schema_id=5 and finding_rule_count
    if status == "success":
        if ping.get("schema_id") != 5:
            errors.append(f"Result ping {i}: success ping has schema_id={ping.get('schema_id')}, expected 5")
        if "finding_rule_count" not in ping:
            errors.append(f"Result ping {i}: success ping missing finding_rule_count")

check(len(pings) > 0 or len(quarantine_pings) > 0, "At least one ping was written")

valid_statuses = all(p.get("scan_status") in VALID_STATUSES for p in pings)
check(valid_statuses, "All result pings have valid scan_status")

has_required = all(
    all(f in p for f in REQUIRED_FIELDS) for p in pings
)
check(len(pings) == 0 or has_required, "All result pings have required fields")

failed_pings = [p for p in pings if p.get("scan_status") == "failed"]
failed_have_reason = all(
    isinstance(p.get("failure_reason"), str) and p.get("failure_reason")
    for p in failed_pings
)
check(len(failed_pings) == 0 or failed_have_reason, "All failed pings have failure_reason string")

# --- Validate quarantine records ---
print("\n=== Validating quarantine.jsonl ===")

quarantine_valid = all(
    isinstance(r.get("ping"), dict) and isinstance(r.get("validation_errors"), list)
    for r in quarantine_records
)
check(quarantine_valid, "All quarantine records have 'ping' dict and 'validation_errors' list")

quarantine_have_errors = all(
    len(r.get("validation_errors", [])) > 0
    for r in quarantine_records
)
check(len(quarantine_records) == 0 or quarantine_have_errors, "All quarantine records have at least one validation error")

quarantine_have_scan_id = all(
    "scan_id" in r.get("ping", {}) or "scan_id" in r.get("ping", {})
    for r in quarantine_records
)
check(len(quarantine_records) == 0 or quarantine_have_scan_id, "All quarantined pings have scan_id")

# --- No silent drops check ---
print("\n=== Checking for silent drops ===")
if os.path.exists(LOG_PATH):
    with open(LOG_PATH) as f:
        run_log = json.load(f)

    work_queue_size = run_log.get("work_queue_size", 0)
    total_pings = len(pings) + len(quarantine_pings)
    check(
        total_pings == work_queue_size,
        f"No silent drops: {total_pings} pings (results + quarantine) == {work_queue_size} repos attempted"
    )
else:
    errors.append("pipeline_run_log.json not found")

# --- Summary ---
print("\n=== SUMMARY ===")
total_all = len(pings) + len(quarantine_pings)
print(f"  Total pings: {total_all}")
print(f"    In scan_results.jsonl: {len(pings)}")
print(f"    In quarantine.jsonl:   {len(quarantine_pings)}")

# Status breakdown for result pings
result_statuses = {}
for p in pings:
    s = p.get("scan_status", "unknown")
    result_statuses[s] = result_statuses.get(s, 0) + 1
print(f"  Result ping statuses:")
for status, count in sorted(result_statuses.items()):
    print(f"    {status}: {count}")
print(f"  Quarantined (raw scanner output, pre-v7.2): {len(quarantine_pings)}")

if errors:
    print(f"\n  VALIDATION: FAIL ({len(errors)} errors)")
    for e in errors:
        print(f"    - {e}")
else:
    print(f"\n  VALIDATION: PASS (0 errors)")
