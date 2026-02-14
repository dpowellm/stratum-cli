# Stratum v7.2 Patch — Semantic Cleanup Before Schema Lock

**Purpose:** v7.1 passes 98/98 checks but has 4 naming/semantic bugs that will cause wrong analysis at 50k scale. This is the final patch before schema lock.

**Principle:** A data scientist receiving 50k rows × 102 columns with no context should not misinterpret any field name.

---

## Bug 1: finding_count is misleading and redundant

**Problem:** `finding_count` (18) and `finding_rule_count` (18) are always identical. `finding_count` sounds like "total findings" but actually means "unique rules that fired." The real total is `total_finding_instances` (94). At 50k rows, any analyst using `finding_count` as a denominator gets answers wrong by ~5x.

**Fix:** Remove `finding_count`. Keep `finding_rule_count` (clear name, unambiguous). Keep `total_finding_instances` (the actual count people want). The field that batch-results calls `finding_count` stays there (it's used for fleet sort and already means unique rules in that context — rename in batch too for consistency).

**Changes:**
- Pings: Remove `finding_count` field entirely
- Pings: All checks that referenced `finding_count` now reference `finding_rule_count`
- batch-results: Rename `finding_count` → `finding_rule_count` on all 16 records
- eval: Update verification references

**Downstream impact on existing checks:**
- S5 was: `finding_count == sum(finding_severities)` → becomes: `finding_rule_count == sum(finding_severities)`
- S16 was: `Initial finding_count==18` → becomes: `Initial finding_rule_count==18`
- V20 was: checking `finding_count` → now checks `finding_rule_count`
- normalized_features.findings_per_agent stays as-is (it uses finding_rule_count/agent_count — unique rules per agent, which is the right metric for risk density)

## Bug 2: `version` field is stale and ambiguous

**Problem:** `version: "0.2.0"` has never been updated across 4 patches. `schema_version: "0.3.1"` and `schema_id: 4` exist alongside it. Nobody knows what `version` means vs `schema_version`.

**Fix:** Rename `version` → `scanner_version`. Set to `"0.3.1"` (matching eval's scanner_version). Now the three version fields have clear semantics:
- `scanner_version`: the CLI version that produced this ping
- `schema_version`: human-readable schema version string
- `schema_id`: machine-readable schema version integer

**Changes:**
- Both pings: Rename `version` → `scanner_version`, value `"0.2.0"` → `"0.3.1"`

## Bug 3: `frameworks` list missing from pings

**Problem:** batch-results has `frameworks: ["CrewAI", "LangChain", "LangGraph"]`. Pings have `framework_versions` (with version strings) and `repo_metadata.primary_framework` but no simple frameworks list. A framework can be detected but have an unknown version — in that case `framework_versions` would have a null value, and you couldn't distinguish "framework detected, version unknown" from "framework not detected."

**Fix:** Add `frameworks` list to both pings. This is the authoritative list of detected frameworks. `framework_versions` provides version strings where available (values can be null).

**Changes:**
- Both pings: Add `frameworks: ["CrewAI", "LangChain", "LangGraph"]`

## Bug 4: Generate data dictionary

**Problem:** 102-field schema with no documentation. Every consumer of the 50k dataset reverse-engineers semantics from JSON.

**Fix:** Generate `SCHEMA.md` as a companion deliverable. Not a ping field — a documentation artifact.

**Deliverable:** SCHEMA.md with every field documented: name, type, description, example value, nullable, added_in_version.

---

## Complete Change List

### Both pings:
1. REMOVE `finding_count`
2. RENAME `version` → `scanner_version`, value → `"0.3.1"`
3. ADD `frameworks: ["CrewAI", "LangChain", "LangGraph"]`
4. schema_id: 4 → 5
5. schema_version: `"0.3.1"` → `"0.3.2"`

### batch-results.json:
1. RENAME `finding_count` → `finding_rule_count` on all 16 records
2. schema_id: 4 → 5

### evaluation-summary.json:
1. patch_version → `"v7.2"`
2. scanner_version → `"0.3.2"`
3. Add `v7_2_fixes` section
4. Add V41-V44 to verification_matrix
5. Update any references to `finding_count` in existing sections

### New deliverable:
- SCHEMA.md — full data dictionary

### Unchanged:
- terminal-default-v6.txt (no changes)
- terminal-rescan-v6.txt (no changes)  
- connection-validation.json (no changes)

---

## Verification Checks

Existing S1-S40 must still pass with these modifications:
- S5: `finding_rule_count == sum(finding_severities)` (was finding_count)
- S15: batch records have `finding_rule_count` (was finding_count)
- S16: `Initial finding_rule_count==18, rescan finding_rule_count==15` (was finding_count)

New checks:
- S41: Neither ping contains field named `finding_count`
- S42: Neither ping contains field named `version` (renamed to scanner_version)
- S43: Both pings have `scanner_version == "0.3.1"` (CLI version)
- S44: Both pings have `frameworks` as list matching `framework_versions` keys
- S45: All batch records have `finding_rule_count` (not `finding_count`)
- S46: schema_id == 5 in both pings and all batch records
- S47: schema_version == "0.3.2" in both pings
- S48: SCHEMA.md exists and documents all ping fields
