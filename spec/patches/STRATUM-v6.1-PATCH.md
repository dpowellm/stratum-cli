# Stratum v6.1 Patch — Severity Propagation Fix

**Root cause:** STRATUM-001's severity downgrade (CRITICAL→HIGH at 55% coverage) was applied to the finding badge only. It was NOT propagated to: severity tally, raw score, normalized score, delta, progress card, score bar, telemetry severities, or initial ping.

**Correct math chain:**
```
STRATUM-001 coverage=55% → downgrade CRITICAL→HIGH
Post-fix severity: 2 critical, 5 high, 7 medium, 1 low (15 total)
Raw = 2×10 + 5×5 + 7×2 + 1×1 = 20+25+14+1 = 60
Score = 60/(60+50)×100 = 54.545 → 55
Delta = 69 - 55 = 14
```

---

## Changes Required (5 files)

### 1. terminal-rescan-v6.txt

**A) Progress card — update score and delta:**
```
BEFORE: Risk Score    62/100       ↓7 points (was 69)
AFTER:  Risk Score    55/100       ↓14 points (was 69)
```

**B) Severity bar — update to 2C/5H:**
```
BEFORE: 3 critical · 4 high · 7 medium · 1 low
AFTER:  2 critical · 5 high · 7 medium · 1 low
```

**C) Score bar — update number and fill:**
```
BEFORE: RISK SCORE ████████████████████████░░░░░░░░░░░░░░░░  62 / 100
AFTER:  RISK SCORE ██████████████████████░░░░░░░░░░░░░░░░░░  55 / 100
```
(22 filled blocks out of 40 = 55%)

**D) Finding ② — fix "1 high + 2 high" phrasing:**
```
BEFORE: Resolves 3 findings (1 high + 2 high)                   HIGH
AFTER:  Resolves 3 findings (3 high)                             HIGH
```

**E) Footer auto-fix count stays the same:** `auto-fix 4 of 15 findings` (unchanged)

### 2. evaluation-summary.json

Update these specific fields:
- `bugs_fixed.bug_1_scoring.after`: change "62/100" to "55/100"
- `bugs_fixed.bug_1_scoring.verification.post_fix_score`: 62 → 55
- `bugs_fixed.bug_1_scoring.verification.score_delta`: -7 → -14
- `v6_fixes.I3_partial_credit.verification.V4_score_delta`: -7 → -14
- `framework_scan.post_fix.risk_score`: 62 → 55
- `framework_scan.post_fix.severity_breakdown`: "2 critical, 5 high, 7 medium, 1 low"
- `framework_scan.fix_cycle.score_delta`: -7 → -14
- `framework_scan.fix_cycle.delta_text`: "down 14 points (was 69)"
- `framework_scan.progress_card.risk_score.current`: 62 → 55
- `framework_scan.progress_card.risk_score.delta`: -7 → -14
- `verification_matrix.V4_score_delta_improved.evidence`: "Delta = -14 (was -4 in v5)"

### 3. sample-rescan-ping.json

- `risk_score`: 62 → 55
- `score_delta`: -7 → -14
- `finding_severities`: `{"CRITICAL": 2, "HIGH": 5, "MEDIUM": 7, "LOW": 1}`

### 4. sample-usage-ping.json (INITIAL PING — add v6 fields)

Add these 6 fields to the existing initial scan ping (all with pre-fix/first-scan values):
```json
"finding_coverages": {},
"severity_downgrades": {},
"crews_clean": 0,
"crews_with_findings": 30,
"provider_confidence_breakdown": {
  "detected": 7,
  "inferred_env_var": 6,
  "inferred_framework": 2,
  "unknown": 1
},
"progress_card_shown": false
```

These go at the end of the JSON object, before the closing `}`, right after the existing v5 bonus fields (guardrail_linked_count, etc.) and before schema_version.

### 5. connection-validation.json

No changes needed — already correct.

### 6. batch-results.json

No changes needed — already correct.

### 7. terminal-default-v6.txt

No changes needed — default scan has no post-fix scores or severity downgrades.

---

## Verification Checklist

After applying the patch, these must all be true:

| # | Check | Expected |
|---|-------|----------|
| M1 | Rescan score | 55/100 (not 62) |
| M2 | Rescan delta | ↓14 points (not ↓7) |
| M3 | Rescan severity bar | 2 critical · 5 high · 7 medium · 1 low |
| M4 | Rescan score bar blocks | 22/40 filled (55%) |
| M5 | Finding ② phrasing | "3 high" not "1 high + 2 high" |
| M6 | Rescan ping risk_score | 55 |
| M7 | Rescan ping score_delta | -14 |
| M8 | Rescan ping finding_severities | CRITICAL:2, HIGH:5 |
| M9 | Initial ping has finding_coverages | {} (empty, first scan) |
| M10 | Initial ping has severity_downgrades | {} (empty, first scan) |
| M11 | Initial ping has crews_clean | 0 |
| M12 | Initial ping has crews_with_findings | 30 |
| M13 | Initial ping has progress_card_shown | false |
| M14 | Initial ping has provider_confidence_breakdown | present with 4 tiers |
| M15 | eval post_fix.risk_score | 55 |
| M16 | eval fix_cycle.score_delta | -14 |
| M17 | eval post_fix.severity_breakdown | "2 critical, 5 high, 7 medium, 1 low" |
| M18 | Score math verifiable | raw=60, 60/(60+50)*100=54.5→55 |

Plus all 16 V-checks and 13 R-checks from v6 evaluation must still pass.
