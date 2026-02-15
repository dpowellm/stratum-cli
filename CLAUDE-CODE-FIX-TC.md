Do these three things in order:

## 1. Fix remediation effort values in catalog

Open stratum/data/toxic_combinations.json. Check every TC's remediation.effort field. The spec requires values to be "low", "medium", or "high". If any TC uses "med" instead of "medium", change it to "medium". Then update eval/test_catalog_schema.py to validate against ("low", "medium", "high") instead of ("low", "med", "high") if it currently uses "med".

## 2. Add missing TC test coverage

Open eval/test_toxic_combinations.py. There are currently tests for TC-001, TC-002, TC-005, and TC-007. Add test functions for the remaining 6 TCs:

- test_match_tc_003: Build a graph triggering TC-003 (code execution reachable from external input). Needs: external_service -> capability(data_access) -> agent -> capability(code_exec), no HITL on path.
- test_match_tc_004: Build a graph triggering TC-004 (financial operation through shared context). Needs: two agents sharing a tool, one with external data access, the other with a financial capability sending to external service, no HITL.
- test_match_tc_006: Build a graph triggering TC-006 (MCP credential cascade). Needs: mcp_server(has_auth=false) connected to agent connected to another mcp_server with credential exposure.
- test_match_tc_008: Build a graph triggering TC-008 (checkpoint-free destructive pipeline). Needs: agent -> agent -> agent -> capability(destructive), chain_depth >= 3, no checkpoint.
- test_match_tc_009: Build a graph triggering TC-009 (cross-crew data sensitivity escalation). Needs: agent(crew_A) with low sensitivity data connected to agent(crew_B) with high sensitivity data, no access control on inter-crew edge.
- test_match_tc_010: Build a graph triggering TC-010 (autonomous loop with external write access). Needs: agent with self-loop/reflection edge and capability(destructive or financial) writing to external service, no HITL.

For each test: read the actual TC pattern definition from the catalog JSON first, then build the minimal graph that satisfies its node types, edge types, and constraints. Verify the TC fires. Each test should follow the same pattern as the existing tests — build helper function, assert match, check severity.

IMPORTANT: Read the actual pattern definitions in stratum/data/toxic_combinations.json before writing each test. The test graphs must match what the pattern matcher actually checks, not just what the TC description says in prose.

## 3. Produce verification output

After making the fixes and adding tests, do the following:

Run pytest eval/ -v and save full output to eval/outputs/tc-eval-results-v2.txt

Copy stratum/data/toxic_combinations.json to eval/outputs/toxic_combinations.json so the catalog can be reviewed.

Check if scanner.py has TC matching wired in. Look for imports of toxic_combinations or match_all or TCMatch in stratum/scanner.py. Also check if terminal.py renders a TOXIC COMBINATIONS section. Save a summary of what you find to eval/outputs/integration-check.txt with this format:

```
scanner.py integration:
- TC matching imported: yes/no
- match_all called after graph build: yes/no
- compute_compound_risk_score present: yes/no
- tc_matches passed to output: yes/no

terminal.py integration:
- TOXIC COMBINATIONS section rendered: yes/no
- TC severity coloring: yes/no
- Matched path rendering: yes/no
- Framework-specific remediation: yes/no

telemetry/profile.py integration:
- tc_count field: yes/no
- tc_ids field: yes/no
- tc_severities field: yes/no
- tc_max_severity field: yes/no
- compound_risk_score field: yes/no
- compound_risk_delta field: yes/no
- schema_id bumped to 6: yes/no

cli.py integration:
- --export-graph flag: yes/no
```

Make sure all output files are written to the eval/outputs/ directory.
