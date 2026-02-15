Run an end-to-end scan to verify TC detection works through the full pipeline (RiskGraph → NetworkX conversion → pattern matching → terminal rendering).

## Step 1: Find a test target

Look for test projects in the repo. Check these locations in order:
- test_project/
- tests/fixtures/
- tests/test_data/
- examples/
- Any directory with a crewai or langchain project (look for files importing crewai, langchain, or langgraph)

If none of these exist, create a minimal CrewAI-style test project at eval/test_crew_project/ with a single Python file that would trigger at least TC-001 and TC-007. It should have:
- An orchestrator agent that delegates to a worker agent (no HITL/approval gate)
- The worker agent with access to a credential-like data store
- A shared tool used by 3+ agents
- At least one external service connection

The file doesn't need to actually run — it just needs to be parseable by the stratum scanner's static analysis.

## Step 2: Run the scan

Run `stratum scan <target_path>` and capture the full terminal output (stdout and stderr) to eval/outputs/e2e-scan-output.txt.

Also run `stratum scan <target_path> --export-graph` and capture output to eval/outputs/e2e-scan-export-output.txt.

## Step 3: Check results

After the scans complete, write eval/outputs/e2e-validation.txt with:

```
TARGET: <path scanned>
SCAN EXIT CODE: <code>
SCAN COMPLETED: yes/no

TOXIC COMBINATIONS SECTION:
- Section appeared in output: yes/no
- Number of TCs detected: <N>
- TC IDs detected: <list>
- Severity rendering correct: yes/no
- Matched paths shown: yes/no
- Remediation code shown: yes/no

COMPOUND RISK SCORING:
- compound_risk_score shown: yes/no
- compound_risk_score >= risk_score: yes/no

GRAPH EXPORT:
- graph.json created: yes/no
- graph.json path: <path>
- Number of nodes in export: <N>
- Number of edges in export: <N>
- TCs in export: <list of tc_ids>

RISKGRAPH CONVERSION:
- Scan completed without conversion errors: yes/no
- Any warnings about "Failed to convert scan graph": yes/no

ISSUES FOUND:
- <list any problems, or "None">
```

If the scan crashes or TCs don't fire, also capture the traceback or relevant error output and include it in the validation file.

## Step 4: Copy the graph export

If .stratum/graph.json was created by the --export-graph run, copy it to eval/outputs/e2e-graph-export.json.

Make sure all output files are written to eval/outputs/.
