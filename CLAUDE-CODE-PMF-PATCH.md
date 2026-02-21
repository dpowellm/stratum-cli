Read ./PATCH-PMF-HARDENING.md in full, then implement every fix and improvement it describes.

Read each file before modifying it. The patch touches these files:

MODIFY sql/schema.sql — add centroid JSONB column to archetypes table
MODIFY api/models.py — remove schema_id upper bound, expand TCCohortData, add headline to BenchmarkResponse
MODIFY api/main.py — fix centroid loading in lifespan (remove broken fetch_stat fallback)
MODIFY api/routes/benchmark.py — all six PMF improvements: enriched TC response, framework-aware remediation, filtered finding comparison, empty DB guard, headline generation, resilience wrappers
MODIFY api/routes/archetypes.py — empty DB graceful degradation
MODIFY api/routes/toxic_combinations.py — empty DB graceful degradation
MODIFY pipeline/05_populate_db.py — write centroids, compute per-TC risk impact stats

Then update existing tests that break due to model changes. In particular:
- eval/test_api_models.py — update for new TCCohortData fields, headline field on BenchmarkResponse
- eval/test_api_routes.py — update mock data to include centroids, update response assertions for new fields

Then produce evaluation outputs in eval/outputs/:

1. Run pytest eval/ -v and save to eval/outputs/patch-validation.txt
2. Copy the updated sql/schema.sql to eval/outputs/schema-diff.txt
3. Create eval/outputs/benchmark-response-example.py — a standalone script that builds a realistic BenchmarkResponse with all new fields and prints it as formatted JSON. Run it and save the output to eval/outputs/benchmark-response-example.json
4. Create eval/outputs/updated-models-summary.txt — list every Pydantic model in api/models.py with all field names and types
5. Save eval/outputs/empty-db-response.txt showing the 503 JSON the API returns when the database has no archetypes

Make sure eval/outputs/ directory exists and all 5 output files are written there.
