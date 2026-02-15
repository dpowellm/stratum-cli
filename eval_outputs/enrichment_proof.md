# Enrichment Proof

Evidence that the enrichment layer populated expected fields.

## Agent Enrichment

### Project Manager
- `makes_decisions`: False
- `error_handling_pattern`: default_on_error
- `betweenness_centrality`: 0.0
- `delegation_enabled`: True
- `human_input_enabled`: False
- `objective_tag`: 
- `domain`: N/A

## Capability Enrichment

### psycopg2
- `reversibility`: conditional
- `subtype`: general
- `external_service`: False
- `data_mutation`: True
- `human_visible`: False
- `idempotent`: None

### psycopg2
- `reversibility`: conditional
- `subtype`: general
- `external_service`: False
- `data_mutation`: True
- `human_visible`: False
- `idempotent`: False

### smtplib
- `reversibility`: irreversible
- `subtype`: general
- `external_service`: True
- `data_mutation`: False
- `human_visible`: False
- `idempotent`: False

### SerperDevTool
- `reversibility`: irreversible
- `subtype`: general
- `external_service`: True
- `data_mutation`: False
- `human_visible`: False
- `idempotent`: False

### FileReadTool
- `reversibility`: irreversible
- `subtype`: general
- `external_service`: False
- `data_mutation`: False
- `human_visible`: False
- `idempotent`: None

## Data Store Enrichment

### PostgreSQL
- `concurrency_control`: version
- `persistence`: persistent
- `schema_defined`: True

### PostgreSQL (write)
- `concurrency_control`: version
- `persistence`: persistent
- `schema_defined`: True

### Crewai Tools
- `concurrency_control`: none
- `persistence`: persistent
- `schema_defined`: False

## Edge Enrichment

- `reads_from`: PostgreSQL → psycopg2
- `writes_to`: psycopg2 → PostgreSQL (write)
- `sends_to`: smtplib → Email (SMTP)
- `shares_with`: psycopg2 → smtplib
  - `trust_crossing`: True

## Computed Edges
