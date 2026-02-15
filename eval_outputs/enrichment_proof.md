# Enrichment Proof

Evidence that the enrichment layer populated expected fields.

## Agent Enrichment

### Senior Research Analyst
- `makes_decisions`: False
- `error_handling_pattern`: default_on_error
- `betweenness_centrality`: 0.0952
- `delegation_enabled`: False
- `human_input_enabled`: False
- `objective_tag`: maximize_portfolio
- `domain`: N/A

### Financial Analyst
- `makes_decisions`: False
- `error_handling_pattern`: default_on_error
- `betweenness_centrality`: 0.0714
- `delegation_enabled`: True
- `human_input_enabled`: False
- `objective_tag`: maximize_portfolio
- `domain`: N/A

### Trade Executor
- `makes_decisions`: False
- `error_handling_pattern`: default_on_error
- `betweenness_centrality`: 0.0
- `delegation_enabled`: False
- `human_input_enabled`: False
- `objective_tag`: maximize_portfolio
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
- `reversibility`: reversible
- `subtype`: general
- `external_service`: True
- `data_mutation`: False
- `human_visible`: False
- `idempotent`: False

### FileReadTool
- `reversibility`: reversible
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
- `tool_of`: SerperDevTool → Senior Research Analyst
  - `trust_crossing`: True
- `task_sequence`: Senior Research Analyst → Financial Analyst
- `feeds_into`: Senior Research Analyst → Financial Analyst
- `delegates_to`: Financial Analyst → Senior Research Analyst
- `shares_with`: FileReadTool → SerperDevTool
  - `trust_crossing`: True
- `implicit_authority_over`: Financial Analyst → SerperDevTool
- `error_boundary`: Senior Research Analyst → Financial Analyst
- `shared_state_conflict`: Financial Analyst → Trade Executor

## Computed Edges

- `implicit_authority_over`: Financial Analyst → SerperDevTool
- `shared_state_conflict`: Financial Analyst → Trade Executor
- `shared_state_conflict`: Financial Analyst → Senior Research Analyst
- `shared_state_conflict`: Trade Executor → Senior Research Analyst