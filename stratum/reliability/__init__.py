"""Reliability scanner — structural reliability analysis for AI agent architectures.

Modules:
- enrichment: Graph enrichment layer (capability, agent, data store, observability analysis)
- traversals: Five reusable graph traversal primitives
- engine: 18 Bucket A reliability finding rules
- composition: 7 STRAT-COMP + 6 STRAT-XCOMP compositional escalations
- metrics_compute: Structural metrics (15 global, 5 per-node) + risk scoring
- anomalies: Structural anomaly detection (z-scores, topology, motifs)
- observations: Observation point generation (monitoring recommendations)
- config: .stratum.yml config loader for Bucket B findings
"""
