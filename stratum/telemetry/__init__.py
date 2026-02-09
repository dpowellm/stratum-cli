"""Telemetry subsystem.

ARCHITECTURAL INVARIANT: This package only EMITS data. It never RECEIVES data.
The only network call in stratum-cli is share.submit_profile() — a one-way POST.

No module in stratum/ may:
- Perform HTTP GET, HEAD, or OPTIONS requests
- Open WebSocket connections
- Read from any network socket
- Import any HTTP client library except urllib.request (stdlib, for POST only)

Benchmarks, comparisons, and contextual insights are delivered via
separate products (web dashboard, API, Slack), never via the CLI.

This invariant exists because:
1. Offline operation is a trust signal for security-sensitive users
2. Inbound data paths expose the intelligence schema to competitors
3. CLI independence means forks retain full scan functionality
"""
