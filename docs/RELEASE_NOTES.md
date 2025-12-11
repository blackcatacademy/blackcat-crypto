## Release Notes

### Governance + Telemetry refresh
- Added `gov:assess` CLI for low-risk auto-approvals (unwrap/decrypt). Tune with `--max-amount`, `--max-sensitivity`, pass context via `--tenant`, `--sensitivity`, `--amount`.
- LowRiskApprovalService available as a PHP helper for service-layer governance.
- Intent telemetry now tags PII clusters and workload class; archives rotate via `archiveMaxBytes`/`archiveKeep`.
- Telemetry exporter emits richer intent tag counts (Prometheus/OpenTelemetry/JSON).
- Database crypto hook bridge exposes telemetry snapshots for DB-facing tooling.

### How to try
- Enable intent collector: `BLACKCAT_CRYPTO_INTENTS=1 ./bin/crypto telemetry:intents --format=prom`.
- Governance check: `./bin/crypto gov:assess --tenant=acme --sensitivity=low --amount=500`.
- Inspect intent archive/recents: `./bin/crypto telemetry:intents --limit=20`.
