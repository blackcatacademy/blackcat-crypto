## Release Notes

### Governance + Telemetry refresh
- Added `gov:assess` CLI for low-risk auto-approvals (unwrap/decrypt). Tune with `--max-amount`, `--max-sensitivity`, pass context via `--tenant`, `--sensitivity`, `--amount`.
- LowRiskApprovalService available as a PHP helper for service-layer governance.
- New lightweight HTTP endpoint `public/governance.php` for runtime approval checks (POST JSON; configurable via `LOW_RISK_MAX_AMOUNT` / `LOW_RISK_MAX_SENSITIVITY`).
- Intent telemetry now tags PII clusters and workload class; archives rotate via `archiveMaxBytes`/`archiveKeep`.
- Telemetry exporter emits richer intent tag counts (Prometheus/OpenTelemetry/JSON).
- Database crypto hook bridge exposes telemetry snapshots for DB-facing tooling, now enriched with CI metadata when present (e.g., GitHub Actions env).
- Added governance intent logging + approval decisions (see `GovernanceApprovalService`) for low-risk unwrap/decrypt with audit tags.
- HSM/KMS metadata now reports allowed ciphers, key version, and fingerprints; unwrap checks version by config.

### How to try
- Enable intent collector: `BLACKCAT_CRYPTO_INTENTS=1 ./bin/crypto telemetry:intents --format=prom`.
- Governance check: `./bin/crypto gov:assess --tenant=acme --sensitivity=low --amount=500`.
- Inspect intent archive/recents: `./bin/crypto telemetry:intents --limit=20`.
