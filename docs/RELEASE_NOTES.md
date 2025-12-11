# Blackcat Crypto – Release Notes

## Highlights
- **Intent telemetry & SSE**: Live intent collection with SSE streaming, JSON/Prometheus export, and now OTLP/JSON export for OpenTelemetry collectors.
- **KMS/HSM routing**: Pluggable `HsmKmsClient`/`KmsRouter` with suspend/resume persistence, cipher/tag/nonce allow-lists, and rich health diagnostics.
- **Wrap queue tooling**: CLI for enqueueing, inspecting, and replaying wrap/unlock jobs with backlog/failed metrics.
- **Manifest validation**: `manifest:validate` with YAML/JSON schemas, drift detection, and environment overlays.
- **Key lifecycle**: CLI rotation with usage manifests and dry-run diffs; legacy decrypt fallback for migration paths.
- **Bridges**: Core bridge for `KeyManager/Crypto/FileVault` interoperability; ready hooks for database-crypto consumers.
- **Telemetry exporters**: Prometheus + OTLP/JSON snapshots for KMS health, wrap queues, and intent counters.

## Notable CLI commands
- `crypto metrics:export [json|prom|otel]` – export KMS/queue/intent telemetry.
- `crypto telemetry:intents [--format=prom|otel] [--limit N]` – intent counters + recent events.
- `crypto key:rotate --manifest path.yaml --dry-run` – plan/apply rotations.
- `crypto manifest:validate` – schema validation and drift hints.
- `crypto wrap:queue`, `wrap:status` – enqueue/inspect wrap jobs.

## Breaking/behavior changes
- Intent collector is opt-in; enable via environment wiring or `IntentCollector::global(new IntentCollector())`.
- OTLP export emits minimal `resourceMetrics` payload (service.name `blackcat-crypto`).

## Migration tips
- For Prometheus users, switch to `metrics:export prom`; for OTLP collectors use `metrics:export otel`.
- When adopting KMS/HSM, pin cipher/tag policies in config to prevent weak or unexpected algorithms.
