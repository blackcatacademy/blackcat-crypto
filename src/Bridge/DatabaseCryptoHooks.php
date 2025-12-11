<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Bridge;

use BlackCat\Crypto\Telemetry\IntentCollector;
use BlackCat\Crypto\Telemetry\TelemetryExporter;

/**
 * Convenience bridge for database integration: emits telemetry snapshots that
 * can be consumed by CI or docs pipelines in the database-crypto repo.
 */
final class DatabaseCryptoHooks
{
    public function __construct(private IntentCollector $collector) {}

    /**
     * @return array<string,mixed>
     */
    public function telemetrySnapshot(): array
    {
        // No KMS/queue context here; we only emit intents/tag counters.
        return TelemetryExporter::snapshot(kmsHealth: [], queue: null, collector: $this->collector);
    }
}
