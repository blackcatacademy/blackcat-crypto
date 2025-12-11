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
        $ciMeta = [
            'ci' => getenv('CI') ?: null,
            'repo' => getenv('GITHUB_REPOSITORY') ?: null,
            'run_id' => getenv('GITHUB_RUN_ID') ?: null,
            'workflow' => getenv('GITHUB_WORKFLOW') ?: null,
            'job' => getenv('GITHUB_JOB') ?: null,
        ];

        $snapshot = TelemetryExporter::snapshot(kmsHealth: [], queue: null, collector: $this->collector);
        $snapshot['ci'] = array_filter($ciMeta, static fn($v) => $v !== null && $v !== '');
        return $snapshot;
    }
}
