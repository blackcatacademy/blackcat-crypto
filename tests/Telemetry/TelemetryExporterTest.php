<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Telemetry;

use BlackCat\Crypto\Queue\InMemoryWrapQueue;
use BlackCat\Crypto\Queue\WrapJob;
use BlackCat\Crypto\Telemetry\IntentCollector;
use BlackCat\Crypto\Telemetry\TelemetryExporter;
use PHPUnit\Framework\TestCase;

final class TelemetryExporterTest extends TestCase
{
    public function testSnapshotIncludesQueueMetrics(): void
    {
        $queue = new InMemoryWrapQueue();
        $queue->enqueue(new WrapJob('users.pii', 'payload-1'));
        $queue->enqueue(new WrapJob('users.ssn', 'payload-2', attempts: 1, lastError: 'boom'));

        $snapshot = TelemetryExporter::snapshot([
            ['client' => 'kms-a', 'status' => ['status' => 'ok']],
            ['client' => 'kms-b', 'status' => ['status' => 'failed']],
        ], $queue);

        self::assertSame(1, $snapshot['kms_up_total']);
        self::assertSame(2, $snapshot['wrap_queue']['backlog']);
        self::assertArrayHasKey('users.pii', $snapshot['wrap_queue']['sample_contexts']);
        self::assertSame(1, $snapshot['wrap_queue']['failed']);
        self::assertNotEmpty($snapshot['wrap_queue']['last_errors']);

        $prom = TelemetryExporter::asPrometheus($snapshot);
        self::assertStringContainsString('blackcat_wrap_queue_backlog 2', $prom);
        self::assertStringContainsString('blackcat_wrap_queue_failed_total 1', $prom);
        self::assertStringContainsString('blackcat_kms_health_info{client="kms-a"', $prom);
    }

    public function testSnapshotIncludesIntentMetricsWhenCollectorProvided(): void
    {
        $collector = new IntentCollector();
        $collector->record('encrypt', ['ctx' => 'a']);
        $collector->record('encrypt', ['ctx' => 'b']);
        $queue = new InMemoryWrapQueue();

        $snapshot = TelemetryExporter::snapshot([], $queue, $collector);

        self::assertArrayHasKey('intents', $snapshot);
        self::assertSame(['encrypt' => 2], $snapshot['intents']['counts']);
    }
}
