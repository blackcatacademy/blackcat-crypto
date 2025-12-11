<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Telemetry;

use BlackCat\Crypto\Queue\WrapQueueInterface;
use BlackCat\Crypto\Queue\WrapJob;

final class TelemetryExporter
{
    /**
     * @param array<int,array<string,mixed>> $kmsHealth
     * @return array<string,mixed>
     */
    public static function snapshot(array $kmsHealth, ?WrapQueueInterface $queue = null, ?IntentCollector $collector = null): array
    {
        $collector = $collector ?? IntentCollector::global();
        $timestamp = time();
        $clients = [];
        $up = 0;
        $suspendedTotal = 0;
        foreach ($kmsHealth as $entry) {
            $clientId = (string)($entry['client'] ?? 'unknown');
            $statusData = $entry['status'] ?? [];
            $status = is_array($statusData)
                ? (string)($statusData['status'] ?? 'unknown')
                : (string)$statusData;
            if (strtolower($status) === 'ok') {
                $up++;
            }
            $suspended = isset($entry['suspended']) && $entry['suspended'] === true;
            if ($suspended) {
                $suspendedTotal++;
            }
            $clients[] = [
                'id' => $clientId,
                'status' => $status,
                'details' => $statusData,
                'suspended' => $suspended,
            ];
        }
        $queueMetrics = self::queueMetrics($queue);
        $intents = $collector ? $collector->snapshot() : null;
        return [
            'timestamp' => $timestamp,
            'kms_up_total' => $up,
            'kms_suspended_total' => $suspendedTotal,
            'kms_clients' => $clients,
            'wrap_queue' => $queueMetrics,
            'intents' => $intents,
        ];
    }

    public static function asPrometheus(array $snapshot): string
    {
        $lines = [];
        $lines[] = '# HELP blackcat_kms_up_total Number of healthy KMS clients.';
        $lines[] = '# TYPE blackcat_kms_up_total gauge';
        $lines[] = 'blackcat_kms_up_total ' . (int)($snapshot['kms_up_total'] ?? 0);
        $lines[] = '# HELP blackcat_kms_health_info Status of each KMS client.';
        $lines[] = '# TYPE blackcat_kms_health_info gauge';
        foreach ($snapshot['kms_clients'] ?? [] as $client) {
            $clientId = $client['id'] ?? 'unknown';
            $status = strtolower((string)($client['status'] ?? 'unknown'));
            $value = $status === 'ok' ? 1 : 0;
            $lines[] = sprintf(
                'blackcat_kms_health_info{client="%s",status="%s"} %d',
                self::escapeLabel((string)$clientId),
                self::escapeLabel($status),
                $value
            );
        }
        $lines[] = '# HELP blackcat_kms_suspended_total Number of suspended KMS clients.';
        $lines[] = '# TYPE blackcat_kms_suspended_total gauge';
        $lines[] = 'blackcat_kms_suspended_total ' . (int)($snapshot['kms_suspended_total'] ?? 0);
        $queue = $snapshot['wrap_queue'] ?? [];
        $lines[] = '# HELP blackcat_wrap_queue_backlog Number of pending wrap jobs.';
        $lines[] = '# TYPE blackcat_wrap_queue_backlog gauge';
        $lines[] = 'blackcat_wrap_queue_backlog ' . (int)($queue['backlog'] ?? 0);
        $lines[] = '# HELP blackcat_wrap_queue_failed_total Number of wrap jobs marked as failed (attempts > 0 or last error).';
        $lines[] = '# TYPE blackcat_wrap_queue_failed_total gauge';
        $lines[] = 'blackcat_wrap_queue_failed_total ' . (int)($queue['failed'] ?? 0);
        $lines[] = '# HELP blackcat_wrap_queue_oldest_age_seconds Age of the oldest pending wrap job.';
        $lines[] = '# TYPE blackcat_wrap_queue_oldest_age_seconds gauge';
        $lines[] = 'blackcat_wrap_queue_oldest_age_seconds ' . (int)($queue['oldest_age_seconds'] ?? 0);

        $intents = $snapshot['intents']['counts'] ?? [];
        $lines[] = '# HELP blackcat_intents_total Total crypto intents recorded by type.';
        $lines[] = '# TYPE blackcat_intents_total counter';
        if (empty($intents)) {
            $lines[] = 'blackcat_intents_total 0';
        } else {
            foreach ($intents as $intent => $count) {
                $lines[] = sprintf(
                    'blackcat_intents_total{intent="%s"} %d',
                    self::escapeLabel((string)$intent),
                    (int)$count
                );
            }
        }
        return implode("\n", $lines) . "\n";
    }

    /**
     * Minimal OpenTelemetry ResourceMetrics payload (OTLP/JSON shape).
     *
     * @param array<string,mixed> $snapshot
     * @return array<string,mixed>
     */
    public static function asOpenTelemetry(array $snapshot, string $serviceName = 'blackcat-crypto', string $scopeName = 'blackcat.crypto'): array
    {
        $ts = (int)floor(microtime(true) * 1_000_000_000);
        $metrics = [];

        $metrics[] = self::gaugeMetric(
            'blackcat.kms.up_total',
            'Number of healthy KMS clients.',
            (int)($snapshot['kms_up_total'] ?? 0),
            $ts
        );

        $metrics[] = self::gaugeMetric(
            'blackcat.kms.suspended_total',
            'Number of suspended KMS clients.',
            (int)($snapshot['kms_suspended_total'] ?? 0),
            $ts
        );

        foreach ($snapshot['kms_clients'] ?? [] as $client) {
            $status = strtolower((string)($client['status'] ?? 'unknown'));
            $value = $status === 'ok' ? 1 : 0;
            $metrics[] = self::gaugeMetric(
                'blackcat.kms.health',
                'KMS client health (1 ok / 0 otherwise).',
                $value,
                $ts,
                [
                    'client' => (string)($client['id'] ?? 'unknown'),
                    'status' => $status,
                ]
            );
        }

        $queue = $snapshot['wrap_queue'] ?? [];
        $metrics[] = self::gaugeMetric(
            'blackcat.wrap_queue.backlog',
            'Number of pending wrap jobs.',
            (int)($queue['backlog'] ?? 0),
            $ts
        );
        $metrics[] = self::gaugeMetric(
            'blackcat.wrap_queue.failed_total',
            'Number of wrap jobs marked as failed.',
            (int)($queue['failed'] ?? 0),
            $ts
        );
        $metrics[] = self::gaugeMetric(
            'blackcat.wrap_queue.oldest_age_seconds',
            'Age of the oldest pending wrap job.',
            (int)($queue['oldest_age_seconds'] ?? 0),
            $ts
        );

        $intents = $snapshot['intents']['counts'] ?? [];
        $intentPoints = [];
        foreach ($intents as $intent => $count) {
            $intentPoints[] = self::numberDataPoint((int)$count, $ts, ['intent' => (string)$intent]);
        }
        $metrics[] = [
            'name' => 'blackcat.intents.total',
            'description' => 'Total crypto intents recorded by type.',
            'unit' => '1',
            'sum' => [
                'aggregationTemporality' => 2, // CUMULATIVE
                'isMonotonic' => true,
                'dataPoints' => $intentPoints ?: [self::numberDataPoint(0, $ts)],
            ],
        ];

        return [
            'resourceMetrics' => [
                [
                    'resource' => [
                        'attributes' => self::attributes([
                            'service.name' => $serviceName,
                        ]),
                    ],
                    'scopeMetrics' => [
                        [
                            'scope' => [
                                'name' => $scopeName,
                                'version' => '1.0.0',
                            ],
                            'metrics' => $metrics,
                        ],
                    ],
                ],
            ],
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public static function queueMetrics(?WrapQueueInterface $queue, int $peekLimit = 50): array
    {
        if ($queue === null) {
            return [
                'backlog' => 0,
                'oldest_age_seconds' => 0,
                'sample_contexts' => [],
                'failed' => 0,
                'failed_contexts' => [],
                'last_errors' => [],
                'sampled' => 0,
            ];
        }
        $size = $queue->size();
        $jobs = $queue->peek(min($peekLimit, max(1, $size)));
        $oldest = null;
        $contexts = [];
        $failed = 0;
        $failedContexts = [];
        $lastErrors = [];
        /** @var WrapJob $job */
        foreach ($jobs as $job) {
            $contexts[$job->context] = ($contexts[$job->context] ?? 0) + 1;
            $oldest = $oldest === null ? $job->enqueuedAt : min($oldest, $job->enqueuedAt);
            $isFailed = $job->attempts > 0 || $job->lastError !== null;
            if ($isFailed) {
                $failed++;
                $failedContexts[$job->context] = ($failedContexts[$job->context] ?? 0) + 1;
                if ($job->lastError !== null) {
                    if (count($lastErrors) < 5) {
                        $lastErrors[] = [
                            'context' => $job->context,
                            'error' => $job->lastError,
                            'at' => $job->lastErrorAt,
                        ];
                    }
                }
            }
        }
        return [
            'backlog' => $size,
            'oldest_age_seconds' => $oldest ? max(0, time() - $oldest) : 0,
            'sample_contexts' => $contexts,
            'failed' => $failed,
            'failed_contexts' => $failedContexts,
            'last_errors' => $lastErrors,
            'sampled' => count($jobs),
        ];
    }

    private static function escapeLabel(string $value): string
    {
        return str_replace(['\\', '"', "\n"], ['\\\\', '\"', ''], $value);
    }

    /**
     * @param array<string,string> $attrs
     * @return array<int,array<string,mixed>>
     */
    private static function attributes(array $attrs): array
    {
        $out = [];
        foreach ($attrs as $key => $value) {
            $out[] = [
                'key' => (string)$key,
                'value' => ['stringValue' => (string)$value],
            ];
        }
        return $out;
    }

    /**
     * @param array<string,string|int|float> $attrs
     * @return array<string,mixed>
     */
    private static function numberDataPoint(int|float $value, int $ts, array $attrs = []): array
    {
        $attrList = [];
        foreach ($attrs as $key => $attrValue) {
            $attrList[] = [
                'key' => (string)$key,
                'value' => is_int($attrValue)
                    ? ['intValue' => $attrValue]
                    : ['stringValue' => (string)$attrValue],
            ];
        }
        return [
            'timeUnixNano' => $ts,
            'asDouble' => (float)$value,
            'attributes' => $attrList,
        ];
    }

    /**
     * @param array<string,string> $attrs
     */
    private static function gaugeMetric(string $name, string $description, int|float $value, int $ts, array $attrs = []): array
    {
        return [
            'name' => $name,
            'description' => $description,
            'unit' => '1',
            'gauge' => [
                'dataPoints' => [
                    self::numberDataPoint($value, $ts, $attrs),
                ],
            ],
        ];
    }
}
