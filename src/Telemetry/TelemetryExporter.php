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
    public static function snapshot(array $kmsHealth, ?WrapQueueInterface $queue = null): array
    {
        $timestamp = time();
        $clients = [];
        $up = 0;
        foreach ($kmsHealth as $entry) {
            $clientId = (string)($entry['client'] ?? 'unknown');
            $statusData = $entry['status'] ?? [];
            $status = is_array($statusData)
                ? (string)($statusData['status'] ?? 'unknown')
                : (string)$statusData;
            if (strtolower($status) === 'ok') {
                $up++;
            }
            $clients[] = [
                'id' => $clientId,
                'status' => $status,
                'details' => $statusData,
            ];
        }
        $queueMetrics = self::queueMetrics($queue);
        return [
            'timestamp' => $timestamp,
            'kms_up_total' => $up,
            'kms_clients' => $clients,
            'wrap_queue' => $queueMetrics,
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
        $queue = $snapshot['wrap_queue'] ?? [];
        $lines[] = '# HELP blackcat_wrap_queue_backlog Number of pending wrap jobs.';
        $lines[] = '# TYPE blackcat_wrap_queue_backlog gauge';
        $lines[] = 'blackcat_wrap_queue_backlog ' . (int)($queue['backlog'] ?? 0);
        $lines[] = '# HELP blackcat_wrap_queue_oldest_age_seconds Age of the oldest pending wrap job.';
        $lines[] = '# TYPE blackcat_wrap_queue_oldest_age_seconds gauge';
        $lines[] = 'blackcat_wrap_queue_oldest_age_seconds ' . (int)($queue['oldest_age_seconds'] ?? 0);
        return implode("\n", $lines) . "\n";
    }

    /**
     * @return array<string,mixed>
     */
    private static function queueMetrics(?WrapQueueInterface $queue): array
    {
        if ($queue === null) {
            return [
                'backlog' => 0,
                'oldest_age_seconds' => 0,
                'sample_contexts' => [],
            ];
        }
        $size = $queue->size();
        $jobs = $queue->peek(min(50, max(1, $size)));
        $oldest = null;
        $contexts = [];
        /** @var WrapJob $job */
        foreach ($jobs as $job) {
            $contexts[$job->context] = ($contexts[$job->context] ?? 0) + 1;
            $oldest = $oldest === null ? $job->enqueuedAt : min($oldest, $job->enqueuedAt);
        }
        return [
            'backlog' => $size,
            'oldest_age_seconds' => $oldest ? max(0, time() - $oldest) : 0,
            'sample_contexts' => $contexts,
        ];
    }

    private static function escapeLabel(string $value): string
    {
        return str_replace(['\\', '"', "\n"], ['\\\\', '\"', ''], $value);
    }
}
