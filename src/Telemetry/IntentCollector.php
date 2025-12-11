<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Telemetry;

/**
 * Lightweight in-memory collector for crypto "intents" (encrypt/decrypt/hmac...).
 * Designed to be cheap and optional — if not wired, nothing happens.
 */
final class IntentCollector
{
    /** @var array<string,int> */
    private array $counters = [];

    /** @var array<string,array<string,int>> */
    private array $tagCounters = [
        'action' => [],
        'tenant' => [],
        'algorithm' => [],
        'route' => [],
        'context' => [],
        'pii_cluster' => [],
        'workload' => [],
        'decision' => [],
        'result' => [],
        'source' => [],
        'region' => [],
        'service' => [],
        'error_class' => [],
    ];

    /** @var array<int,array<string,mixed>> */
    private array $recent = [];
    private static ?self $global = null;

    public function __construct(
        private int $recentLimit = 50,
        private ?string $archivePath = null,
        private ?int $archiveMaxBytes = null,
        private int $archiveKeep = 3
    ) {}

    public static function global(?self $set = null): ?self
    {
        if ($set !== null) {
            self::$global = $set;
        }
        return self::$global;
    }

    /**
     * @param array<string,mixed> $payload
     */
    public function record(string $intent, array $payload): void
    {
        $this->counters[$intent] = ($this->counters[$intent] ?? 0) + 1;

        $this->bumpTag('action', $payload['action'] ?? null);
        $this->bumpTag('tenant', $payload['tenant'] ?? $payload['tenant_id'] ?? null);
        $this->bumpTag('algorithm', $payload['algorithm'] ?? null);
        $this->bumpTag('route', $payload['route'] ?? null);
        $this->bumpTag('context', $payload['context'] ?? null);
        $this->bumpTag('pii_cluster', $payload['pii_cluster'] ?? null);
        $this->bumpTag('workload', $payload['workload'] ?? null);
        $this->bumpTag('decision', $payload['decision'] ?? $payload['policy'] ?? null);
        $this->bumpTag('result', $payload['result'] ?? null);
        $this->bumpTag('source', $payload['source'] ?? null);
        $this->bumpTag('region', $payload['region'] ?? null);
        $this->bumpTag('service', $payload['service'] ?? $payload['component'] ?? null);
        $this->bumpTag('error_class', $payload['error'] ?? $payload['error_class'] ?? null);

        $entry = [
            'intent' => $intent,
            'payload' => $payload,
            'ts' => time(),
        ];
        $this->recent[] = $entry;
        if (count($this->recent) > $this->recentLimit) {
            array_shift($this->recent);
        }

        if ($this->archivePath) {
            if ($this->archiveMaxBytes !== null) {
                $this->rotateArchiveIfNeeded();
            }
            $meta = [
                'host' => gethostname() ?: 'unknown',
                'pid' => getmypid(),
            ];
            $line = json_encode(['meta' => $meta] + $entry) . PHP_EOL;
            @file_put_contents($this->archivePath, $line, FILE_APPEND | LOCK_EX);
        }
    }

    /**
     * @return array<string,mixed>
     */
    public function snapshot(): array
    {
        return [
            'counts' => $this->counters,
            'tag_counts' => $this->tagCounters,
            'recent' => $this->recent,
        ];
    }

    private function bumpTag(string $key, mixed $value): void
    {
        if ($value === null || $value === '') {
            return;
        }
        $bucket = &$this->tagCounters[$key];
        $value = (string) $value;
        $bucket[$value] = ($bucket[$value] ?? 0) + 1;
    }

    private function rotateArchiveIfNeeded(): void
    {
        if ($this->archivePath === null || $this->archiveMaxBytes === null) {
            return;
        }
        clearstatcache(false, $this->archivePath);
        $size = @filesize($this->archivePath);
        if ($size !== false && $size >= $this->archiveMaxBytes) {
            // Rotate archive.log -> archive.log.1 -> archive.log.2 ...
            for ($i = $this->archiveKeep; $i >= 1; $i--) {
                $src = $this->archivePath . ($i === 1 ? '' : '.' . ($i - 1));
                $dst = $this->archivePath . '.' . $i;
                if (file_exists($src)) {
                    @rename($src, $dst);
                }
            }
        }
    }
}
