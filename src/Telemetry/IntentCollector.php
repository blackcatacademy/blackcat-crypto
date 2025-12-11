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
    ];

    /** @var array<int,array<string,mixed>> */
    private array $recent = [];
    private static ?self $global = null;

    public function __construct(
        private int $recentLimit = 50,
        private ?string $archivePath = null
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
            $line = json_encode($entry) . PHP_EOL;
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
}
