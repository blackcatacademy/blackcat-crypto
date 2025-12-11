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

    /** @var array<int,array<string,mixed>> */
    private array $recent = [];
    private static ?self $global = null;

    public function __construct(private int $recentLimit = 50) {}

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
        $entry = [
            'intent' => $intent,
            'payload' => $payload,
            'ts' => time(),
        ];
        $this->recent[] = $entry;
        if (count($this->recent) > $this->recentLimit) {
            array_shift($this->recent);
        }
    }

    /**
     * @return array<string,mixed>
     */
    public function snapshot(): array
    {
        return [
            'counts' => $this->counters,
            'recent' => $this->recent,
        ];
    }
}
