<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Queue;

final class WrapJob
{
    public readonly string $id;
    public readonly int $enqueuedAt;
    public int $attempts;

    public function __construct(
        public readonly string $context,
        public readonly string $payload,
        int $attempts = 0,
        ?int $enqueuedAt = null,
        ?string $id = null,
    ) {
        $this->attempts = $attempts;
        $this->enqueuedAt = $enqueuedAt ?? time();
        $this->id = $id ?? bin2hex(random_bytes(8));
    }

    public static function fromArray(array $data): self
    {
        return new self(
            context: (string)($data['context'] ?? ''),
            payload: (string)($data['payload'] ?? ''),
            attempts: (int)($data['attempts'] ?? 0),
            enqueuedAt: isset($data['enqueuedAt']) ? (int)$data['enqueuedAt'] : null,
            id: isset($data['id']) ? (string)$data['id'] : null,
        );
    }

    /** @return array{context:string,payload:string,attempts:int,enqueuedAt:int,id:string} */
    public function toArray(): array
    {
        return [
            'context' => $this->context,
            'payload' => $this->payload,
            'attempts' => $this->attempts,
            'enqueuedAt' => $this->enqueuedAt,
            'id' => $this->id,
        ];
    }

    public function requeue(): self
    {
        return new self(
            context: $this->context,
            payload: $this->payload,
            attempts: $this->attempts,
            enqueuedAt: time(),
            id: $this->id,
        );
    }
}
