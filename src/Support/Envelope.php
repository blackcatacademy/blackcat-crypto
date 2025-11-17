<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Support;

final class Envelope
{
    public function __construct(
        public readonly Payload $local,
        public readonly array $kmsMetadata,
        public readonly string $context,
        public readonly array $meta = [],
    ) {}

    public static function fromLayers(Payload $local, array $kmsMetadata, string $context): self
    {
        $meta = [
            'createdAt' => time(),
            'wrapCount' => ($kmsMetadata['wrapCount'] ?? 1),
        ];
        return new self($local, $kmsMetadata, $context, $meta);
    }

    public static function decode(string $serialized): self
    {
        $data = json_decode($serialized, true);
        if (!is_array($data)) {
            throw new \RuntimeException('Invalid envelope');
        }
        $payload = new Payload(
            $data['local']['ciphertext'],
            $data['local']['nonce'],
            $data['local']['keyId'],
            $data['local']['meta'] ?? []
        );
        return new self($payload, $data['kms'], $data['context'], $data['meta'] ?? []);
    }

    public function encode(): string
    {
        return json_encode([
            'context' => $this->context,
            'local' => [
                'ciphertext' => $this->local->ciphertext,
                'nonce' => $this->local->nonce,
                'keyId' => $this->local->keyId,
                'meta' => $this->local->meta,
            ],
            'kms' => $this->kmsMetadata,
            'meta' => $this->meta,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
