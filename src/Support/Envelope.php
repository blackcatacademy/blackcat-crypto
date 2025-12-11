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
            'wrapCount' => ($kmsMetadata['wrapCount'] ?? 0),
        ];
        return new self($local, $kmsMetadata, $context, $meta);
    }

    public static function decode(string $serialized): self
    {
        $data = json_decode($serialized, true);
        if (
            !is_array($data)
            || !isset($data['local'], $data['kms'], $data['context'])
            || !is_array($data['local'])
        ) {
            throw new \RuntimeException('Invalid envelope');
        }
        $local = $data['local'];
        $cipherB64 = (string)($local['ciphertext'] ?? '');
        $nonceB64 = (string)($local['nonce'] ?? '');
        $ciphertext = base64_decode($cipherB64, true);
        $nonce = base64_decode($nonceB64, true);
        if ($ciphertext === false || $nonce === false) {
            throw new \RuntimeException('Invalid envelope payload encoding');
        }
        $payload = new Payload(
            ciphertext: $ciphertext,
            nonce: $nonce,
            keyId: (string)($local['keyId'] ?? ''),
            meta: $local['meta'] ?? []
        );
        return new self($payload, $data['kms'], $data['context'], $data['meta'] ?? []);
    }

    public function encode(): string
    {
        return json_encode([
            'context' => $this->context,
            'local' => [
                'ciphertext' => base64_encode($this->local->ciphertext),
                'nonce' => base64_encode($this->local->nonce),
                'keyId' => $this->local->keyId,
                'meta' => $this->local->meta,
            ],
            'kms' => $this->kmsMetadata,
            'meta' => $this->meta,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
