<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Tests\Support;

use BlackCat\Crypto\Contracts\KmsClientInterface;
use BlackCat\Crypto\Support\Payload;

final class LoopbackKmsClient implements KmsClientInterface
{
    public function __construct(private readonly array $config = []) {}

    public function id(): string
    {
        return $this->config['id'] ?? 'loopback';
    }

    public function wrap(string $context, Payload $payload): array
    {
        return [
            'client' => $this->id(),
            'ciphertext' => base64_encode($payload->ciphertext),
            'nonce' => base64_encode($payload->nonce),
            'keyId' => $payload->keyId,
        ];
    }

    public function unwrap(string $context, array $metadata): Payload
    {
        return new Payload(
            base64_decode((string)$metadata['ciphertext'], true) ?: '',
            base64_decode((string)$metadata['nonce'], true) ?: '',
            (string)$metadata['keyId'],
        );
    }

    public function health(): array
    {
        return ['status' => 'ok'];
    }
}
