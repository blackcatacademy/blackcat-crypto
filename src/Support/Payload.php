<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Support;

final class Payload
{
    public function __construct(
        public readonly string $ciphertext,
        public readonly string $nonce,
        public readonly string $keyId,
        public readonly array $meta = [],
    ) {}
}
