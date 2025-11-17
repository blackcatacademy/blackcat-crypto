<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Keyring;

final class KeyMaterial
{
    public function __construct(
        public readonly string $id,
        public readonly string $bytes,
        public readonly string $slot,
        public readonly array $metadata = [],
    ) {}
}
