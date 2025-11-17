<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Contracts;

use BlackCat\Crypto\Support\Payload;

interface KmsClientInterface
{
    public function id(): string;
    public function wrap(string $context, Payload $payload): array;
    public function unwrap(string $context, array $metadata): Payload;
    public function health(): array;
}
