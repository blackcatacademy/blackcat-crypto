<?php
declare(strict_types=1);

namespace BlackCat\Crypto\Hmac;

use BlackCat\Crypto\Keyring\KeyRegistry;
use Psr\Log\LoggerInterface;

final class HmacService
{
    public function __construct(private readonly KeyRegistry $registry, private readonly ?LoggerInterface $logger = null) {}

    public function sign(string $slot, string $message): string
    {
        $key = $this->registry->deriveAeadKey($slot);
        return hash_hmac('sha3-512', $message, $key->bytes, true);
    }

    public function verify(string $slot, string $message, string $signature): bool
    {
        $key = $this->registry->deriveAeadKey($slot);
        $calc = hash_hmac('sha3-512', $message, $key->bytes, true);
        return hash_equals($calc, $signature);
    }
}
